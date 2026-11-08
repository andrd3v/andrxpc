//
//  xpchook.m
//  andrxpc
//
//  Created by andr on 08.11.2026.
//

#import <CoreFoundation/CoreFoundation.h>
#import <xpc/xpc.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <servers/bootstrap.h>
#import <unistd.h>
#import <libproc.h>
#import <pthread.h>
#import <sys/stat.h>
#import <sys/time.h>
#import <stdarg.h>
#import <dlfcn.h>
#import <os/log.h>

#define MAX_DESC 4096

#define INTERPOSE(_hook, _orig) \
    __attribute__((used)) static struct { const void *r; const void *o; } \
    _interpose_##_orig __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)&_hook, (const void *)&_orig };

static FILE *gLog = NULL;
static int gUseSyslog = 0;
static os_log_t gOsLog = NULL;
static pthread_mutex_t gMtx = PTHREAD_MUTEX_INITIALIZER;

static void openLog(void)
{
    if (gLog || gUseSyslog) return;

    char name[256];
    bzero(name, sizeof(name));
    proc_name(getpid(), name, sizeof(name));

    const char *dirs[] = {"/tmp/andrxpc", "/Library/Apple/usr/lib/andrxpc_logs", NULL};
    for (int i = 0; dirs[i]; i++)
    {
        mkdir(dirs[i], 0777);
        char path[512];
        snprintf(path, sizeof(path), "%s/%d_%s.xpc.log", dirs[i], getpid(), name);
        FILE *f = fopen(path, "a");
        if (f)
        {
            gLog = f;
            setvbuf(f, NULL, _IONBF, 0);
            return;
        }
    }

    gUseSyslog = 1;
    gOsLog = os_log_create("com.andrxpc.hook", "xpc");
}

__attribute__((format(printf, 2, 3)))
static void xlog(const char *tag, const char *fmt, ...)
{
    if (!gLog && !gUseSyslog) openLog();

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);

    char line[8192];
    int off = snprintf(line, sizeof(line), "%02d:%02d:%02d.%03d %5s ",
                       tm.tm_hour, tm.tm_min, tm.tm_sec,
                       (int)(tv.tv_usec / 1000), tag);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + off, sizeof(line) - off, fmt, ap);
    va_end(ap);

    if (gLog)
    {
        pthread_mutex_lock(&gMtx);
        fputs(line, gLog);
        fputc('\n', gLog);
        fflush(gLog);
        pthread_mutex_unlock(&gMtx);
    }

    if (gUseSyslog && gOsLog)
    {
        os_log(gOsLog, "%{public}s", line);
    }
}

static char *xdesc(xpc_object_t obj)
{
    if (!obj) return strdup("(null)");
    char *d = xpc_copy_description(obj);
    if (d && strlen(d) > MAX_DESC)
    {
        d[MAX_DESC - 3] = '.';
        d[MAX_DESC - 2] = '.';
        d[MAX_DESC - 1] = '\0';
    }
    return d;
}

static const char *connInfo(xpc_connection_t c)
{
    static __thread char buf[128];
    if (!c) return "(null)";
    snprintf(buf, sizeof(buf), "%p/pid=%d", c, xpc_connection_get_pid(c));
    return buf;
}

static const char *errName(xpc_object_t e)
{
    if (e == XPC_ERROR_CONNECTION_INVALID) return "CONNECTION_INVALID";
    if (e == XPC_ERROR_CONNECTION_INTERRUPTED) return "CONNECTION_INTERRUPTED";
    if (e == XPC_ERROR_TERMINATION_IMMINENT) return "TERMINATION_IMMINENT";
    return "UNKNOWN_ERROR";
}

static xpc_connection_t hookCreateMachService(
    const char *name,
    dispatch_queue_t queue,
    uint64_t flags)
{
    xpc_connection_t c = xpc_connection_create_mach_service(name, queue, flags);
    xlog("CONN", "create_mach_service(\"%s\", flags=0x%llx) -> %p",
         name ?: "(null)", flags, c);
    return c;
}
INTERPOSE(hookCreateMachService, xpc_connection_create_mach_service)

static xpc_connection_t hookCreate(
    const char *name,
    dispatch_queue_t queue)
{
    xpc_connection_t c = xpc_connection_create(name, queue);
    xlog("CONN", "create(\"%s\") -> %p", name ?: "(null)", c);
    return c;
}
INTERPOSE(hookCreate, xpc_connection_create)

static void hookSendMessage(
    xpc_connection_t c,
    xpc_object_t msg)
{
    char *d = xdesc(msg);
    xlog("SEND", "[%s] %s", connInfo(c), d);
    free(d);
    xpc_connection_send_message(c, msg);
}
INTERPOSE(hookSendMessage, xpc_connection_send_message)

static void hookSendMessageWithReply(
    xpc_connection_t c,
    xpc_object_t msg,
    dispatch_queue_t replyq,
    xpc_handler_t handler)
{
    char *d = xdesc(msg);
    xlog("SEND", "[%s] (async) %s", connInfo(c), d);
    free(d);

    xpc_handler_t wrapper = ^(xpc_object_t reply) {
        char *rd = xdesc(reply);
        xlog("REPLY", "[%s] (async) %s", connInfo(c), rd);
        free(rd);
        handler(reply);
    };
    xpc_connection_send_message_with_reply(c, msg, replyq, wrapper);
}
INTERPOSE(hookSendMessageWithReply, xpc_connection_send_message_with_reply)

static xpc_object_t hookSendMessageWithReplySync(
    xpc_connection_t c,
    xpc_object_t msg)
{
    char *d = xdesc(msg);
    xlog("SEND", "[%s] (sync) %s", connInfo(c), d);
    free(d);

    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(c, msg);

    char *rd = xdesc(reply);
    xlog("REPLY", "[%s] (sync) %s", connInfo(c), rd);
    free(rd);
    return reply;
}
INTERPOSE(hookSendMessageWithReplySync, xpc_connection_send_message_with_reply_sync)

static void hookSetEventHandler(
    xpc_connection_t c,
    xpc_handler_t handler)
{
    xpc_handler_t wrapper = ^(xpc_object_t event) {
        xpc_type_t t = xpc_get_type(event);
        if (t == XPC_TYPE_DICTIONARY)
        {
            char *d = xdesc(event);
            xlog("RECV", "[%s] %s", connInfo(c), d);
            free(d);
        } else if (t == XPC_TYPE_ERROR) {
            xlog("EVENT", "[%s] %s", connInfo(c), errName(event));
        }
        handler(event);
    };
    xpc_connection_set_event_handler(c, wrapper);
}
INTERPOSE(hookSetEventHandler, xpc_connection_set_event_handler)

static void hookResume(xpc_connection_t c)
{
    xlog("CONN", "resume(%s)", connInfo(c));
    xpc_connection_resume(c);
}
INTERPOSE(hookResume, xpc_connection_resume)

static void hookCancel(xpc_connection_t c)
{
    xlog("CONN", "cancel(%s)", connInfo(c));
    xpc_connection_cancel(c);
}
INTERPOSE(hookCancel, xpc_connection_cancel)

static kern_return_t hookBootstrapLookUp(
    mach_port_t bp,
    const char *name,
    mach_port_t *sp)
{
    kern_return_t kr = bootstrap_look_up(bp, name, sp);
    xlog("BOOT", "look_up(\"%s\") -> port=0x%x kr=%d",
         name ?: "(null)", sp ? *sp : 0, kr);
    return kr;
}
INTERPOSE(hookBootstrapLookUp, bootstrap_look_up)

static kern_return_t hookBootstrapCheckIn(
    mach_port_t bp,
    const char *name,
    mach_port_t *sp)
{
    kern_return_t kr = bootstrap_check_in(bp, name, sp);
    xlog("BOOT", "check_in(\"%s\") -> port=0x%x kr=%d",
         name ?: "(null)", sp ? *sp : 0, kr);
    return kr;
}
INTERPOSE(hookBootstrapCheckIn, bootstrap_check_in)

static CFMessagePortRef hookCFMessagePortCreateRemote(
    CFAllocatorRef alloc,
    CFStringRef name)
{
    CFMessagePortRef port = CFMessagePortCreateRemote(alloc, name);
    char buf[256];
    bzero(buf, sizeof(buf));
    if (name) CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8);
    xlog("CFMP", "CreateRemote(\"%s\") -> %p", buf, port);
    return port;
}
INTERPOSE(hookCFMessagePortCreateRemote, CFMessagePortCreateRemote)

static CFMessagePortRef hookCFMessagePortCreateLocal(
    CFAllocatorRef alloc,
    CFStringRef name,
    CFMessagePortCallBack callout,
    CFMessagePortContext *ctx,
    Boolean *shouldFreeInfo)
{
    CFMessagePortRef port = CFMessagePortCreateLocal(
        alloc, name, callout, ctx, shouldFreeInfo);
    char buf[256];
    bzero(buf, sizeof(buf));
    if (name) CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8);
    xlog("CFMP", "CreateLocal(\"%s\") -> %p", buf, port);
    return port;
}
INTERPOSE(hookCFMessagePortCreateLocal, CFMessagePortCreateLocal)

static SInt32 hookCFMessagePortSendRequest(
    CFMessagePortRef remote,
    SInt32 msgid,
    CFDataRef data,
    CFTimeInterval sendTimeout,
    CFTimeInterval rcvTimeout,
    CFStringRef replyMode,
    CFDataRef *returnData)
{
    SInt32 r = CFMessagePortSendRequest(
        remote, msgid, data, sendTimeout, rcvTimeout, replyMode, returnData);
    xlog("CFMP", "SendRequest(port=%p, msgid=%d, len=%ld) -> %d",
         remote, msgid, data ? CFDataGetLength(data) : 0, r);
    return r;
}
INTERPOSE(hookCFMessagePortSendRequest, CFMessagePortSendRequest)

static IMP origInitWithServiceName;
static IMP origInitWithMachServiceName;
static IMP origInitWithListenerEndpoint;
static IMP origListenerInit;
static IMP origNSXPCResume;
static IMP origNSXPCInvalidate;
static IMP origRemoteObjectProxy;
static IMP origRemoteObjectProxyErr;
static IMP origPostDistNotification;

static const char *nsstrUtf8(id str)
{
    if (!str) return "(null)";
    return ((const char *(*)(id, SEL))objc_msgSend)(
        str, sel_registerName("UTF8String"));
}

static const char *connServiceDesc(id conn)
{
    id sn = ((id (*)(id, SEL))objc_msgSend)(
        conn, sel_registerName("serviceName"));
    if (sn) return nsstrUtf8(sn);
    id ep = ((id (*)(id, SEL))objc_msgSend)(
        conn, sel_registerName("endpoint"));
    return ep ? "(endpoint)" : "(null)";
}

static id swzInitWithServiceName(id self, SEL _cmd, id name)
{
    xlog("NSXPC", "initWithServiceName:\"%s\"", nsstrUtf8(name));
    return ((id (*)(id, SEL, id))origInitWithServiceName)(self, _cmd, name);
}

static id swzInitWithMachServiceName(
    id self,
    SEL _cmd,
    id name,
    unsigned long opts)
{
    xlog("NSXPC", "initWithMachServiceName:\"%s\" options:%lu",
         nsstrUtf8(name), opts);
    return ((id (*)(id, SEL, id, unsigned long))
            origInitWithMachServiceName)(self, _cmd, name, opts);
}

static id swzInitWithListenerEndpoint(
    id self,
    SEL _cmd,
    id ep)
{
    xlog("NSXPC", "initWithListenerEndpoint:%p", ep);
    return ((id (*)(id, SEL, id))
            origInitWithListenerEndpoint)(self, _cmd, ep);
}

static id swzListenerInit(id self, SEL _cmd, id name)
{
    xlog("NSXPC", "NSXPCListener initWithMachServiceName:\"%s\"",
         nsstrUtf8(name));
    return ((id (*)(id, SEL, id))origListenerInit)(self, _cmd, name);
}

static void swzNSXPCResume(id self, SEL _cmd)
{
    xlog("NSXPC", "resume conn=%p service:\"%s\"", self, connServiceDesc(self));
    ((void (*)(id, SEL))origNSXPCResume)(self, _cmd);
}

static void swzNSXPCInvalidate(id self, SEL _cmd)
{
    xlog("NSXPC", "invalidate conn=%p service:\"%s\"", self, connServiceDesc(self));
    ((void (*)(id, SEL))origNSXPCInvalidate)(self, _cmd);
}

static id swzRemoteObjectProxy(id self, SEL _cmd)
{
    xlog("NSXPC", "remoteObjectProxy conn=%p service:\"%s\"",
         self, connServiceDesc(self));
    return ((id (*)(id, SEL))origRemoteObjectProxy)(self, _cmd);
}

static id swzRemoteObjectProxyWithErr(
    id self,
    SEL _cmd,
    id handler)
{
    xlog("NSXPC", "remoteObjectProxyWithErrorHandler: conn=%p service:\"%s\"",
         self, connServiceDesc(self));
    return ((id (*)(id, SEL, id))
            origRemoteObjectProxyErr)(self, _cmd, handler);
}

static void swzPostDistNotification(
    id self,
    SEL _cmd,
    id name,
    id object,
    id userInfo,
    BOOL immediate)
{
    xlog("DNOTE", "post:\"%s\" object:\"%s\" immediate:%d",
         nsstrUtf8(name),
         object ? nsstrUtf8(object) : "(null)",
         immediate);
    ((void (*)(id, SEL, id, id, id, BOOL))
     origPostDistNotification)(self, _cmd, name, object, userInfo, immediate);
}

static void swizzle(Class cls, SEL sel, IMP imp, IMP *orig)
{
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m) *orig = method_setImplementation(m, imp);
}

static int gInited = 0;

__attribute__((constructor))
static void andrxpcInit(void)
{
    if (gInited) return;
    gInited = 1;

    openLog();

    char name[256];
    bzero(name, sizeof(name));
    proc_name(getpid(), name, sizeof(name));
    xlog("INIT", "andrxpc loaded into pid %d (%s)", getpid(), name);

    const char *inserted = getenv("DYLD_INSERT_LIBRARIES");
    if (inserted && strstr(inserted, "xpchook"))
        xlog("INIT", "DYLD_INTERPOSE active (launch-time, all IPC hooks)");
    else
        xlog("INIT", "dlopen mode (NSXPC swizzle only, use -r for full hooks)");

    void *foundationHandle = dlopen(
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        RTLD_NOLOAD | RTLD_LAZY);
    if (foundationHandle)
    {
        Class xpcConn = objc_getClass("NSXPCConnection");
        Class xpcListener = objc_getClass("NSXPCListener");
        Class distCenter = objc_getClass("NSDistributedNotificationCenter");

        swizzle(xpcConn,
                sel_registerName("initWithServiceName:"),
                (IMP)swzInitWithServiceName,
                &origInitWithServiceName);

        swizzle(xpcConn,
                sel_registerName("initWithMachServiceName:options:"),
                (IMP)swzInitWithMachServiceName,
                &origInitWithMachServiceName);

        swizzle(xpcConn,
                sel_registerName("initWithListenerEndpoint:"),
                (IMP)swzInitWithListenerEndpoint,
                &origInitWithListenerEndpoint);

        swizzle(xpcConn,
                sel_registerName("resume"),
                (IMP)swzNSXPCResume,
                &origNSXPCResume);

        swizzle(xpcConn,
                sel_registerName("invalidate"),
                (IMP)swzNSXPCInvalidate,
                &origNSXPCInvalidate);

        swizzle(xpcConn,
                sel_registerName("remoteObjectProxy"),
                (IMP)swzRemoteObjectProxy,
                &origRemoteObjectProxy);

        swizzle(xpcConn,
                sel_registerName("remoteObjectProxyWithErrorHandler:"),
                (IMP)swzRemoteObjectProxyWithErr,
                &origRemoteObjectProxyErr);

        swizzle(xpcListener,
                sel_registerName("initWithMachServiceName:"),
                (IMP)swzListenerInit,
                &origListenerInit);

        swizzle(distCenter,
                sel_registerName("postNotificationName:object:userInfo:deliverImmediately:"),
                (IMP)swzPostDistNotification,
                &origPostDistNotification);

        xlog("INIT", "NSXPC + distributed notifications swizzle active");
    } else {
        xlog("INIT", "no Foundation, NSXPC swizzle skipped");
    }
}
