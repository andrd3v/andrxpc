//
//  injector.m
//  andrxpc
//
//  Created by andr on 08.11.2026.
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/thread_act.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <sys/ptrace.h>
#import <sys/wait.h>
#import <signal.h>
#import <libproc.h>
#import <limits.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <dlfcn.h>
#import "injector.h"

#if __arm64e__
#import <ptrauth.h>
#endif

#define STACK_SIZE 65536
#define SANDBOX_STAGING_DIR "/Library/Apple/usr/lib"
#define APP_SANDBOX_READ "com.apple.app-sandbox.read"
#define SANDBOX_FILTER_PATH 1
#define SANDBOX_CHECK_NO_REPORT 0x40000000
#define CS_OPS_ENTITLEMENTS_BLOB 7

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
extern char *sandbox_extension_issue_file(
    const char *ext_type,
    const char *path,
    uint64_t flags);
extern char *sandbox_extension_issue_file_to_process_by_pid(
    const char *ext_type,
    const char *path,
    uint64_t flags,
    pid_t pid);

static const uint32_t trampolineCode[] = {
    0xD63F0100, 0xB4000074, 0xAA1403E0, 0xD63F0260,
    0xB4000075, 0xAA1503E0, 0xD63F0260, 0xAA1703E0,
    0xAA1803E1, 0xD63F02C0, 0xF9000320, 0xB5000060,
    0xD63F0340, 0xF9000720, 0x14000000,
};

static bool hasCheckedAllocations(pid_t pid)
{
    size_t sz = 65536;
    void *buf = malloc(sz);
    if (!buf) return false;

    int r = csops(pid, CS_OPS_ENTITLEMENTS_BLOB, buf, sz);
    if (r != 0)
    {
        bzero(buf, sz);
        free(buf);
        return false;
    }

    bool found = (memmem(buf, sz, "checked-allocations", 19) != NULL);
    bzero(buf, sz);
    free(buf);
    return found;
}

static void *makeSymCallable(void *ptr)
{
#if __arm64e__
    ptr = ptrauth_sign_unauthenticated(
        ptrauth_strip(ptr, ptrauth_key_function_pointer),
        ptrauth_key_function_pointer, 0);
#endif
    return ptr;
}

static bool decodeAdrpLdr(
    uint32_t adrp,
    uint32_t ldr,
    uint64_t pc,
    uint64_t *out)
{
    if ((adrp & 0x9F000000) != 0x90000000) return false;
    int32_t imm = (int32_t)(((adrp & 0x60000000) >> 29) |
                             ((adrp & 0x00FFFFE0) >> 3)) << 12;

    if ((ldr & 0xBFC00000) != 0xB9400000) return false;
    uint16_t off = (ldr >> 10) & 0xFFF;
    if (ldr & 0x40000000) off *= 8; else off *= 4;

    if (out) *out = (pc & ~0xFFFULL) + imm + off;
    return true;
}

static task_array_t gTasks = NULL;
static mach_msg_type_number_t gNumTasks = 0;

int pst_init(void)
{
    kern_return_t kr;
    task_port_t psDefault, psCtrl;

    kr = processor_set_default(mach_host_self(), &psDefault);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "processor_set_default: %s\n", mach_error_string(kr));
        return -1;
    }

    kr = host_processor_set_priv(mach_host_self(), psDefault, &psCtrl);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "host_processor_set_priv: %s\n", mach_error_string(kr));
        return -1;
    }

    kr = processor_set_tasks(psCtrl, &gTasks, &gNumTasks);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "processor_set_tasks: %s\n", mach_error_string(kr));
        return -1;
    }

    return 0;
}

mach_port_t pst_find_task(pid_t target)
{
    for (mach_msg_type_number_t i = 0; i < gNumTasks; i++)
    {
        int pid = -1;
        if (pid_for_task(gTasks[i], &pid) == KERN_SUCCESS && pid == target)
            return gTasks[i];
    }
    return MACH_PORT_NULL;
}

void pst_cleanup(void)
{
    if (!gTasks) return;
    vm_deallocate(mach_task_self(), (vm_address_t)gTasks,
                  gNumTasks * sizeof(*gTasks));
    gTasks = NULL;
    gNumTasks = 0;
}

mach_port_t get_task(pid_t pid)
{
    if (!gTasks) pst_init();

    mach_port_t t = pst_find_task(pid);
    if (t != MACH_PORT_NULL) return t;

    mach_port_t task = MACH_PORT_NULL;
    task_for_pid(mach_task_self(), pid, &task);
    return task;
}

pid_t find_pid_by_name(const char *name)
{
    int pids[4096];
    int count = proc_listallpids(pids, sizeof(pids));

    for (int i = 0; i < count; i++)
    {
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pids[i], path, sizeof(path)) <= 0) continue;

        const char *bn = strrchr(path, '/');
        bn = bn ? bn + 1 : path;
        if (strcmp(bn, name) == 0) return pids[i];
    }
    return -1;
}

static kern_return_t taskRead(
    task_t task,
    vm_address_t addr,
    void *buf,
    vm_size_t size)
{
    vm_size_t out = size;
    return vm_read_overwrite(task, addr, size, (vm_address_t)buf, &out);
}

static vm_address_t writeStringToTask(
    task_t task,
    const char *str,
    size_t *lenOut)
{
    size_t len = strlen(str) + 1;
    vm_address_t remote = 0;

    if (vm_allocate(task, &remote, len, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
        return 0;
    vm_protect(task, remote, len, TRUE, VM_PROT_READ | VM_PROT_WRITE);
    if (vm_write(task, remote, (vm_address_t)str, (mach_msg_type_number_t)len) != KERN_SUCCESS)
        return 0;

    if (lenOut) *lenOut = len;
    return remote;
}

static vm_address_t getRemoteImageAddr(
    task_t task,
    vm_address_t infoAddr,
    const char *imagePath)
{
    struct dyld_all_image_infos infos;
    if (taskRead(task, infoAddr, &infos, sizeof(infos)) != KERN_SUCCESS)
        return 0;

    size_t arrSize = sizeof(struct dyld_image_info) * infos.infoArrayCount;
    struct dyld_image_info *arr = malloc(arrSize);
    if (taskRead(task, (vm_address_t)infos.infoArray, arr, arrSize) != KERN_SUCCESS)
    {
        free(arr);
        return 0;
    }

    vm_address_t result = 0;
    for (uint32_t i = 0; i < infos.infoArrayCount; i++)
    {
        char path[PATH_MAX];
        if (taskRead(task, (vm_address_t)arr[i].imageFilePath, path, sizeof(path)) != KERN_SUCCESS)
            continue;
        if (strcmp(path, imagePath) == 0)
        {
            result = (vm_address_t)arr[i].imageLoadAddress;
            break;
        }
    }

    free(arr);
    return result;
}

static vm_address_t remoteDlSym(
    task_t task,
    vm_address_t imageAddr,
    const char *sym)
{
    if (!imageAddr) return 0;

    struct mach_header_64 mh;
    if (taskRead(task, imageAddr, &mh, sizeof(mh)) != KERN_SUCCESS)
        return 0;

    vm_address_t cur = imageAddr + sizeof(struct mach_header_64);
    struct segment_command_64 linkedit = {0};
    struct symtab_command symtab = {0};
    vm_address_t slide = 0;
    int firstSeg = 1;

    for (uint32_t i = 0; i < mh.ncmds; i++)
    {
        struct load_command lc;
        taskRead(task, cur, &lc, sizeof(lc));

        if (lc.cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 seg;
            taskRead(task, cur, &seg, sizeof(seg));
            if (firstSeg) { slide = imageAddr - seg.vmaddr; firstSeg = 0; }
            if (strncmp(seg.segname, "__LINKEDIT", 16) == 0) linkedit = seg;
        } else if (lc.cmd == LC_SYMTAB) {
            taskRead(task, cur, &symtab, sizeof(symtab));
        }

        cur += lc.cmdsize;
    }

    if (!linkedit.cmd || !symtab.cmd) return 0;

    vm_address_t base = linkedit.vmaddr + slide - linkedit.fileoff;
    size_t nlSize = sizeof(struct nlist_64) * symtab.nsyms;
    struct nlist_64 *nls = malloc(nlSize);
    char *strtbl = malloc(symtab.strsize);
    if (!nls || !strtbl) { free(nls); free(strtbl); return 0; }

    taskRead(task, base + symtab.symoff, nls, nlSize);
    taskRead(task, base + symtab.stroff, strtbl, symtab.strsize);

    vm_address_t result = 0;
    for (uint32_t s = 0; s < symtab.nsyms; s++)
    {
        if (nls[s].n_un.n_strx >= symtab.strsize || nls[s].n_un.n_strx == 0)
            continue;
        if ((nls[s].n_type & N_TYPE) != N_SECT) continue;
        if (strcmp(&strtbl[nls[s].n_un.n_strx], sym) == 0)
        {
            result = nls[s].n_value + slide;
            break;
        }
    }

    free(nls);
    free(strtbl);
    return result;
}

static vm_address_t remoteDlSymFindImage(
    task_t task,
    vm_address_t infoAddr,
    const char *sym)
{
    struct dyld_all_image_infos infos;
    if (taskRead(task, infoAddr, &infos, sizeof(infos)) != KERN_SUCCESS)
        return 0;

    size_t arrSize = sizeof(struct dyld_image_info) * infos.infoArrayCount;
    struct dyld_image_info *arr = malloc(arrSize);
    if (taskRead(task, (vm_address_t)infos.infoArray, arr, arrSize) != KERN_SUCCESS)
    {
        free(arr);
        return 0;
    }

    vm_address_t result = 0;
    for (uint32_t i = 0; i < infos.infoArrayCount; i++)
    {
        result = remoteDlSym(task, (vm_address_t)arr[i].imageLoadAddress, sym);
        if (result) break;
    }

    free(arr);
    return result;
}

static kern_return_t waitForThread(
    thread_act_t thread,
    uint64_t targetPC,
    arm_thread_state64_t *outState)
{
    int errCount = 0;

    for (int i = 0; i < 30000; i++)
    {
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
        arm_thread_state64_t state;
        kern_return_t kr = thread_get_state(
            thread, ARM_THREAD_STATE64,
            (thread_state_t)&state, &cnt);

        if (kr != KERN_SUCCESS)
        {
            if (++errCount >= 10) return kr;
            usleep(200);
            continue;
        }

        errCount = 0;
        uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
        if (pc == targetPC)
        {
            if (outState) *outState = state;
            return KERN_SUCCESS;
        }

        usleep(200);
    }

    return KERN_FAILURE;
}

static const char *stageDylibForSandbox(pid_t pid, const char *path)
{
    if (strncmp(path, SANDBOX_STAGING_DIR, strlen(SANDBOX_STAGING_DIR)) == 0)
        return path;

    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;

    static char staged[PATH_MAX];
    snprintf(staged, sizeof(staged), "%s/%s", SANDBOX_STAGING_DIR, bn);

    FILE *src = fopen(path, "rb");
    if (!src) return NULL;

    FILE *dst = fopen(staged, "wb");
    if (!dst) { fclose(src); return NULL; }

    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) fwrite(buf, 1, n, dst);
    fclose(src);
    fclose(dst);

    char signCmd[PATH_MAX + 32];
    snprintf(signCmd, sizeof(signCmd), "codesign -f -s - '%s' 2>/dev/null", staged);
    system(signCmd);

    fprintf(stderr, "staged to %s\n", staged);
    return staged;
}

int inject_dylib(task_t task, pid_t pid, const char *dylibPath)
{
    kern_return_t kr;
    setvbuf(stderr, NULL, _IONBF, 0);

    const char *effectivePath = stageDylibForSandbox(pid, dylibPath);
    if (!effectivePath) { fprintf(stderr, "no staging path\n"); return -1; }
    if (effectivePath != dylibPath) dylibPath = effectivePath;

    task_dyld_info_data_t dyldInfo;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "task_dyld_info: %s\n", mach_error_string(kr));
        return -1;
    }

    vm_address_t infoAddr = dyldInfo.all_image_info_addr;
    fprintf(stderr, "all_image_info_addr: 0x%llx\n", (uint64_t)infoAddr);

    uint32_t opaqueFlags = 0;
#if __arm64e__
    {
        thread_act_array_t threads;
        mach_msg_type_number_t threadCount;
        kr = task_threads(task, &threads, &threadCount);
        if (kr != KERN_SUCCESS || threadCount == 0)
        {
            fprintf(stderr, "task_threads: %s\n", mach_error_string(kr));
            return -1;
        }

        struct arm_unified_thread_state vs;
        mach_msg_type_number_t vc = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state(threads[0], ARM_THREAD_STATE64,
                              (thread_state_t)&vs.ts_64, &vc);
        vm_deallocate(mach_task_self(), (vm_offset_t)threads,
                      sizeof(thread_act_t) * threadCount);
        if (kr != KERN_SUCCESS)
        {
            fprintf(stderr, "get flags: %s\n", mach_error_string(kr));
            return -1;
        }

        opaqueFlags = vs.ts_64.__opaque_flags;
        fprintf(stderr, "opaque_flags: 0x%x\n", opaqueFlags);
    }
#endif



    vm_address_t libPthread = getRemoteImageAddr(
        task, infoAddr, "/usr/lib/system/libsystem_pthread.dylib");
    if (!libPthread)
    {
        fprintf(stderr, "libsystem_pthread not found\n");
        return -1;
    }

    uint64_t pthreadSetSelf = remoteDlSym(task, libPthread, "__pthread_set_self");
    if (!pthreadSetSelf)
    {
        fprintf(stderr, "_pthread_set_self not found\n");
        return -1;
    }

    uint64_t mainThread = 0;
    uint64_t pthreadMainNp = remoteDlSym(task, libPthread, "_pthread_main_thread_np");
    if (pthreadMainNp)
    {
        uint32_t insns[2];
        if (taskRead(task, pthreadMainNp, insns, sizeof(insns)) == KERN_SUCCESS)
        {
            uint64_t ptr = 0;
            if (decodeAdrpLdr(insns[0], insns[1], pthreadMainNp, &ptr))
                taskRead(task, ptr, &mainThread, sizeof(mainThread));
        }
    }

    vm_address_t libDyld = getRemoteImageAddr(
        task, infoAddr, "/usr/lib/system/libdyld.dylib");
    uint64_t dlopenAddr = libDyld ? remoteDlSym(task, libDyld, "_dlopen") : 0;
    uint64_t dlerrorAddr = libDyld ? remoteDlSym(task, libDyld, "_dlerror") : 0;
    if (!dlopenAddr)
        dlopenAddr = remoteDlSymFindImage(task, infoAddr, "_dlopen");
    if (!dlerrorAddr)
        dlerrorAddr = remoteDlSymFindImage(task, infoAddr, "_dlerror");

    vm_address_t libSandbox = getRemoteImageAddr(
        task, infoAddr, "/usr/lib/system/libsystem_sandbox.dylib");
    uint64_t sbConsumeAddr = libSandbox ?
        remoteDlSym(task, libSandbox, "_sandbox_extension_consume") :
        remoteDlSymFindImage(task, infoAddr, "_sandbox_extension_consume");

    fprintf(stderr, "_pthread_set_self=0x%llx mainThread=0x%llx\n",
            pthreadSetSelf, mainThread);
    fprintf(stderr, "dlopen=0x%llx dlerror=0x%llx\n", dlopenAddr, dlerrorAddr);
    if (!dlopenAddr) { fprintf(stderr, "dlopen not found\n"); return -1; }

    vm_address_t remoteReadExt = 0;
    vm_address_t remoteExecExt = 0;
    size_t readExtLen = 0, execExtLen = 0;

    int needRead = sandbox_check(pid, "file-read-data",
        SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);
    int needExec = sandbox_check(pid, "file-map-executable",
        SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);
    fprintf(stderr, "sandbox read=%s exec=%s\n",
            needRead ? "blocked" : "ok", needExec ? "blocked" : "ok");

    if (sbConsumeAddr && (needRead || needExec))
    {
        char *readStr = sandbox_extension_issue_file_to_process_by_pid(
            APP_SANDBOX_READ, dylibPath, 0, pid);
        if (!readStr)
            readStr = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath, 0);
        if (readStr)
        {
            remoteReadExt = writeStringToTask(task, readStr, &readExtLen);
            fprintf(stderr, "read ext issued\n");
            free(readStr);
        }

        char *execStr = sandbox_extension_issue_file_to_process_by_pid(
            "com.apple.sandbox.executable", dylibPath, 0, pid);
        if (!execStr)
            execStr = sandbox_extension_issue_file(
                "com.apple.sandbox.executable", dylibPath, 0);
        if (execStr)
        {
            remoteExecExt = writeStringToTask(task, execStr, &execExtLen);
            fprintf(stderr, "exec ext issued\n");
            free(execStr);
        }
    }

    size_t remotePathLen = 0;
    vm_address_t remotePath = writeStringToTask(task, dylibPath, &remotePathLen);
    if (!remotePath) { fprintf(stderr, "write path failed\n"); return -1; }

    vm_address_t resultAddr = 0;
    kr = vm_allocate(task, &resultAddr, 16, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "alloc result: %s\n", mach_error_string(kr));
        return -1;
    }
    vm_protect(task, resultAddr, 16, TRUE, VM_PROT_READ | VM_PROT_WRITE);
    uint64_t zeros[2] = {0, 0};
    vm_write(task, resultAddr, (vm_address_t)zeros, 16);

    vm_address_t codePage = 0;
    kr = vm_allocate(task, &codePage, 4096, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "alloc code: %s\n", mach_error_string(kr));
        return -1;
    }
    kr = vm_write(task, codePage, (vm_address_t)trampolineCode,
                  sizeof(trampolineCode));
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "write code: %s\n", mach_error_string(kr));
        return -1;
    }
    kr = vm_protect(task, codePage, 4096, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "protect rx: %s\n", mach_error_string(kr));
        return -1;
    }
    fprintf(stderr, "trampoline at 0x%llx\n", (uint64_t)codePage);

    vm_address_t remoteStack = 0;
    kr = vm_allocate(task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "alloc stack: %s\n", mach_error_string(kr));
        return -1;
    }
    vm_protect(task, remoteStack, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

    struct arm_unified_thread_state ts;
    bzero(&ts, sizeof(ts));
    ts.ash.flavor = ARM_THREAD_STATE64;
    ts.ash.count = ARM_THREAD_STATE64_COUNT;

    vm_address_t spinAddr = codePage + (sizeof(trampolineCode) - 4);

    uint64_t sp = remoteStack + (STACK_SIZE / 2);
    __darwin_arm_thread_state64_set_sp(ts.ts_64, (void *)sp);
    __darwin_arm_thread_state64_set_pc_fptr(
        ts.ts_64, makeSymCallable((void *)codePage));
    __darwin_arm_thread_state64_set_lr_fptr(
        ts.ts_64, makeSymCallable((void *)spinAddr));

    ts.ts_64.__x[0]  = mainThread;
    ts.ts_64.__x[8]  = pthreadSetSelf;
    ts.ts_64.__x[19] = sbConsumeAddr;
    ts.ts_64.__x[20] = remoteReadExt;
    ts.ts_64.__x[21] = remoteExecExt;
    ts.ts_64.__x[22] = dlopenAddr;
    ts.ts_64.__x[23] = remotePath;
    ts.ts_64.__x[24] = RTLD_NOW;
    ts.ts_64.__x[25] = resultAddr;
    ts.ts_64.__x[26] = dlerrorAddr;

#if __arm64e__
    ts.ts_64.__opaque_flags = opaqueFlags;
#endif

    int didAttach = 0;
    thread_act_t thread;
    kr = thread_create_running(
        task, ARM_THREAD_STATE64,
        (thread_state_t)&ts.ts_64, ARM_THREAD_STATE64_COUNT, &thread);

    if (kr != KERN_SUCCESS && hasCheckedAllocations(pid))
    {
        fprintf(stderr, "retrying with ptrace for checked-allocations\n");
        if (ptrace(PT_ATTACH, pid, NULL, 0) == 0)
        {
            didAttach = 1;
            int status;
            waitpid(pid, &status, WUNTRACED);
            ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
            kr = thread_create_running(
                task, ARM_THREAD_STATE64,
                (thread_state_t)&ts.ts_64, ARM_THREAD_STATE64_COUNT, &thread);
            if (kr != KERN_SUCCESS)
            {
                ptrace(PT_DETACH, pid, (caddr_t)1, 0);
                didAttach = 0;
            }
        }
    }

    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr, "thread_create_running: %s\n", mach_error_string(kr));
        return -1;
    }
    fprintf(stderr, "trampoline thread running\n");

    arm_thread_state64_t outState;
    kr = waitForThread(thread, spinAddr, &outState);
    if (kr != KERN_SUCCESS)
    {
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
        arm_thread_state64_t st;
        kern_return_t kr2 = thread_get_state(
            thread, ARM_THREAD_STATE64,
            (thread_state_t)&st, &cnt);
        if (kr2 == KERN_SUCCESS)
        {
            fprintf(stderr, "thread stuck at pc=0x%llx\n",
                    (uint64_t)__darwin_arm_thread_state64_get_pc(st));
        } else {
            fprintf(stderr, "thread dead: %s\n", mach_error_string(kr2));
        }
        thread_terminate(thread);
        if (didAttach) ptrace(PT_DETACH, pid, (caddr_t)1, 0);
        return -1;
    }

    uint64_t handle = 0;
    taskRead(task, resultAddr, &handle, sizeof(handle));

    if (handle)
    {
        fprintf(stderr, "dlopen ok handle=0x%llx\n", handle);
    } else {
        fprintf(stderr, "dlopen failed\n");
        uint64_t errStr = 0;
        taskRead(task, resultAddr + 8, &errStr, sizeof(errStr));
        if (errStr)
        {
            char buf[512];
            bzero(buf, sizeof(buf));
            taskRead(task, errStr, buf, sizeof(buf) - 1);
            fprintf(stderr, "dlerror: %s\n", buf);
        }
    }

    thread_terminate(thread);

    if (didAttach)
    {
        ptrace(PT_DETACH, pid, (caddr_t)1, 0);
        fprintf(stderr, "ptrace detached\n");
    }

    vm_deallocate(task, codePage, 4096);
    vm_deallocate(task, remoteStack, STACK_SIZE);
    vm_deallocate(task, resultAddr, 16);
    vm_deallocate(task, remotePath, remotePathLen);
    if (remoteReadExt) vm_deallocate(task, remoteReadExt, readExtLen);
    if (remoteExecExt) vm_deallocate(task, remoteExecExt, execExtLen);

    return handle ? 0 : -1;
}
