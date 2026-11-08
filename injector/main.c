//
//  main.c
//  andrxpc
//
//  Created by andr on 08.11.2026.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <spawn.h>
#include <libproc.h>
#include <stdarg.h>
#include <sys/stat.h>
#include "injector.h"

extern char **environ;

static void usage(const char *prog)
{
    fprintf(stderr, "andrxpc injector\n\n");
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  %s -p <pid> <dylib>          inject via dlopen\n", prog);
    fprintf(stderr, "  %s -n <name> <dylib>         inject via dlopen\n", prog);
    fprintf(stderr, "  %s -r <name> <dylib>         kill & restart with DYLD_INSERT\n", prog);
    fprintf(stderr, "  %s -d <label> <dylib>        restart daemon via launchctl\n", prog);
    fprintf(stderr, "  %s -a <dylib>                inject all\n", prog);
    fprintf(stderr, "  %s -l                        list tasks\n", prog);
}

static void listTasks(void)
{
    if (pst_init() != 0)
    {
        fprintf(stderr, "pst init failed, need root\n");
        return;
    }

    int pids[16384];
    int npids = proc_listallpids(pids, sizeof(pids));

    printf("%-8s %-30s %-10s\n", "PID", "NAME", "PST");
    printf("─────────────────────────────────────────────────\n");

    for (int p = 0; p < npids; p++)
    {
        char name[256];
        bzero(name, sizeof(name));
        proc_name(pids[p], name, sizeof(name));
        mach_port_t task = pst_find_task(pids[p]);
        printf("%-8d %-30s %-10s\n", pids[p], name[0] ? name : "?",
               task != MACH_PORT_NULL ? "OK" : "-");
    }

    pst_cleanup();
}

static int getExePath(pid_t pid, char *buf, size_t bufLen)
{
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    bzero(pathbuf, sizeof(pathbuf));
    int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if (ret <= 0) return -1;
    strlcpy(buf, pathbuf, bufLen);
    return 0;
}

static int restartWithInsert(const char *procName, const char *dylibPath)
{
    pid_t pid = find_pid_by_name(procName);
    if (pid < 0)
    {
        fprintf(stderr, "process '%s' not found\n", procName);
        return 1;
    }

    char exePath[1024];
    bzero(exePath, sizeof(exePath));
    if (getExePath(pid, exePath, sizeof(exePath)) != 0)
    {
        fprintf(stderr, "cant get exe path for pid %d\n", pid);
        return 1;
    }

    printf("%s pid=%d exe=%s\n", procName, pid, exePath);
    printf("killing %d...\n", pid);
    kill(pid, SIGKILL);
    usleep(500000);

    setenv("DYLD_INSERT_LIBRARIES", dylibPath, 1);

    pid_t child;
    char *spawnArgv[] = {exePath, NULL};

    int err = posix_spawn(&child, exePath, NULL, NULL, spawnArgv, environ);
    if (err != 0)
    {
        fprintf(stderr, "posix_spawn: %d (%s)\n", err, strerror(err));
        child = fork();
        if (child == 0)
        {
            execv(exePath, spawnArgv);
            _exit(127);
        }
        if (child < 0)
        {
            fprintf(stderr, "fork failed\n");
            return 1;
        }
    }

    printf("started pid %d, all hooks on\n", child);
    return 0;
}

static int shellCmd(const char *fmt, ...)
{
    char cmd[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    printf("$ %s\n", cmd);
    return system(cmd);
}

static void ensureLogDirs(void)
{
    mkdir("/tmp/andrxpc", 0777);
    chmod("/tmp/andrxpc", 01777);
    mkdir("/Library/Apple/usr/lib/andrxpc_logs", 0777);
    chmod("/Library/Apple/usr/lib/andrxpc_logs", 01777);
}

static const char *stageDylib(const char *path)
{
    static char staged[1024];
    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;
    snprintf(staged, sizeof(staged), "/Library/Apple/usr/lib/%s", bn);

    FILE *src = fopen(path, "rb");
    if (!src) return path;
    FILE *dst = fopen(staged, "wb");
    if (!dst) { fclose(src); return path; }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) fwrite(buf, 1, n, dst);
    fclose(src);
    fclose(dst);

    char cmd[1024 + 32];
    snprintf(cmd, sizeof(cmd), "codesign -f -s - '%s' 2>/dev/null", staged);
    system(cmd);

    printf("staged to %s\n", staged);
    return staged;
}

static int restartDaemon(const char *label, const char *dylibPath)
{
    char target[512];
    char check[1024];

    snprintf(target, sizeof(target), "system/%s", label);
    snprintf(check, sizeof(check), "launchctl print %s >/dev/null 2>&1", target);
    if (system(check) != 0)
    {
        uid_t uid = getuid();
        if (uid == 0)
        {
            const char *su = getenv("SUDO_UID");
            if (su) uid = (uid_t)atoi(su);
        }
        snprintf(target, sizeof(target), "gui/%d/%s", uid, label);
        snprintf(check, sizeof(check), "launchctl print %s >/dev/null 2>&1", target);
        if (system(check) != 0)
        {
            snprintf(target, sizeof(target), "user/%d/%s", uid, label);
            snprintf(check, sizeof(check), "launchctl print %s >/dev/null 2>&1", target);
            if (system(check) != 0)
            {
                fprintf(stderr, "service '%s' not found\n", label);
                return 1;
            }
        }
    }

    printf("service: %s\n", target);

    const char *stagedPath = stageDylib(dylibPath);
    ensureLogDirs();

    int ret = shellCmd("launchctl debug %s --environment DYLD_INSERT_LIBRARIES=%s",
                       target, stagedPath);
    if (ret != 0)
    {
        fprintf(stderr, "launchctl debug failed (%d)\n", ret);
        return 1;
    }

    printf("restarting...\n");
    shellCmd("launchctl kill SIGTERM %s", target);
    usleep(1000000);
    ret = shellCmd("launchctl kickstart %s", target);
    if (ret != 0)
    {
        fprintf(stderr, "kickstart failed, trying kill+start\n");
        shellCmd("launchctl kill SIGKILL %s", target);
        usleep(500000);
        ret = shellCmd("launchctl kickstart %s", target);
    }

    if (ret != 0)
    {
        fprintf(stderr, "restart failed\n");
        return 1;
    }

    printf("all hooks on (one-shot, next restart clean)\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    if (getuid() != 0)
    {
        fprintf(stderr, "need root\n");
        return 1;
    }

    if (strcmp(argv[1], "-l") == 0)
    {
        listTasks();
        return 0;
    }

    if (argc < 3)
    {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-r") == 0 && argc >= 4)
    {
        char rp[1024];
        if (!realpath(argv[3], rp))
        {
            fprintf(stderr, "dylib not found: %s\n", argv[3]);
            return 1;
        }
        return restartWithInsert(argv[2], rp);
    }

    if (strcmp(argv[1], "-d") == 0 && argc >= 4)
    {
        char rp[1024];
        if (!realpath(argv[3], rp))
        {
            fprintf(stderr, "dylib not found: %s\n", argv[3]);
            return 1;
        }
        return restartDaemon(argv[2], rp);
    }

    const char *dylibPath = NULL;
    pid_t targetPid = -1;
    int injectAll = 0;

    if (strcmp(argv[1], "-p") == 0 && argc >= 4)
    {
        targetPid = atoi(argv[2]);
        dylibPath = argv[3];
    } else if (strcmp(argv[1], "-n") == 0 && argc >= 4) {
        const char *name = argv[2];
        dylibPath = argv[3];
        targetPid = find_pid_by_name(name);
        if (targetPid < 0)
        {
            fprintf(stderr, "process '%s' not found\n", name);
            return 1;
        }
        printf("%s -> pid %d\n", name, targetPid);
    } else if (strcmp(argv[1], "-a") == 0) {
        dylibPath = argv[2];
        injectAll = 1;
    } else {
        usage(argv[0]);
        return 1;
    }

    char realPath[1024];
    if (!realpath(dylibPath, realPath))
    {
        fprintf(stderr, "dylib not found: %s\n", dylibPath);
        return 1;
    }
    dylibPath = realPath;
    printf("dylib: %s\n", dylibPath);

    if (pst_init() != 0)
    {
        fprintf(stderr, "pst init failed\n");
        return 1;
    }

    if (injectAll)
    {
        int ok = 0, fail = 0, skip = 0;
        int allpids[16384];
        int npids = proc_listallpids(allpids, sizeof(allpids));

        for (int i = 0; i < npids; i++)
        {
            pid_t p = allpids[i];
            if (p == 0 || p == getpid()) { skip++; continue; }

            mach_port_t task = pst_find_task(p);
            if (task == MACH_PORT_NULL) { skip++; continue; }

            char name[256];
            bzero(name, sizeof(name));
            proc_name(p, name, sizeof(name));

            int kr = inject_dylib(task, p, dylibPath);
            if (kr == 0)
            {
                printf("pid %d (%s) ok\n", p, name);
                ok++;
            } else {
                printf("pid %d (%s) fail\n", p, name);
                fail++;
            }
        }

        printf("\ndone: %d ok, %d fail, %d skip\n", ok, fail, skip);
    } else {
        mach_port_t task = get_task(targetPid);
        if (task == MACH_PORT_NULL)
        {
            fprintf(stderr, "cant get task for pid %d\n", targetPid);
            pst_cleanup();
            return 1;
        }

        char name[256];
        bzero(name, sizeof(name));
        proc_name(targetPid, name, sizeof(name));
        printf("target: pid %d (%s) task=0x%x\n", targetPid, name, task);

        int kr = inject_dylib(task, targetPid, dylibPath);
        if (kr != 0)
        {
            fprintf(stderr, "injection failed\n");
            pst_cleanup();
            return 1;
        }
        printf("ok\n");
    }

    pst_cleanup();
    return 0;
}
