//
//  main.c
//  andrxpc tui
//
//  Created by andr on 08.11.2026.
//

#include <ncurses.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <libproc.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <mach-o/dyld.h>

#define LOG_DIR "/tmp/axpc"
#define LOG_DIR2 "/Library/Apple/usr/lib/axpc_logs"
#define MAX_PROCS 1024
#define MAX_LOGS 32768
#define MAX_WATCH 128
#define MAX_LINE 2048

enum
{
    C_TITLE = 1,
    C_SEL,
    C_LIVE,
    C_IDLE,
    C_INIT,
    C_CONN,
    C_SEND,
    C_RECV,
    C_REPLY,
    C_BOOT,
    C_NSXPC,
    C_CFMP,
    C_DNOTE,
    C_EVENT,
    C_FILTER,
    C_STATUS,
    C_DIM,
    C_PROC_HDR,
};

typedef struct
{
    pid_t pid;
    char name[256];
    int monitored;
    int msgCount;
} Proc;

typedef struct
{
    char path[512];
    int fd;
    pid_t pid;
    char procName[64];
    char buf[4096];
    int bufLen;
} Watched;

typedef struct
{
    char time[16];
    char tag[8];
    pid_t pid;
    char proc[64];
    char text[MAX_LINE];
    int clr;
} LogEntry;

typedef struct
{
    Proc procs[MAX_PROCS];
    int nProcs;
    int procSel;
    int procScroll;

    LogEntry *logs;
    int nLogs;
    int logScroll;
    int autoScroll;

    Watched watch[MAX_WATCH];
    int nWatch;

    char filter[256];
    int filterLen;
    int focus;

    int procH;
    int running;

    char selfDir[1024];

    struct timeval lastScan;
    time_t startTime;
    int totalMsgs;
    int tick;

    FILE *oslogPipe;
    pid_t oslogPid;
} App;

static volatile int gResize = 0;

static void onWinch(int s)
{
    (void)s;
    gResize = 1;
}

static void getSelfDir(char *buf, size_t len)
{
    uint32_t sz = (uint32_t)len;
    bzero(buf, len);
    _NSGetExecutablePath(buf, &sz);
    char *sl = strrchr(buf, '/');
    if (sl) *sl = '\0';
}

static void initColors(void)
{
    start_color();
    use_default_colors();
    init_pair(C_TITLE,    COLOR_BLACK,   COLOR_WHITE);
    init_pair(C_SEL,      COLOR_BLACK,   COLOR_CYAN);
    init_pair(C_LIVE,     COLOR_GREEN,   -1);
    init_pair(C_IDLE,     COLOR_WHITE,   -1);
    init_pair(C_INIT,     COLOR_WHITE,   -1);
    init_pair(C_CONN,     COLOR_CYAN,    -1);
    init_pair(C_SEND,     COLOR_GREEN,   -1);
    init_pair(C_RECV,     COLOR_YELLOW,  -1);
    init_pair(C_REPLY,    COLOR_BLUE,    -1);
    init_pair(C_BOOT,     COLOR_MAGENTA, -1);
    init_pair(C_NSXPC,    COLOR_CYAN,    -1);
    init_pair(C_CFMP,     COLOR_MAGENTA, -1);
    init_pair(C_DNOTE,    COLOR_YELLOW,  -1);
    init_pair(C_EVENT,    COLOR_RED,     -1);
    init_pair(C_FILTER,   COLOR_WHITE,   COLOR_BLUE);
    init_pair(C_STATUS,   COLOR_BLACK,   COLOR_GREEN);
    init_pair(C_DIM,      COLOR_WHITE,   -1);
    init_pair(C_PROC_HDR, COLOR_BLACK,   COLOR_WHITE);
}

static int tagClr(const char *tag)
{
    if (!tag[0]) return C_DIM;
    if (strcmp(tag, "INIT")  == 0) return C_INIT;
    if (strcmp(tag, "CONN")  == 0) return C_CONN;
    if (strcmp(tag, "SEND")  == 0) return C_SEND;
    if (strcmp(tag, "RECV")  == 0) return C_RECV;
    if (strcmp(tag, "REPLY") == 0) return C_REPLY;
    if (strcmp(tag, "BOOT")  == 0) return C_BOOT;
    if (strcmp(tag, "NSXPC") == 0) return C_NSXPC;
    if (strcmp(tag, "CFMP")  == 0) return C_CFMP;
    if (strcmp(tag, "DNOTE") == 0) return C_DNOTE;
    if (strcmp(tag, "EVENT") == 0) return C_EVENT;
    return C_DIM;
}

typedef struct
{
    pid_t pid;
    int monitored;
    int msgCount;
} ProcState;

static void scanProcs(App *app)
{
    ProcState old[MAX_PROCS];
    char oldNames[MAX_PROCS][256];
    int nOld = app->nProcs;
    for (int i = 0; i < nOld; i++)
    {
        old[i].pid = app->procs[i].pid;
        old[i].monitored = app->procs[i].monitored;
        old[i].msgCount = app->procs[i].msgCount;
        strlcpy(oldNames[i], app->procs[i].name, 256);
    }

    int pids[8192];
    int n = proc_listallpids(pids, sizeof(pids));

    app->nProcs = 0;
    for (int i = 0; i < n && app->nProcs < MAX_PROCS; i++)
    {
        if (pids[i] <= 1) continue;
        char name[256];
        bzero(name, sizeof(name));
        proc_name(pids[i], name, sizeof(name));
        if (!name[0]) continue;

        int dup = -1;
        for (int d = 0; d < app->nProcs; d++)
        {
            if (strcmp(app->procs[d].name, name) == 0)
            {
                dup = d;
                break;
            }
        }
        if (dup >= 0)
        {
            if (pids[i] > app->procs[dup].pid)
                app->procs[dup].pid = pids[i];
            continue;
        }

        Proc *p = &app->procs[app->nProcs];
        p->pid = pids[i];
        strlcpy(p->name, name, sizeof(p->name));
        p->monitored = 0;
        p->msgCount = 0;

        for (int j = 0; j < nOld; j++)
        {
            if (old[j].pid == pids[i] ||
                strcmp(oldNames[j], name) == 0)
            {
                p->monitored = old[j].monitored;
                if (old[j].msgCount > p->msgCount)
                    p->msgCount = old[j].msgCount;
            }
        }

        if (!p->monitored)
        {
            for (int w = 0; w < app->nWatch; w++)
            {
                if (app->watch[w].pid == pids[i] ||
                    strcmp(app->watch[w].procName, name) == 0)
                {
                    p->monitored = 1;
                }
            }
        }

        app->nProcs++;
    }

    for (int w = 0; w < app->nWatch; w++)
    {
        int found = 0;
        for (int p = 0; p < app->nProcs; p++)
        {
            if (app->watch[w].pid == app->procs[p].pid ||
                strcmp(app->watch[w].procName, app->procs[p].name) == 0)
            {
                found = 1;
                break;
            }
        }
        if (!found && app->nProcs < MAX_PROCS)
        {
            Proc *p = &app->procs[app->nProcs];
            p->pid = app->watch[w].pid;
            strlcpy(p->name, app->watch[w].procName, sizeof(p->name));
            p->monitored = 2;
            p->msgCount = 0;

            for (int j = 0; j < nOld; j++)
            {
                if (old[j].pid == p->pid ||
                    strcmp(app->procs[app->nProcs].name, app->watch[w].procName) == 0)
                {
                    p->msgCount = old[j].msgCount;
                    break;
                }
            }

            app->nProcs++;
        }
    }

    for (int i = 0; i < app->nProcs; i++)
    {
        for (int j = i + 1; j < app->nProcs; j++)
        {
            if (app->procs[j].monitored > app->procs[i].monitored ||
                (app->procs[j].monitored == app->procs[i].monitored &&
                 strcasecmp(app->procs[j].name, app->procs[i].name) < 0))
            {
                Proc tmp = app->procs[i];
                app->procs[i] = app->procs[j];
                app->procs[j] = tmp;
            }
        }
    }
}

static void watchOneDir(App *app, const char *dir)
{
    mkdir(dir, 0777);
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (!strstr(ent->d_name, ".xpc.log")) continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (st.st_mtimespec.tv_sec < app->startTime - 60) continue;

        int found = 0;
        for (int i = 0; i < app->nWatch; i++)
        {
            if (strcmp(app->watch[i].path, path) == 0) { found = 1; break; }
        }
        if (found) continue;
        if (app->nWatch >= MAX_WATCH) continue;

        Watched *w = &app->watch[app->nWatch];
        strlcpy(w->path, path, sizeof(w->path));
        w->fd = open(path, O_RDONLY);
        if (w->fd < 0) continue;
        w->bufLen = 0;
        if (st.st_birthtimespec.tv_sec < app->startTime)
            lseek(w->fd, 0, SEEK_END);

        w->pid = 0;
        bzero(w->procName, sizeof(w->procName));
        sscanf(ent->d_name, "%d_%63[^.]", &w->pid, w->procName);

        app->nWatch++;
    }
    closedir(d);
}

static void watchLogDir(App *app)
{
    watchOneDir(app, LOG_DIR);
    watchOneDir(app, LOG_DIR2);
}

static void startOsLogStream(App *app)
{
    if (app->oslogPipe) return;

    int pipefd[2];
    if (pipe(pipefd) != 0) return;

    pid_t pid = fork();
    if (pid == 0)
    {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execlp("log", "log", "stream", "--style", "compact",
               "--predicate", "subsystem == \"com.axpc.hook\"",
               NULL);
        _exit(127);
    }

    close(pipefd[1]);
    if (pid < 0) { close(pipefd[0]); return; }

    app->oslogPid = pid;
    app->oslogPipe = fdopen(pipefd[0], "r");
    if (app->oslogPipe)
    {
        int fd = fileno(app->oslogPipe);
        int flags = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

static void readOsLogStream(App *app)
{
    if (!app->oslogPipe) return;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), app->oslogPipe))
    {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        char *payload = strstr(line, "com.axpc.hook");
        if (!payload) continue;
        payload = strchr(payload, ']');
        if (!payload) continue;
        payload++;
        while (*payload == ' ') payload++;

        if (app->nLogs >= MAX_LOGS)
        {
            memmove(&app->logs[0], &app->logs[1],
                    sizeof(LogEntry) * (MAX_LOGS - 1));
            app->nLogs = MAX_LOGS - 1;
            if (app->logScroll > 0) app->logScroll--;
        }

        LogEntry *e = &app->logs[app->nLogs];
        bzero(e, sizeof(*e));

        int h, m, s, ms;
        char tag[16];
        bzero(tag, sizeof(tag));

        if (sscanf(payload, "%d:%d:%d.%d %15s ", &h, &m, &s, &ms, tag) >= 5)
        {
            snprintf(e->time, sizeof(e->time), "%02d:%02d:%02d.%03d", h, m, s, ms);
            strlcpy(e->tag, tag, sizeof(e->tag));
            e->clr = tagClr(tag);

            char *msg = strstr(payload, tag);
            if (msg)
            {
                msg += strlen(tag);
                while (*msg == ' ') msg++;
                strlcpy(e->text, msg, sizeof(e->text));
            }
        } else {
            strlcpy(e->text, payload, sizeof(e->text));
            e->clr = C_DIM;
        }

        char procBuf[64];
        bzero(procBuf, sizeof(procBuf));
        int pid = 0;
        char *pidStr = strstr(line, "[");
        if (pidStr)
        {
            sscanf(pidStr + 1, "%d", &pid);
        }
        char *procStart = strstr(line, "com.axpc.hook");
        if (procStart)
        {
            char *bracket = strchr(line, '[');
            if (bracket && bracket > line)
            {
                char *pn = bracket - 1;
                while (pn > line && *(pn - 1) != ' ' && *(pn - 1) != '\t') pn--;
                int len = (int)(bracket - pn);
                if (len > 0 && len < 64)
                {
                    memcpy(procBuf, pn, len);
                    procBuf[len] = '\0';
                }
            }
        }

        e->pid = pid;
        if (procBuf[0])
            strlcpy(e->proc, procBuf, sizeof(e->proc));
        else
            strlcpy(e->proc, "os_log", sizeof(e->proc));

        app->nLogs++;
        app->totalMsgs++;

        for (int p = 0; p < app->nProcs; p++)
        {
            if (app->procs[p].pid == pid ||
                (procBuf[0] && strcmp(app->procs[p].name, procBuf) == 0))
            {
                app->procs[p].msgCount++;
                app->procs[p].monitored = 1;
                break;
            }
        }
    }
    clearerr(app->oslogPipe);
}

static void stopOsLogStream(App *app)
{
    if (app->oslogPipe)
    {
        fclose(app->oslogPipe);
        app->oslogPipe = NULL;
    }
    if (app->oslogPid > 0)
    {
        kill(app->oslogPid, SIGTERM);
        waitpid(app->oslogPid, NULL, 0);
        app->oslogPid = 0;
    }
}

static int parseLine(
    const char *line,
    Watched *w,
    LogEntry *out)
{
    bzero(out, sizeof(*out));
    out->pid = w->pid;
    strlcpy(out->proc, w->procName, sizeof(out->proc));

    int h, m, s, ms;
    char tag[16];
    bzero(tag, sizeof(tag));

    if (sscanf(line, "%d:%d:%d.%d %15s ", &h, &m, &s, &ms, tag) >= 5)
    {
        snprintf(out->time, sizeof(out->time), "%02d:%02d:%02d.%03d", h, m, s, ms);
        strlcpy(out->tag, tag, sizeof(out->tag));
        out->clr = tagClr(tag);

        const char *msg = strstr(line, tag);
        if (msg)
        {
            msg += strlen(tag);
            while (*msg == ' ') msg++;
            strlcpy(out->text, msg, sizeof(out->text));
        }
    } else {
        strlcpy(out->text, line, sizeof(out->text));
        out->clr = C_DIM;
    }

    char *nl = strchr(out->text, '\n');
    if (nl) *nl = '\0';

    return 1;
}

static void readLogs(App *app)
{
    for (int i = 0; i < app->nWatch; i++)
    {
        Watched *w = &app->watch[i];
        if (w->fd < 0) continue;

        char tmp[2048];
        ssize_t n = read(w->fd, tmp, sizeof(tmp));
        if (n <= 0) continue;

        for (ssize_t j = 0; j < n; j++)
        {
            if (tmp[j] == '\n')
            {
                w->buf[w->bufLen] = '\0';

                if (w->bufLen > 0)
                {
                    if (app->nLogs >= MAX_LOGS)
                    {
                        memmove(&app->logs[0], &app->logs[1],
                                sizeof(LogEntry) * (MAX_LOGS - 1));
                        app->nLogs = MAX_LOGS - 1;
                        if (app->logScroll > 0) app->logScroll--;
                    }

                    parseLine(w->buf, w, &app->logs[app->nLogs]);
                    app->nLogs++;
                    app->totalMsgs++;

                    for (int p = 0; p < app->nProcs; p++)
                    {
                        if (app->procs[p].pid == w->pid ||
                            strcmp(app->procs[p].name, w->procName) == 0)
                        {
                            app->procs[p].msgCount++;
                            app->procs[p].monitored = 1;
                            break;
                        }
                    }
                }
                w->bufLen = 0;
            }
            else if (w->bufLen < (int)sizeof(w->buf) - 1)
            {
                w->buf[w->bufLen++] = tmp[j];
            }
        }
    }
}

static int matchFilter(App *app, LogEntry *e)
{
    if (!app->filterLen) return 1;

    char filt[256];
    strlcpy(filt, app->filter, sizeof(filt));

    char *tok = strtok(filt, " ");
    while (tok)
    {
        if (strncmp(tok, "pid:", 4) == 0)
        {
            pid_t fp = atoi(tok + 4);
            if (e->pid != fp) return 0;
        } else if (strncmp(tok, "tag:", 4) == 0) {
            if (strcasecmp(e->tag, tok + 4) != 0) return 0;
        } else if (strncmp(tok, "port:", 5) == 0) {
            if (!strstr(e->text, tok + 5)) return 0;
        } else {
            if (!strcasestr(e->text, tok) &&
                !strcasestr(e->proc, tok) &&
                !strcasestr(e->tag, tok))
                return 0;
        }
        tok = strtok(NULL, " ");
    }
    return 1;
}

static void drawTitle(void)
{
    attron(COLOR_PAIR(C_TITLE) | A_BOLD);
    mvhline(0, 0, ' ', COLS);
    mvprintw(0, 1, "axpc");
    attroff(A_BOLD);
    mvprintw(0, COLS - 40, "tab:switch  enter:inject  /:filter  q:quit");
    attroff(COLOR_PAIR(C_TITLE));
}

static void drawProcs(App *app)
{
    int y = 1;
    attron(COLOR_PAIR(C_PROC_HDR));
    mvhline(y, 0, ' ', COLS);
    mvprintw(y, 1, "  %-7s %-24s %-14s %s", "PID", "NAME", "STATUS", "MSGS");
    attroff(COLOR_PAIR(C_PROC_HDR));

    for (int i = 0; i < app->procH - 1 && i + app->procScroll < app->nProcs; i++)
    {
        int idx = i + app->procScroll;
        Proc *p = &app->procs[idx];
        int row = y + 1 + i;

        if (idx == app->procSel && app->focus == 0)
        {
            attron(COLOR_PAIR(C_SEL));
            mvhline(row, 0, ' ', COLS);
        } else {
            move(row, 0);
            clrtoeol();
        }

        if (p->monitored == 2)
        {
            if (!(idx == app->procSel && app->focus == 0))
                attron(COLOR_PAIR(C_EVENT));
            mvprintw(row, 1, "%s", "\xe2\x97\x8f");
            mvprintw(row, 3, "%-7d %-24s %-14s %d",
                     p->pid, p->name, "exited", p->msgCount);
            if (!(idx == app->procSel && app->focus == 0))
                attroff(COLOR_PAIR(C_EVENT));
        } else if (p->monitored) {
            if (!(idx == app->procSel && app->focus == 0))
                attron(COLOR_PAIR(C_LIVE));
            mvprintw(row, 1, "%s", "\xe2\x97\x8f");
            mvprintw(row, 3, "%-7d %-24s %-14s %d",
                     p->pid, p->name, "monitoring", p->msgCount);
            if (!(idx == app->procSel && app->focus == 0))
                attroff(COLOR_PAIR(C_LIVE));
        } else {
            attron(A_DIM);
            mvprintw(row, 1, "%s", "\xe2\x97\x8b");
            mvprintw(row, 3, "%-7d %-24s", p->pid, p->name);
            attroff(A_DIM);
        }

        if (idx == app->procSel && app->focus == 0)
            attroff(COLOR_PAIR(C_SEL));
    }
}

static void drawFilter(App *app)
{
    int y = 1 + app->procH;
    attron(COLOR_PAIR(C_FILTER));
    mvhline(y, 0, ' ', COLS);
    if (app->focus == 2)
        mvprintw(y, 1, " filter: %s\xe2\x96\x8e", app->filter);
    else if (app->filterLen)
        mvprintw(y, 1, " filter: %s", app->filter);
    else
        mvprintw(y, 1, " filter: (press / to type)");
    attroff(COLOR_PAIR(C_FILTER));
}

static int *gVisible = NULL;

static void drawLogs(App *app)
{
    int logY = 2 + app->procH;
    int logH = LINES - logY - 1;
    if (logH < 1) return;

    if (!gVisible)
        gVisible = (int *)malloc(sizeof(int) * MAX_LOGS);

    int nVisible = 0;
    for (int i = 0; i < app->nLogs; i++)
    {
        if (matchFilter(app, &app->logs[i]))
            gVisible[nVisible++] = i;
    }

    if (app->autoScroll && nVisible > logH)
        app->logScroll = nVisible - logH;
    if (app->logScroll < 0) app->logScroll = 0;
    if (nVisible > logH)
    {
        if (app->logScroll >= nVisible - logH)
        {
            app->logScroll = nVisible - logH;
            app->autoScroll = 1;
        }
    }

    for (int row = 0; row < logH; row++)
    {
        int vi = row + app->logScroll;
        int y = logY + row;

        move(y, 0);
        clrtoeol();

        if (vi >= nVisible) continue;
        LogEntry *e = &app->logs[gVisible[vi]];

        int sel = (row == 0 && app->focus == 1) ? 1 : 0;
        (void)sel;

        attron(A_DIM);
        mvprintw(y, 0, " %s", e->time);
        attroff(A_DIM);

        attron(COLOR_PAIR(e->clr) | A_BOLD);
        mvprintw(y, 14, "%5s", e->tag);
        attroff(COLOR_PAIR(e->clr) | A_BOLD);

        attron(A_BOLD);
        mvprintw(y, 20, "%-10s", e->proc);
        attroff(A_BOLD);

        int msgX = 31;
        int maxW = COLS - msgX - 1;
        if (maxW > 0)
        {
            char trunc[MAX_LINE];
            strlcpy(trunc, e->text, sizeof(trunc));
            if ((int)strlen(trunc) > maxW) trunc[maxW] = '\0';
            mvprintw(y, msgX, "%s", trunc);
        }
    }
}

static void drawStatus(App *app)
{
    int y = LINES - 1;
    attron(COLOR_PAIR(C_STATUS));
    mvhline(y, 0, ' ', COLS);

    int monitored = 0;
    for (int i = 0; i < app->nProcs; i++)
        if (app->procs[i].monitored) monitored++;

    mvprintw(y, 1, " %d monitored  |  %d messages  |  %d log files",
             monitored, app->totalMsgs, app->nWatch);

    if (app->autoScroll)
        mvprintw(y, COLS - 14, "auto-scroll ");
    else
        mvprintw(y, COLS - 14, "scroll: %d ", app->logScroll);

    attroff(COLOR_PAIR(C_STATUS));
}

static void drawAll(App *app)
{
    erase();
    drawTitle();
    drawProcs(app);
    drawFilter(app);
    drawLogs(app);
    drawStatus(app);
    refresh();
}

static int isRestricted(pid_t pid)
{
    char path[PROC_PIDPATHINFO_MAXSIZE];
    bzero(path, sizeof(path));
    if (proc_pidpath(pid, path, sizeof(path)) <= 0) return 0;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "otool -l '%s' 2>/dev/null | grep -q '__RESTRICT'", path);
    return system(cmd) == 0;
}

static int findLaunchdLabel(pid_t pid, char *label, size_t len)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "launchctl list 2>/dev/null");
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;

    char line[1024];
    while (fgets(line, sizeof(line), fp))
    {
        int lpid = 0;
        char lbl[512];
        bzero(lbl, sizeof(lbl));
        if (sscanf(line, "%d %*d %511s", &lpid, lbl) == 2)
        {
            if (lpid == pid)
            {
                strlcpy(label, lbl, len);
                pclose(fp);
                return 1;
            }
        }
    }
    pclose(fp);
    return 0;
}

static int showMenu(App *app, Proc *p)
{
    char label[512];
    bzero(label, sizeof(label));
    int isDaemon = findLaunchdLabel(p->pid, label, sizeof(label));
    int restricted = isRestricted(p->pid);

    int h = restricted ? 10 : 8;
    int w = 52;
    int y = (LINES - h) / 2;
    int x = (COLS - w) / 2;
    WINDOW *win = newwin(h, w, y, x);
    box(win, 0, 0);

    wattron(win, A_BOLD);
    mvwprintw(win, 0, 2, " %s (pid %d) ", p->name, p->pid);
    wattroff(win, A_BOLD);

    mvwprintw(win, 2, 3, "1  inject (dlopen, NSXPC only)");
    if (isDaemon)
        mvwprintw(win, 3, 3, "2  restart all hooks (daemon: %s)", label);
    else
        mvwprintw(win, 3, 3, "2  restart all hooks (kill+relaunch)");

    if (restricted)
    {
        wattron(win, COLOR_PAIR(C_EVENT) | A_BOLD);
        mvwprintw(win, 5, 3, "__RESTRICT: DYLD_INSERT blocked by dyld");
        wattroff(win, COLOR_PAIR(C_EVENT) | A_BOLD);
        mvwprintw(win, 6, 3, "only inject (1) works for this process");
        mvwprintw(win, h - 2, 3, "ESC cancel");
    } else {
        mvwprintw(win, h - 2, 3, "ESC cancel");
    }

    wrefresh(win);

    int choice = -1;
    nodelay(stdscr, FALSE);
    while (1)
    {
        int ch = wgetch(win);
        if (ch == '1') { choice = 1; break; }
        if (ch == '2') { choice = isDaemon ? 3 : 2; break; }
        if (ch == 27 || ch == 'q') break;
    }
    nodelay(stdscr, TRUE);

    delwin(win);
    return choice;
}

static void doInject(App *app, Proc *p, int mode)
{
    char dylib[1024], cmd[2048];
    snprintf(dylib, sizeof(dylib), "%s/xpchook.dylib", app->selfDir);

    bzero(cmd, sizeof(cmd));

    if (mode == 1)
    {
        snprintf(cmd, sizeof(cmd), "%s/injector -p %d '%s'",
                 app->selfDir, p->pid, dylib);
    } else if (mode == 2) {
        snprintf(cmd, sizeof(cmd), "%s/injector -r '%s' '%s'",
                 app->selfDir, p->name, dylib);
    } else if (mode == 3) {
        char label[512];
        bzero(label, sizeof(label));
        findLaunchdLabel(p->pid, label, sizeof(label));
        snprintf(cmd, sizeof(cmd), "%s/injector -d '%s' '%s'",
                 app->selfDir, label, dylib);
    }

    def_prog_mode();
    endwin();
    printf("\n$ %s\n\n", cmd);
    system(cmd);
    printf("\n");
    sleep(1);

    reset_prog_mode();
    refresh();
    nodelay(stdscr, TRUE);
}

static void copyLogs(App *app)
{
    if (!gVisible) return;

    int logY = 2 + app->procH;
    int logH = LINES - logY - 1;
    if (logH < 1) return;

    int nVisible = 0;
    for (int i = 0; i < app->nLogs; i++)
    {
        if (matchFilter(app, &app->logs[i]))
            gVisible[nVisible++] = i;
    }

    FILE *pb = popen("pbcopy", "w");
    if (!pb) return;

    int start = app->logScroll;
    int end = start + logH;
    if (end > nVisible) end = nVisible;

    for (int vi = start; vi < end; vi++)
    {
        LogEntry *e = &app->logs[gVisible[vi]];
        fprintf(pb, "%s %s %s %s\n", e->time, e->tag, e->proc, e->text);
    }
    pclose(pb);
}

static void handleInput(App *app, int ch)
{
    if (app->focus == 2)
    {
        if (ch == 27 || ch == '\n')
        {
            app->focus = 1;
            app->logScroll = 0;
            app->autoScroll = 1;
            return;
        }
        if (ch == KEY_BACKSPACE || ch == 127)
        {
            if (app->filterLen > 0)
                app->filter[--app->filterLen] = '\0';
            return;
        }
        if (ch >= 32 && ch < 127 && app->filterLen < 250)
        {
            app->filter[app->filterLen++] = ch;
            app->filter[app->filterLen] = '\0';
            app->logScroll = 0;
            app->autoScroll = 1;
            return;
        }
        return;
    }

    switch (ch)
    {
        case 'q':
            app->running = 0;
            break;

        case '\t':
            app->focus = (app->focus + 1) % 2;
            break;

        case '/':
            app->focus = 2;
            break;

        case 'y':
            copyLogs(app);
            break;

        case 'c':
            app->filter[0] = '\0';
            app->filterLen = 0;
            app->autoScroll = 1;
            break;

        case KEY_UP:
        case 'k':
            if (app->focus == 0)
            {
                if (app->procSel > 0) app->procSel--;
                if (app->procSel < app->procScroll)
                    app->procScroll = app->procSel;
            } else {
                app->autoScroll = 0;
                if (app->logScroll > 0) app->logScroll--;
            }
            break;

        case KEY_DOWN:
        case 'j':
            if (app->focus == 0)
            {
                if (app->procSel < app->nProcs - 1) app->procSel++;
                if (app->procSel >= app->procScroll + app->procH - 1)
                    app->procScroll = app->procSel - app->procH + 2;
            } else {
                app->autoScroll = 0;
                app->logScroll++;
            }
            break;

        case KEY_PPAGE:
            if (app->focus == 1)
            {
                app->autoScroll = 0;
                app->logScroll -= (LINES - app->procH - 4);
                if (app->logScroll < 0) app->logScroll = 0;
            }
            break;

        case KEY_NPAGE:
            if (app->focus == 1)
            {
                app->logScroll += (LINES - app->procH - 4);
                app->autoScroll = 0;
            }
            break;

        case 'G':
            app->autoScroll = 1;
            break;

        case '\n':
        case KEY_ENTER:
            if (app->focus == 0 && app->procSel < app->nProcs)
            {
                Proc *p = &app->procs[app->procSel];
                int mode = showMenu(app, p);
                if (mode > 0) doInject(app, p, mode);
            }
            break;

    }
}

int main(int argc, char **argv)
{
    if (getuid() != 0)
    {
        fprintf(stderr, "need root: sudo %s\n", argv[0]);
        return 1;
    }

    setlocale(LC_ALL, "");

    App app;
    bzero(&app, sizeof(app));
    for (int i = 0; i < MAX_WATCH; i++) app.watch[i].fd = -1;
    app.logs = (LogEntry *)malloc(sizeof(LogEntry) * MAX_LOGS);
    bzero(app.logs, sizeof(LogEntry) * MAX_LOGS);
    app.running = 1;
    app.autoScroll = 1;
    app.startTime = time(NULL);
    getSelfDir(app.selfDir, sizeof(app.selfDir));

    signal(SIGWINCH, onWinch);

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, FALSE);
    nodelay(stdscr, TRUE);
    curs_set(0);
    mousemask(ALL_MOUSE_EVENTS, NULL);
    printf("\033[?1000h");
    initColors();

    mkdir(LOG_DIR, 0777);

    app.procH = LINES / 3;
    if (app.procH < 6) app.procH = 6;
    if (app.procH > 20) app.procH = 20;

    scanProcs(&app);
    watchLogDir(&app);
    startOsLogStream(&app);
    gettimeofday(&app.lastScan, NULL);

    while (app.running)
    {
        if (gResize)
        {
            gResize = 0;
            endwin();
            refresh();
            app.procH = LINES / 3;
            if (app.procH < 6) app.procH = 6;
            if (app.procH > 20) app.procH = 20;
        }

        int ch = getch();
        while (ch != ERR)
        {
            if (ch == 27)
            {
                wtimeout(stdscr, 10);
                int c2 = getch();
                if (c2 == '[')
                {
                    int c3 = getch();
                    if (c3 == 'A') handleInput(&app, KEY_UP);
                    else if (c3 == 'B') handleInput(&app, KEY_DOWN);
                    else if (c3 == '5') { getch(); handleInput(&app, KEY_PPAGE); }
                    else if (c3 == '6') { getch(); handleInput(&app, KEY_NPAGE); }
                    else if (c3 == 'M')
                    {
                        int btn = getch() - 32;
                        (void)getch();
                        int my = getch() - 33;
                        int filterY = 1 + app.procH;
                        int logY = 2 + app.procH;
                        if (btn == 64)
                        {
                            if (my < filterY)
                            {
                                if (app.procSel > 0) app.procSel -= 3;
                                if (app.procSel < 0) app.procSel = 0;
                                if (app.procSel < app.procScroll)
                                    app.procScroll = app.procSel;
                            } else if (my >= logY) {
                                app.autoScroll = 0;
                                app.logScroll -= 3;
                                if (app.logScroll < 0) app.logScroll = 0;
                            }
                        }
                        else if (btn == 65)
                        {
                            if (my < filterY)
                            {
                                app.procSel += 3;
                                if (app.procSel >= app.nProcs)
                                    app.procSel = app.nProcs - 1;
                                if (app.procSel >= app.procScroll + app.procH - 1)
                                    app.procScroll = app.procSel - app.procH + 2;
                            } else if (my >= logY) {
                                app.autoScroll = 0;
                                app.logScroll += 3;
                            }
                        }
                    }
                    else if (c3 != ERR) { ungetch(c3); handleInput(&app, 27); }
                    else handleInput(&app, 27);
                }
                else
                {
                    if (c2 != ERR) ungetch(c2);
                    handleInput(&app, 27);
                }
                nodelay(stdscr, TRUE);
            } else {
                handleInput(&app, ch);
            }
            ch = getch();
        }

        struct timeval now;
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - app.lastScan.tv_sec) * 1000 +
                       (now.tv_usec - app.lastScan.tv_usec) / 1000;

        if (elapsed > 500)
        {
            scanProcs(&app);
            watchLogDir(&app);
            app.lastScan = now;
        }

        readLogs(&app);
        readOsLogStream(&app);
        app.tick++;
        drawAll(&app);
        usleep(16000);
    }

    printf("\033[?1000l\n");
    endwin();
    stopOsLogStream(&app);

    for (int i = 0; i < app.nWatch; i++)
    {
        if (app.watch[i].fd >= 0) close(app.watch[i].fd);
    }

    free(app.logs);
    if (gVisible) free(gVisible);

    return 0;
}
