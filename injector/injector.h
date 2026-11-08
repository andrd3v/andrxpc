//
//  injector.h
//  andrxpc
//
//  Created by andr on 08.11.2026.
//

#ifndef ANDRXPC_INJECTOR_H
#define ANDRXPC_INJECTOR_H

#include <mach/mach.h>
#include <sys/types.h>

int pst_init(void);
mach_port_t pst_find_task(pid_t pid);
void pst_cleanup(void);
mach_port_t get_task(pid_t pid);
pid_t find_pid_by_name(const char *name);
int inject_dylib(task_t task, pid_t pid, const char *dylibPath);

#endif
