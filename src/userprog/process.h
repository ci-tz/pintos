#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"

#define MAXARGC (128)
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#ifdef VM
bool handle_mm_fault(struct sup_pte *pte);
#endif

#endif /* userprog/process.h */
