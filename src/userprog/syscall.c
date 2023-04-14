#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"


//User space's stack pointer
static void *user_esp;

static void syscall_handler (struct intr_frame *);

/* Helper functions for verifying user-provided pointers. */
static bool addr_valid(void *ptr);
static bool addr_valid_str(void *ptr);
static bool addr_valid_buf(void *ptr, unsigned size);

/* Called by the syscall_handler to terminate the process if the user-provided string is invalid. */
static void check_addr_str(void *ptr);
static void check_addr_buf(void *ptr, unsigned size);

/* System call functions. */
static void halt(void);
static void exit(int status);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  user_esp = f->esp;
  //Check if the user-provided pointer is valid
  check_addr_buf(user_esp, 4);
  //Get the system call number
  int syscall_num = *((int *)user_esp);
  switch(syscall_num)
  {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_addr_buf(user_esp + 4, 4);
      exit(*((int *)(user_esp + 4)));
      break;
    default:
      break;
  }





  // printf ("system call!\n");
  // thread_exit ();
}

/* Helper function, verify the validity of a user-provided pointer. */
static bool addr_valid(void *ptr)
{
  if (ptr == NULL || !is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
    return false;
  return true;
}


/* Verify the validity of a user-provided string. */
static bool addr_valid_str(void *ptr)
{
  int i;
  for (i = 0; ; i++)
  {
    if (!addr_valid(ptr + i))
      return false;
    if (*((char *)ptr + i) == '\0')
      break;
  }
  return true;
}

/* Verify the validity of a user-provided buffer. */
static bool addr_valid_buf(void *ptr, unsigned size)
{
  int i;
  for (i = 0; i < size; i++)
  {
    if (!addr_valid(ptr + i))
      return false;
  }
  return true;
}

/* Verify and terminate the process if the user-provided string is invalid. */
static void check_addr_str(void *ptr)
{
  if (!addr_valid_str(ptr))
    exit(-1);
}

/* Verify and terminate the process if the user-provided buffer is invalid. */
static void check_addr_buf(void *ptr, unsigned size)
{
  if (!addr_valid_buf(ptr, size))
    exit(-1);
}

/* Terminates Pintos by calling shutdown_power_off() (declared in "threads/init.h"). 
   This should be seldom used, because you lose some information about possible deadlock situations, etc. */
static void halt(void)
{
  shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. If the process's parent waits for it (see below), 
   this is the status that will be returned. Conventionally, a status of 0 indicates success and nonzero values indicate errors. */
static void exit(int status)
{
  thread_current()->exit_status = status;
  printf("%s: exit(%d)", thread_current()->name, status);
  thread_exit();
}


