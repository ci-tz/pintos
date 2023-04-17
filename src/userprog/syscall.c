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
static int wait(int pid);
static int write(int fd, const void *buffer, unsigned size);

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
    case SYS_WAIT:
      check_addr_buf(user_esp + 4, 4);
      f->eax = wait(*((int *)(user_esp + 4)));
      break;
    case SYS_WRITE:
      check_addr_buf(user_esp + 4, 4);
      check_addr_buf(user_esp + 8, 4);
      check_addr_buf(user_esp + 12, 4);
      check_addr_buf(user_esp + 16, 4);
      f->eax = write(*((int *)(user_esp + 4)), *((void **)(user_esp + 8)), *((unsigned *)(user_esp + 12)));
      break;
    default:
      exit(-1);
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
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
  printf("after thread_exit() in exit(),%s\n", thread_current()->name);
}

/* Wait for termination of child process whose process id is pid. If the child process has already terminated, 
   return immediately. Otherwise, wait until the child process terminates and then return its exit status. */
static int wait(int pid)
{
  return process_wait(pid);
}

/* Write size bytes from buffer to the open file fd. Returns the number of bytes actually written, 
   which may be less than size if some bytes could not be written. */
static int write(int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  else
    return -1;
}


