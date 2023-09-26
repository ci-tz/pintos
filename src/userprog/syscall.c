#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"


//Use global lock to avoid race condition on file
struct lock filesys_lock;

//User space's stack pointer
static uint8_t *user_esp;

static void syscall_handler (struct intr_frame *);

/* Helper function, verify the validity of a user-provided pointer. */
static void check_user (const uint8_t *uaddr);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void copy_from_user (void *src, void *des, size_t bytes);

/* Called by the syscall_handler to terminate the process if the user-provided string is invalid. */
static void check_addr_str(void *ptr);
static void check_addr_buf(void *ptr, unsigned size);

static int find_next_fd(void);

/* System call functions. */
static void halt(void);
void exit(int status);
static int wait(int pid);
static int exec(const char *cmd_line);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
void close(int fd);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  //Initialize the global lock
  lock_init(&filesys_lock);
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
    case SYS_EXEC:
      check_addr_buf(user_esp + 4, 4);
      check_addr_str(*((void **)(user_esp + 4)));
      f->eax = exec(*((char **)(user_esp + 4)));
      break;
    case SYS_CREATE:
      check_addr_buf(user_esp + 4, 4);
      check_addr_buf(user_esp + 8, 4);
      check_addr_str(*((void **)(user_esp + 4)));
      f->eax = create(*((char **)(user_esp + 4)), *((unsigned *)(user_esp + 8)));
      break;
    case SYS_REMOVE:
      check_addr_buf(user_esp + 4, 4);
      check_addr_str(*((void **)(user_esp + 4)));
      f->eax = remove(*((char **)(user_esp + 4)));
      break;
    case SYS_OPEN:
      check_addr_buf(user_esp + 4, 4);
      check_addr_str(*((void **)(user_esp + 4)));
      f->eax = open(*((char **)(user_esp + 4)));
      break;
    case SYS_FILESIZE:
      check_addr_buf(user_esp + 4, 4);
      f->eax = filesize(*((int *)(user_esp + 4)));
      break;
    case SYS_READ:
      check_addr_buf(user_esp + 4, 4);
      check_addr_buf(user_esp + 8, 4);
      check_addr_buf(user_esp + 12, 4);
      check_addr_buf(*((void**)(user_esp + 8)), *(unsigned*)(user_esp + 12));
      f->eax = read(*((int *)(user_esp + 4)), *((void **)(user_esp + 8)), *((unsigned *)(user_esp + 12)));
      break;
    case SYS_WRITE:
      check_addr_buf(user_esp + 4, 4);
      check_addr_buf(user_esp + 8, 4);
      check_addr_buf(user_esp + 12, 4);
      check_addr_buf(*((void**)(user_esp + 8)), *(unsigned*)(user_esp + 12));
      f->eax = write(*((int *)(user_esp + 4)), *((void **)(user_esp + 8)), *((unsigned *)(user_esp + 12)));
      break;
    case SYS_SEEK:
      check_addr_buf(user_esp + 4, 4);
      check_addr_buf(user_esp + 8, 4);
      seek(*((int *)(user_esp + 4)), *((unsigned *)(user_esp + 8)));
      break;
    case SYS_TELL:
      check_addr_buf(user_esp + 4, 4);
      f->eax = tell(*((int *)(user_esp + 4)));
      break;
    case SYS_CLOSE:
      check_addr_buf(user_esp + 4, 4);
      close(*((int *)(user_esp + 4)));
      break;
    default:
      printf("Invalid system call number: %d\n", syscall_num);
      exit(-1);
      break;
  }
}


/* Terminates Pintos by calling shutdown_power_off() (declared in "threads/init.h"). 
   This should be seldom used, because you lose some information about possible deadlock situations, etc. */
static void halt(void)
{
  shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. If the process's parent waits for it (see below), 
   this is the status that will be returned. Conventionally, a status of 0 indicates success and nonzero values indicate errors. */
void exit(int status)
{
  thread_current()->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
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
  //Judge if fd is leagal

  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    return size;
  }
  else
  {
    //Judge if fd is leagal
    if (fd < 2 || fd >= MAX_FD)
      return -1;
    struct file *file = thread_current()->fdt[fd];
    if (file == NULL)
      return -1;
    lock_acquire(&filesys_lock);
    int bytes_written = file_write(file, buffer, size);
    lock_release(&filesys_lock);
    return bytes_written;
  }
}

/* Changes the next byte to be read or written in open file fd to position. */
static void seek(int fd, unsigned position)
{
  //Judge if fd is leagal
  if (fd < 2 || fd >= MAX_FD)
    return;
  struct thread* curr = thread_current();
  struct file *file = curr->fdt[fd];
  if (file == NULL)
    return;
  lock_acquire(&filesys_lock);
  file_seek(file, position);
  lock_release(&filesys_lock);
}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. */
static unsigned tell(int fd)
{
  //Judge if fd is leagal
  if (fd < 2 || fd >= MAX_FD)
    return -1;
  struct thread* curr = thread_current();
  struct file *file = curr->fdt[fd];
  if (file == NULL)
    return -1;
  lock_acquire(&filesys_lock);
  unsigned position = file_tell(file);
  lock_release(&filesys_lock);
  return position;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, 
   as if by calling this function for each one. */
void close(int fd)
{
  //Judge if fd is leagal
  if (fd < 2 || fd >= MAX_FD)
    return;
  struct thread* curr = thread_current();
  struct file *file = curr->fdt[fd];
  if (file == NULL)
    return;
  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);
  curr->fdt[fd] = NULL;
}

/* Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). 
   Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. 
   Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. 
   You must use appropriate synchronization to ensure this. */
static int exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

/* Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. 
   Creating a new file does not open it: opening the new file is a separate operation which would require a open system call. */
static bool create(const char *file, unsigned initial_size)
{
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

/* Deletes the file called file. Returns true if successful, false otherwise. 
   A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. 
   See Removing an Open File, for details. */
static bool remove(const char *file)
{
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

/* Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), 
   or -1 if the file could not be opened. */
static int open(const char *file)
{
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  lock_release(&filesys_lock);
  if (f == NULL)
    return -1;
  else
  {
    struct thread* curr = thread_current();
    if(curr->next_fd == -1)
    {
      printf("ERROR: File descriptor table is full.\n");
      return -1;
    }
    curr->fdt[curr->next_fd] = f;
    int fd = curr->next_fd;
    curr->next_fd = find_next_fd();
    return fd;
  }
}

/* Helper function to find the next available file descriptor. */
static int find_next_fd(void)
{
  struct thread* curr = thread_current();
  int i;
  for (i = 2; i < MAX_FD; i++)
  {
    if (curr->fdt[i] == NULL)
      return i;
  }
  return -1;
}

/* Returns the size, in bytes, of the file open as fd. */
static int filesize(int fd)
{
  //Judge if fd is leagal
  if (fd < 2 || fd >= MAX_FD)
    return -1;
  lock_acquire(&filesys_lock);
  int size = file_length(thread_current()->fdt[fd]);
  lock_release(&filesys_lock);
  return size;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), 
   or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc(). */
static int read(int fd, void *buffer, unsigned size)
{
  if (fd == 0)
  {
    unsigned i;
    for (i = 0; i < size; i++)
      *((char *)buffer + i) = input_getc();
    return size;
  }
  else
  {
    //Judge if fd is leagal
    if (fd < 2 || fd >= MAX_FD)
      return -1;
    struct file *file = thread_current()->fdt[fd];
    if(file == NULL)
      return -1;
    lock_acquire(&filesys_lock);
    int bytes_read = file_read(file, buffer, size);
    lock_release(&filesys_lock);
    return bytes_read;
  }
}

/**
 * Reads a single 'byte' at user memory admemory at 'uaddr'.
 * 'uaddr' must be below PHYS_BASE.
 *
 * Returns the byte value if successful (extract the least significant byte),
 * or -1 in case of error (a segfault occurred or invalid uaddr)
 */
static int get_user(const uint8_t *uaddr)
{
  if (!is_user_vaddr(uaddr))
    return -1;
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

/* Writes a single byte (content is 'byte') to user address 'udst'.
 * 'udst' must be below PHYS_BASE.
 *
 * Returns true if successful, false if a segfault occurred.
 */

static bool put_user(uint8_t *udst, uint8_t byte)
{
  if (!is_user_vaddr(udst))
    return false;

  int error_code;
  // as suggested in the reference manual, see (3.1.5)
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}

/**
 * Copy consecutive `bytes` of data from user memory space with the
 * starting address `src`, and writes to `dst`.
 *
 * In case of invalid memory access, exit() is called and consequently
 * the process is terminated with return code -1.
 */
static void copy_from_user(void *src, void *des, size_t bytes)
{
  int value;
  for (int i = 0; i < bytes; i++) {
    value = get_user(src + i);
    if (value == -1)
      exit(-1);
    else
      *((uint8_t *)des + i) = value;
  }
}