#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdint.h>
#include <stdio.h>
#include <syscall-nr.h>

// Use global lock to avoid race condition on file
struct lock filesys_lock;

// User space's stack pointer
static uint8_t *user_esp;

static void syscall_handler(struct intr_frame *);

/* Helper function, verify the validity of a user-provided pointer. */
static void validate_ptr_range(const void *vaddr, size_t size);
static void validate_string(const char *str);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
static bool copy_from_user(const void *src, void *des, size_t bytes);
static bool copy_to_user(void *src, void *des, size_t bytes);
static void copy_from_user_exits(void *src, void *des, size_t bytes);
static void copy_to_user_exits(void *src, void *des, size_t bytes);
static bool copy_from_user_str(void *src, void *des);

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

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    // Initialize the global lock
    lock_init(&filesys_lock);
}

static void syscall_handler(struct intr_frame *f UNUSED)
{
    user_esp = f->esp;
    int syscall_num;

    copy_from_user_exits(user_esp, &syscall_num, sizeof(int));
    switch (syscall_num) {
    case SYS_HALT: {
        halt();
        break;
    }
    case SYS_EXIT: {
        int exit_status;
        copy_from_user_exits(user_esp + 4, &exit_status, sizeof(int));
        exit(exit_status);
        break;
    }
    case SYS_WAIT: {
        int pid;
        copy_from_user(user_esp + 4, &pid, sizeof(int));
        f->eax = wait(pid);
        break;
    }
    case SYS_EXEC: {
        int cmd_line;
        copy_from_user_exits(user_esp + 4, &cmd_line, sizeof(int));
        f->eax = exec((char *)cmd_line);
        break;
    }
    case SYS_CREATE: {
        int filename;
        int initial_size;
        copy_from_user_exits(user_esp + 4, &filename, sizeof(int));
        copy_from_user_exits(user_esp + 8, &initial_size, sizeof(int));
        f->eax = create((char *)filename, initial_size);
        break;
    }
    case SYS_REMOVE: {
        int filename;
        copy_from_user_exits(user_esp + 4, &filename, sizeof(int));
        f->eax = remove((char *)filename);
        break;
    }
    case SYS_OPEN: {
        int filename;
        copy_from_user_exits(user_esp + 4, &filename, sizeof(int));
        f->eax = open((char *)filename);
        break;
    }
    case SYS_FILESIZE: {
        int fd;
        copy_from_user_exits(user_esp + 4, &fd, sizeof(int));
        f->eax = filesize(fd);
        break;
    }
    case SYS_READ: {
        int fd;
        int buffer;
        int size;
        copy_from_user_exits(user_esp + 4, &fd, sizeof(int));
        copy_from_user_exits(user_esp + 8, &buffer, sizeof(int));
        copy_from_user_exits(user_esp + 12, &size, sizeof(int));
        f->eax = read(fd, (void *)buffer, size);
        break;
    }
    case SYS_WRITE: {
        int fd;
        int buffer;
        int size;
        copy_from_user_exits(user_esp + 4, &fd, sizeof(int));
        copy_from_user_exits(user_esp + 8, &buffer, sizeof(int));
        copy_from_user_exits(user_esp + 12, &size, sizeof(int));
        f->eax = write(fd, (void *)buffer, size);
        break;
    }
    case SYS_SEEK: {
        int fd;
        int position;
        copy_from_user_exits(user_esp + 4, &fd, sizeof(int));
        copy_from_user_exits(user_esp + 8, &position, sizeof(int));
        seek(fd, position);
        break;
    }
    case SYS_TELL: {
        int fd;
        copy_from_user_exits(user_esp + 4, &fd, sizeof(int));
        f->eax = tell(fd);
        break;
    }
    case SYS_CLOSE: {
        int fd;
        copy_from_user_exits(user_esp + 4, &fd, sizeof(int));
        close(fd);
        break;
    }
    default:
        printf("Invalid system call number: %d\n", syscall_num);
        exit(-1);
        break;
    }
}

/* Terminates Pintos by calling shutdown_power_off() (declared in
   "threads/init.h"). This should be seldom used, because you lose some
   information about possible deadlock situations, etc. */
static void halt(void) { shutdown_power_off(); }

/* Terminates the current user program, returning status to the kernel. If the
   process's parent waits for it (see below), this is the status that will be
   returned. Conventionally, a status of 0 indicates success and nonzero values
   indicate errors. */
void exit(int status)
{
    thread_current()->exit_status = status;
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

/* Wait for termination of child process whose process id is pid. If the child
   process has already terminated, return immediately. Otherwise, wait until the
   child process terminates and then return its exit status. */
static int wait(int pid) { return process_wait(pid); }

/* Write size bytes from buffer to the open file fd. Returns the number of bytes
   actually written, which may be less than size if some bytes could not be
   written. */
static int write(int fd, const void *buffer, unsigned size)
{
    if(size == 0) {
        return 0;
    }
    void *kbuffer = malloc(size);
    if (kbuffer == NULL) {
        exit(-1);
    }

    bool success = copy_from_user(buffer, kbuffer, size);
    if (!success) {
        free(kbuffer);
        exit(-1);
    }

    int bytes_written = 0;
    if (fd == 1) {
        putbuf(kbuffer, size);
        bytes_written = size;
    } else {
        if (fd < 2 || fd >= MAX_FD) {
            exit(-1);
        }
        struct file *file = thread_current()->fdt[fd];
        if (file == NULL) {
            exit(-1);
        }
        lock_acquire(&filesys_lock);
        bytes_written = file_write(file, kbuffer, size);
        lock_release(&filesys_lock);
    }
    free(kbuffer);
    return bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position. */
static void seek(int fd, unsigned position)
{
    // Judge if fd is leagal
    if (fd < 2 || fd >= MAX_FD)
        return;
    struct thread *curr = thread_current();
    struct file *file = curr->fdt[fd];
    if (file == NULL)
        return;
    lock_acquire(&filesys_lock);
    file_seek(file, position);
    lock_release(&filesys_lock);
}

/* Returns the position of the next byte to be read or written in open file fd,
 * expressed in bytes from the beginning of the file. */
static unsigned tell(int fd)
{
    // Judge if fd is leagal
    if (fd < 2 || fd >= MAX_FD)
        return -1;
    struct thread *curr = thread_current();
    struct file *file = curr->fdt[fd];
    if (file == NULL)
        return -1;
    lock_acquire(&filesys_lock);
    unsigned position = file_tell(file);
    lock_release(&filesys_lock);
    return position;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes
   all its open file descriptors, as if by calling this function for each one.
 */
void close(int fd)
{
    // Judge if fd is leagal
    if (fd < 2 || fd >= MAX_FD)
        return;
    struct thread *curr = thread_current();
    struct file *file = curr->fdt[fd];
    if (file == NULL)
        return;
    lock_acquire(&filesys_lock);
    file_close(file);
    lock_release(&filesys_lock);
    curr->fdt[fd] = NULL;
}

/* Runs the executable whose name is given in cmd_line, passing any given
   arguments, and returns the new process's program id (pid). Must return pid
   -1, which otherwise should not be a valid pid, if the program cannot load or
   run for any reason. Thus, the parent process cannot return from the exec
   until it knows whether the child process successfully loaded its executable.
   You must use appropriate synchronization to ensure this. */
static int exec(const char *cmd_line)
{
    void *ptr = palloc_get_page(0);
    if (ptr == NULL) {
        return -1;
    }
    bool success = copy_from_user_str((void *)cmd_line, ptr);
    if (!success) {
        palloc_free_page(ptr);
        exit(-1);
    }
    tid_t tid = process_execute((char *)ptr);
    palloc_free_page(ptr);
    return tid;
}

/* Creates a new file called file initially initial_size bytes in size. Returns
   true if successful, false otherwise. Creating a new file does not open it:
   opening the new file is a separate operation which would require a open
   system call. */
static bool create(const char *file, unsigned initial_size)
{
    void *ptr = palloc_get_page(0);
    if (ptr == NULL) {
        exit(-1);
    }
    bool success = copy_from_user_str((void *)file, ptr);
    if (!success) {
        palloc_free_page(ptr);
        exit(-1);
    }
    lock_acquire(&filesys_lock);
    success = filesys_create((char *)ptr, initial_size);
    lock_release(&filesys_lock);
    palloc_free_page(ptr);
    return success;
}

/* Deletes the file called file. Returns true if successful, false otherwise.
   A file may be removed regardless of whether it is open or closed, and
   removing an open file does not close it. See Removing an Open File, for
   details. */
static bool remove(const char *file)
{
    void *ptr = palloc_get_page(0);
    if (ptr == NULL) {
        exit(-1);
    }
    bool success = copy_from_user_str((void *)file, ptr);
    if (!success) {
        palloc_free_page(ptr);
        exit(-1);
    }
    lock_acquire(&filesys_lock);
    success = filesys_remove((char *)ptr);
    lock_release(&filesys_lock);
    palloc_free_page(ptr);
    return success;
}

/* Opens the file called file. Returns a nonnegative integer handle called a
   "file descriptor" (fd), or -1 if the file could not be opened. */
static int open(const char *file)
{
    void *ptr = palloc_get_page(0);
    if (ptr == NULL) {
        exit(-1);
    }
    bool success = copy_from_user_str((void *)file, ptr);
    if (!success) {
        palloc_free_page(ptr);
        exit(-1);
    }

    lock_acquire(&filesys_lock);
    struct file *f = filesys_open((char *)ptr);
    lock_release(&filesys_lock);
    if (f == NULL) {
        palloc_free_page(ptr);
        return -1;
    } else {
        struct thread *curr = thread_current();
        if (curr->next_fd == -1) {
            printf("ERROR: File descriptor table is full.\n");
            return -1;
        }
        curr->fdt[curr->next_fd] = f;
        int fd = curr->next_fd;
        curr->next_fd = find_next_fd();
        palloc_free_page(ptr);
        return fd;
    }
}

/* Helper function to find the next available file descriptor. */
static int find_next_fd(void)
{
    struct thread *curr = thread_current();
    int i;
    for (i = 2; i < MAX_FD; i++) {
        if (curr->fdt[i] == NULL)
            return i;
    }
    return -1;
}

/* Returns the size, in bytes, of the file open as fd. */
static int filesize(int fd)
{
    // Judge if fd is leagal
    if (fd < 2 || fd >= MAX_FD)
        return -1;
    lock_acquire(&filesys_lock);
    int size = file_length(thread_current()->fdt[fd]);
    lock_release(&filesys_lock);
    return size;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of
   bytes actually read (0 at end of file), or -1 if the file could not be read
   (due to a condition other than end of file). Fd 0 reads from the keyboard
   using input_getc(). */
static int read(int fd, void *buffer, unsigned size)
{
    if(size == 0) {
        return 0;
    }

    void *kbuff = malloc(size);
    if (kbuff == NULL) {
        exit(-1);
    }

    unsigned bytes_read = 0;
    bool success = false;
    if (fd == 0) {
        while (bytes_read < size) {
            *((char *)kbuff + bytes_read) = input_getc();
            bytes_read++;
        }
    } else {
        if (fd < 2 || fd >= MAX_FD) {
            exit(-1);
        }
        struct file *file = thread_current()->fdt[fd];
        if (file == NULL) {
            exit(-1);
        }
        lock_acquire(&filesys_lock);
        bytes_read = file_read(file, kbuff, size);
        lock_release(&filesys_lock);
    }
    success = copy_to_user(kbuff, buffer, bytes_read);
    if(!success) {
        free(kbuff);
        exit(-1);
    }
    free(kbuff);
    return bytes_read;
}

/**
 * Validates the pointer range of a given virtual address and size.
 * If any of the memory addresses in the range is invalid, the program exits
 * with status -1.
 *
 * @param vaddr The virtual address to start validating from.
 * @param size The size of the memory range to validate.
 */
static void validate_ptr_range(const void *vaddr, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (get_user((uint8_t *)vaddr + i) == -1)
            exit(-1);
    }
}

/**
 * Validates a string by checking if it is a null-terminated string and has a
 * length less than or equal to MAX_STR_LEN. If the string is not valid, the
 * function exits with a status of -1.
 *
 * @param str The string to be validated.
 */
static void validate_string(const char *str)
{
#define MAX_STR_LEN 100
    int count = 0;
    char c;
    do {
        c = get_user((uint8_t *)str + count) & 0xff;
        if (c == -1)
            exit(-1);
        count++;
    } while (c != '\0' && count < MAX_STR_LEN);
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

static bool copy_from_user(const void *src, void *des, size_t bytes)
{
    uint8_t *src_ptr = (uint8_t *)src;
    uint8_t *des_ptr = (uint8_t *)des;
    for (size_t i = 0; i < bytes; i++) {
        int byte = get_user(src_ptr + i);
        if (byte == -1)
            return false;
        des_ptr[i] = byte;
    }
    return true;
}

static bool copy_to_user(void *src, void *des, size_t bytes)
{
    uint8_t *src_ptr = (uint8_t *)src;
    uint8_t *des_ptr = (uint8_t *)des;
    for (size_t i = 0; i < bytes; i++) {
        if (!put_user(des_ptr + i, src_ptr[i]))
            return false;
    }
    return true;
}

static void copy_from_user_exits(void *src, void *des, size_t bytes)
{
    if (!copy_from_user(src, des, bytes))
        exit(-1);
}

static void copy_to_user_exits(void *src, void *des, size_t bytes)
{
    if (!copy_to_user(src, des, bytes))
        exit(-1);
}

static bool copy_from_user_str(void *src, void *des)
{
    uint8_t *src_ptr = (uint8_t *)src;
    uint8_t *des_ptr = (uint8_t *)des;
    int byte;
    do {
        byte = get_user(src_ptr);
        if (byte == -1)
            return false;
        *des_ptr = byte;
        src_ptr++;
        des_ptr++;
    } while (byte != '\0');
    return true;
}