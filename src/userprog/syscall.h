#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "vm/mmap.h"

struct lock filesys_lock; /* File system lock. */

typedef int pid_t;

/* code-segment lower bound */
#define CODE_SEGMENT_BOTTON ((void *) 0x08048000)

void syscall_init (void);

void halt(void);

void exit(int status);

pid_t exec(const char *cmd_line);

int wait(pid_t pid);

int read(int fd, const void *buffer, unsigned size);

int write(int fd, const void *buffer, unsigned size);

bool create(const char *file_path, unsigned initial_size);

bool remove(const char *file_path);

int open(const char *file_path);

void close(int fd);

struct file *find_file(int fd);

struct file_handler *find_file_handler(int fd);

unsigned tell(int fd);

int filesize(int fd);

void check_ptr_in_user_memory(const void *vaddr);

int syscall_get_kernel_ptr(const void *vaddr);

mapid_t mmap(int fd, void *addr);

void munmap(mapid_t mapping);

struct sup_page* check_valid_ptr(const void *vaddr, void* esp);

#endif /* userprog/syscall.h */
