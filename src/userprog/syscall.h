#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "lib/user/syscall.h"

void syscall_init (void);

void halt(void);

void exit(int status);

pid_t exec(const char *cmd_line);

int wait(pid_t pid);

int write(int fd, const void *buffer, unsigned size);

bool create (const char *file_path, unsigned initial_size);

bool remove (const char *file_path);

int open (const char *file_path);

#endif /* userprog/syscall.h */
