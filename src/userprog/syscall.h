#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>

typedef int pid_t;

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
#endif /* userprog/syscall.h */
