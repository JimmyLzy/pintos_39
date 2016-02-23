#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdbool.h>

//number of system call types
#define SYSCALL_NUM 13
//maximum number of arguments of system calls
#define MAX_ARGS_NUM 4

static int syscall_args_num[SYSCALL_NUM];

static void syscall_handler(struct intr_frame *);

static int get_user(const uint8_t *uaddr);

static bool put_user(uint8_t *udst, uint8_t byte);

static void syscall_handler(struct intr_frame *f);

static int* syscall_get_args(void *uaddr, int syscall_num);


void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

	syscall_args_num[SYS_HALT] = 0;
	syscall_args_num[SYS_EXIT] = 1;
	syscall_args_num[SYS_EXEC] = 1;
	syscall_args_num[SYS_WAIT] = 1;
	syscall_args_num[SYS_CREATE] = 2;
	syscall_args_num[SYS_REMOVE] = 1;
	syscall_args_num[SYS_OPEN] = 1;
	syscall_args_num[SYS_FILESIZE] = 1;
	syscall_args_num[SYS_READ] = 3;
	syscall_args_num[SYS_WRITE] = 3;
	syscall_args_num[SYS_SEEK] = 2;
	syscall_args_num[SYS_TELL] = 1;
	syscall_args_num[SYS_CLOSE] = 1;

}

/* Reads a byte at user virtual address UADDR.
 UADDR must be below PHYS_BASE.
 Returns the byte value if successful, -1 if a segfault
 occurred. */
static int get_user(const uint8_t *uaddr) {

	if (!is_user_vaddr((void*) uaddr)) {
		thread_exit();
	}
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

/* Writes BYTE to user address UDST.
 UDST must be below PHYS_BASE.
 Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {

	int error_code;
	asm ("movl $1f, %0; movb %b2, %1; 1:"
			: "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

static void syscall_handler(struct intr_frame *f) {

	struct thread *t = thread_current();
	void *uaddr = f->esp;
	int syscall_num = get_user(uaddr);
	if (syscall_num < SYS_HALT || syscall_num > SYS_MUNMAP) {
		thread_exit();
	}
	int *args = syscall_get_args(uaddr, syscall_num);
	switch (syscall_num) {

	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(args[1]);
		break;
	case SYS_EXEC:
		break;
	case SYS_WAIT:
		break;
	case SYS_CREATE:
		break;
	case SYS_REMOVE:
		break;
	case SYS_OPEN:
		break;
	case SYS_FILESIZE:
		break;
	case SYS_READ:
		break;
	case SYS_WRITE:
		write(args[1], args[2], args[3]);
		break;
	case SYS_SEEK:
	case SYS_TELL:
	case SYS_CLOSE:

	default:
		break;
	}
}

static int* syscall_get_args(void *uaddr, int syscall_num) {
	int *args = (int*) malloc(MAX_ARGS_NUM);
	int args_num = syscall_args_num[syscall_num];
	int i;
	for (i = 0; i < args_num; i++) {
		args[i] = get_user((int *) uaddr + i);
	}
	return args;
}

//========================syscalls=====================

void halt(void) {
	shutdown_power_off();
}

void exit(int status) {

	struct thread *t = thread_current();
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

pid_t exec(const char *cmd_line) {
	return -1;
}

int wait(pid_t pid) {
	return -1;
}

int write(int fd, const void *buffer, unsigned size) {

	if (fd == 1) {
		int written_size = 0;
		const int MAX_PUTBUF_SIZE = 256;
		if (size < MAX_PUTBUF_SIZE) {
			putbuf((char *) buffer, size);
		} else {
			while (size > MAX_PUTBUF_SIZE) {
				putbuf((char *) (buffer + written_size), MAX_PUTBUF_SIZE);
				size -= MAX_PUTBUF_SIZE;
				written_size += MAX_PUTBUF_SIZE;
			}
			putbuf((char *) (buffer + written_size), size);
			written_size += size;
		}
		return written_size;
	}

	return 0;

}

///* Tasks 2 and later. */
//SYS_HALT,                   /* Halt the operating system. */
//SYS_EXIT,                   /* Terminate this process. */
//SYS_EXEC,                   /* Start another process. */
//SYS_WAIT,                   /* Wait for a child process to die. */
//SYS_CREATE,                 /* Create a file. */
//SYS_REMOVE,                 /* Delete a file. */
//SYS_OPEN,                   /* Open a file. */
//SYS_FILESIZE,               /* Obtain a file's size. */
//SYS_READ,                   /* Read from a file. */
//SYS_WRITE,                  /* Write to a file. */
//SYS_SEEK,                   /* Change position in a file. */
//SYS_TELL,                   /* Report current position in a file. */
//SYS_CLOSE,                  /* Close a file. */
