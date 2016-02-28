#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdbool.h>

#include "filesys/filesys.h"

//number of system call types
#define SYSCALL_NUM 13
//maximum number of arguments of system calls
#define MAX_ARGS_NUM 3
//maximum buffer size per putbuf() operation
#define MAX_PUTBUF_SIZE 512

//file descriptor constant
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

static int syscall_args_num[SYSCALL_NUM];

static void syscall_handler(struct intr_frame *);

static void syscall_handler(struct intr_frame *f);

static int* syscall_get_args(struct intr_frame *f, int syscall_num);

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

static void syscall_handler(struct intr_frame *f) {

    struct thread *t = thread_current();
    void *uaddr = f-> esp;

    if (!is_user_vaddr((void*) uaddr)) {
        thread_exit();
    }

    int syscall_num = *(int *) pagedir_get_page(t -> pagedir, uaddr);

    if (syscall_num < SYS_HALT || syscall_num > SYS_MUNMAP) {
        thread_exit();
    }

    int *args = syscall_get_args(f, syscall_num);

    switch (syscall_num) {

    case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        exit(args[0]);
        break;
    case SYS_EXEC:
        f->eax = exec((const char*)args[0]);
        break;
    case SYS_WAIT:
        f->eax = wait(args[0]);
        break;
    case SYS_CREATE:
        f->eax = create((const char *)args[0], args[1]);
        break;
    case SYS_REMOVE:
        break;
    case SYS_OPEN:
        f->eax = open((const char *)args[0]);
        break;
    case SYS_FILESIZE:
        f->eax = filesize(args[0]);
        break;
    case SYS_READ:
        f->eax = read(args[0], (void *)args[1], args[2]);
        break;
    case SYS_WRITE:
        f->eax = write(args[0], (void *)args[1], args[2]);
        break;
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE:

    default:
        break;
    }
}

static int* syscall_get_args(struct intr_frame *f, int syscall_num) {
    int *args = (int*) malloc(MAX_ARGS_NUM);
    int args_num = syscall_args_num[syscall_num];
    int i;
    int *ptr;
    for (i = 0; i < args_num; i++) {
        ptr = (int *) f->esp + i + 1;
        args[i] = *ptr;
    }
    return args;
}


void halt(void) {
    shutdown_power_off();
}

void exit(int status) {

    struct thread *t = thread_current();
    printf("%s: exit(%d)\n", t->name, status);
    t->return_status = status;
    thread_exit();
}

pid_t exec(const char *cmd_line) {
    return process_execute(cmd_line);
}

int wait(pid_t pid) {
    return process_wait(pid);
}

bool create (const char *file_path, unsigned initial_size) {

    return filesys_create(file_path, initial_size);

}

int read(int fd, const void *buffer, unsigned size) {

    if (fd == STDIN_FILENO) {
        unsigned i;
        uint8_t *getc_buffer = (uint8_t *) buffer;
        for (i = 0; i < size; i++) {
            getc_buffer[i] = input_getc();
        }
        return size;
    }
    //lock_acuqire(&filesys_lock);


    struct file *file = find_file(fd);
    if (file == NULL) {
        //lock_release(&filesys_lock);
        return -1;
    }
    int read_size = file_read(file, buffer, size);
    return read_size;
}


int write(int fd, const void *buffer, unsigned size) {

    //printf("=====fd is %d, ====writing: %s\n", fd, (char *)buffer);

    if (fd == 1) {
        int written_size = 0;
        if (size < MAX_PUTBUF_SIZE) {
            putbuf((char *) buffer, size);
            return size;
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
    } else {
       // find_file(fd);

        //printf("found file\n");

//
//        int written_size = 0;
//        if (size < MAX_PUTBUF_SIZE) {
//            file_write(find_file(fd), buffer, size);
//            return size;
//        } else {
//
//
//            while (size > MAX_PUTBUF_SIZE) {
//                file_write(find_file(fd), buffer + written_size,
//                        MAX_PUTBUF_SIZE);
//                size -= MAX_PUTBUF_SIZE;
//                written_size += MAX_PUTBUF_SIZE;
//            }
//            file_write(find_file(fd), buffer + written_size, size);
//            written_size += size;
//        }
//        return written_size;
        return size;
    }

}

bool remove (const char *file_path) {

	return filesys_remove(file_path); 

}

int open (const char *file_path) {

    struct file *file = filesys_open(file_path);

    if(file != NULL) {
        struct thread *t = thread_current();
//        struct file_handler fh;
//        struct file_handler *fh_p = &fh;
        struct file_handler *fh_p = malloc(sizeof(struct file_handler));
        t->fd++;
        fh_p->fd = t->fd;
        fh_p->file = file;
        list_push_back(&t->file_handler_list, &fh_p->elem);
        return t->fd;
    }
    return -1;
}

int filesize(int fd) {

    struct file *file = find_file(fd);
    if (file != NULL) {
        return file_length(file);
    }
    return -1;
//    exit(-1);
}

struct file *find_file(int fd) {

    struct list_elem *e;
    struct thread *cur = thread_current();
    struct file_handler *fh;

    if (!list_empty(&cur->file_handler_list)) {
        for (e = list_begin(&cur->file_handler_list);
                e != list_end(&cur->file_handler_list); e = list_next(e)) {
            fh = list_entry(e, struct file_handler, elem);
            if (fh->fd == fd) {
                return fh->file;
            }
        }
    }
    return NULL;

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
