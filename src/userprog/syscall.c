#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdbool.h>

#include "filesys/filesys.h"
#include "threads/synch.h"

//number of system call types
#define SYSCALL_NUM 13
//maximum number of arguments of system calls
#define MAX_ARGS_NUM 3
//maximum buffer size per putbuf() operation
#define MAX_PUTBUF_SIZE 512

//file descriptor constant
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

/* code-segment lower bound */
#define CODE_SEGMENT_BOTTON ((void *) 0x08048000)

static int syscall_args_num[SYSCALL_NUM];

static void syscall_handler(struct intr_frame *);

static void syscall_handler(struct intr_frame *f);

static int* syscall_get_args(struct intr_frame *f, int syscall_num);

static struct lock filesys_lock; /* File system lock. */

void syscall_init(void) {

    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

    lock_init(&filesys_lock);

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

    check_ptr_in_user_memory((const void *) uaddr);

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
        args[0] = syscall_get_kernel_ptr((const char *) args[0]);
        f->eax = exec((const char*)args[0]);
        break;
    case SYS_WAIT:
        f->eax = wait(args[0]);
        break;
    case SYS_CREATE:
        args[0] = syscall_get_kernel_ptr((const char *) args[0]);
        f->eax = create((const char *)args[0], args[1]);
        break;
    case SYS_REMOVE:
        f->eax = remove((const char *) args[0]);
        break;
    case SYS_OPEN:
        args[0] = syscall_get_kernel_ptr((const char *) args[0]);
        f->eax = open((const char *)args[0]);
        break;
    case SYS_FILESIZE:
        f->eax = filesize(args[0]);
        break;
    case SYS_READ:
        args[1] = syscall_get_kernel_ptr((const char *) args[1]);
        f->eax = read(args[0], (void *)args[1], args[2]);
        break;
    case SYS_WRITE:
        args[1] = syscall_get_kernel_ptr((const char *) args[1]);
        f->eax = write((int)args[0], (const void *)args[1], (unsigned)args[2]);
        break;
    case SYS_SEEK:
        f->eax = seek((int)args[0], (unsigned)args[1]);
        break;
    case SYS_TELL:
        f->eax = tell((const char *) args[0]);
        break;
    case SYS_CLOSE:
        close(args[0]);
        break;
    default:
        break;
    }

    free(args);
}

int syscall_get_kernel_ptr(const void *vaddr) {
    check_ptr_in_user_memory(vaddr);
    void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
    if (ptr == NULL) {
        exit(-1);
    }
    return (int) ptr;
}

void check_ptr_in_user_memory(const void *vaddr) {
    if (!is_user_vaddr(vaddr) || vaddr < CODE_SEGMENT_BOTTON) {
        exit(-1);
    }
}

static int* syscall_get_args(struct intr_frame *f, int syscall_num) {
    int *args = (int*) malloc(MAX_ARGS_NUM);
    if (args == NULL) {
        PANIC ("Allocation of memory of arguments fails.");
    }    
    int args_num = syscall_args_num[syscall_num];
    int i;
    int *ptr;
    for (i = 0; i < args_num; i++) {
        ptr = (int *) f->esp + i + 1;
        check_ptr_in_user_memory((const void *) ptr);
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
    if (t->parent != NULL) {
        t->parent->return_status = status;
    }

    /*Close all the files and free all the file handler*/
    int fd = t->fd;
    while(fd > 1) {
        close(fd);
        fd--;
    }

    thread_exit();
}

pid_t exec(const char *cmd_line) {

    return process_execute(cmd_line);
}

int wait(pid_t pid) {
//    struct thread* child_thread = get_child_thread(pid);
//    if (child_thread != NULL) {
//        int status = child_thread->return_status;
//        process_wait(pid);
//        return thread_current()->return_status;
//    }
    //struct thread* child_thread = get_child_thread(pid);
    return process_wait(pid);


//    return child_thread->return_status;
}

/* Create a file with the given file path and initial size
   by calling the filesys_create() method. Return true upon
   success. */
bool create (const char *file_path, unsigned initial_size) {

    if(file_path == NULL) {
      exit(-1);
    }

    lock_acquire(&filesys_lock);
    bool success = filesys_create(file_path, initial_size);
    lock_release(&filesys_lock);

    return success;

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

    // lock_acquire(&filesys_lock);
    struct file *file = find_file(fd);

    if (file == NULL) {
        // lock_release(&filesys_lock);
        return -1;
    }
    int read_size = file_read(file, buffer, size);
    // lock_release(&filesys_lock);
    return read_size;
}


int write(int fd, const void *buffer, unsigned size) {

    if (fd == 0) {
        return -1;
    }
    if (fd == STDOUT_FILENO) {
        int written_size = 0;
        if (size <= MAX_PUTBUF_SIZE) {
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
        lock_acquire(&filesys_lock);

        struct file* file = find_file(fd);

        if (file == NULL) {
            lock_release(&filesys_lock);
            exit(-1);
        }

        int bytes = file_write(file, buffer, size);
//        int written_size = 0;
//        if (size < MAX_PUTBUF_SIZE) {
//            printf("small file\n");
//            file_write(file, buffer, size);
//            lock_release(&filesys_lock);
//            return size;
//        } else {
//            printf("big file\n");
//            while (size > MAX_PUTBUF_SIZE) {
//                file_write(file, buffer + written_size,
//                        MAX_PUTBUF_SIZE);
//                size -= MAX_PUTBUF_SIZE;
//                written_size += MAX_PUTBUF_SIZE;
//            }
//            file_write(file, buffer + written_size, size);
//            written_size += size;
//        }

        lock_release(&filesys_lock);

        return bytes;
    }
}

/* Remove the file with the given file path by calling the
   filesys_remove() method. Return true upon success. */
bool remove (const char *file_path) {

    if(file_path == NULL) {
      exit(-1);
    }

    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file_path);
    lock_release(&filesys_lock);

    return success;

}

/* Open the file with the given file path by calling the
   filesys_open() method. Store the opened file and its 
   file descripter to a file handler in heap and push the 
   handler to the back of file handler list. */
int open (const char *file_path) {

    if(file_path == NULL) {
      exit(-1);
    }

    lock_acquire(&filesys_lock);

    struct file *file = filesys_open(file_path);

    int fd = -1;
    if(file != NULL) {
        struct thread *t = thread_current();
        struct file_handler *fh_p = malloc(sizeof(struct file_handler));
        if (fh_p == NULL) {
            PANIC ("Allocation of memory of file handler fails.");
        }
        t->fd++;
        fh_p->fd = t->fd;
        fh_p->file = file;
        list_push_back(&t->file_handler_list, &fh_p->elem);
        fd = t->fd;
    }

    lock_release(&filesys_lock);
    return fd;
}

/* Return the file size of a file with the given file descripter. */
int filesize(int fd) {

    struct file *file = find_file(fd);
    if (file != NULL) {
        return file_length(file);
    }
    return -1;

}

/* Find the file with given file descripter in the file handler list
   by calling find_file_handler(). Return the file on success
   , otherwise return null.
 */
struct file *find_file(int fd) {

    struct file_handler *file_handler = find_file_handler(fd);

    if(file_handler != NULL) {
        return file_handler->file;
    }
    exit(-1);

}

/* Loop through the file_handler_list of the current thread and find
   the file handler by comparing the file descriptor. Return the file
   handler on success, otherwise return null.
 */
struct file_handler *find_file_handler(int fd) {

    struct list_elem *e;
    struct thread *cur = thread_current();
    struct file_handler *fh;


    if(!list_empty(&cur->file_handler_list)) {
      for (e = list_begin(&cur->file_handler_list); e != list_end(&cur->file_handler_list);
              e = list_next(e)) {
          fh = list_entry(e, struct file_handler, elem);
          if (fh->fd == fd) {
              return fh;
          }
       }
    }

    return NULL;

}

/*Find the file using file descriptor. Close the file by calling file_close()
  and remove the file handler from the list when successfully finding the file.
  Also free the file handler on success.
*/
void close (int fd) {

    lock_acquire(&filesys_lock);
    struct file_handler *file_handler = find_file_handler(fd);
    if(file_handler != NULL) {
      struct file *file = file_handler->file;
      if(file != NULL) {
         file_close(file);
         list_remove(&file_handler->elem);
         free(file_handler);
      }
    }

    lock_release(&filesys_lock);

}

/*Find the file using file descriptor. Return the position of the next byte to
  be read or written of the file by calling file_tell() on success. Otherwise,
  exit the process with -1.
*/

unsigned tell (int fd) {

    lock_acquire(&filesys_lock);

    struct file *file = find_file(fd);
    if (file != NULL) {

        lock_release(&filesys_lock);
        return file_tell(file);
    }
    lock_release(&filesys_lock);
    exit(-1);

}

/*Find the file using file descriptor. Changes the next byte to be read or written 
  in the file to position by calling file_seek(), expressed in bytes from the 
  beginning of the file on success. Otherwise, exit the process with -1; 
*/
void seek (int fd, unsigned position) {

    lock_acquire(&filesys_lock);

    struct file *file = find_file(fd);
    if (file != NULL) {

        lock_release(&filesys_lock);
        return file_seek(file, position);
    }
    lock_release(&filesys_lock);
    exit(-1);

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
