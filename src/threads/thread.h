#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "vm/mmap.h"

/* States in a thread's life cycle. */
enum thread_status {
    THREAD_RUNNING, /* Running thread. */
    THREAD_READY, /* Not running but ready to run. */
    THREAD_BLOCKED, /* Waiting for an event to trigger. */
    THREAD_DYING /* About to be destroyed. */
};

/* Thread identifier type.
 You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

 Each thread structure is stored in its own 4 kB page.  The
 thread structure itself sits at the very bottom of the page
 (at offset 0).  The rest of the page is reserved for the
 thread's kernel stack, which grows downward from the top of
 the page (at offset 4 kB).  Here's an illustration:

 4 kB +---------------------------------+
 |          kernel stack           |
 |                |                |
 |                |                |
 |                V                |
 |         grows downward          |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 +---------------------------------+
 |              magic              |
 |                :                |
 |                :                |
 |               name              |
 |              status             |
 0 kB +---------------------------------+

 The upshot of this is twofold:

 1. First, `struct thread' must not be allowed to grow too
 big.  If it does, then there will not be enough room for
 the kernel stack.  Our base `struct thread' is only a
 few bytes in size.  It probably should stay well under 1
 kB.

 2. Second, kernel stacks must not be allowed to grow too
 large.  If a stack overflows, it will corrupt the thread
 state.  Thus, kernel functions should not allocate large
 structures or arrays as non-static local variables.  Use
 dynamic allocation with malloc() or palloc_get_page()
 instead.

 The first symptom of either of these problems will probably be
 an assertion failure in thread_current(), which checks that
 the `magic' member of the running thread's `struct thread' is
 set to THREAD_MAGIC.  Stack overflow will normally change this
 value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 the run queue (thread.c), or it can be an element in a
 semaphore wait list (synch.c).  It can be used these two ways
 only because they are mutually exclusive: only a thread in the
 ready state is on the run queue, whereas only a thread in the
 blocked state is on a semaphore wait list. */



struct thread {
    /* Owned by thread.c. */
    tid_t tid;                      /* Thread identifier. */
    enum thread_status status;      /* Thread state. */
    char name[16];                  /* Name (for debugging purposes). */
    uint8_t *stack;                 /* Saved stack pointer. */
    int priority;                   /* Priority. */
    int donated_priority;           /* Donated priority. */
    struct list_elem allelem;       /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;          /* List element. */

    int sleep_time;                 /* Sleeping time of the thread*/
    struct semaphore *semaphore;    /* Semaphore used to control the sleep of a thread*/
    struct list_elem sleep_elem;    /* List element for sleep_thread_list*/

    struct lock *waiting_for_lock;  /* The lock that this thread is waiting for. */
    struct list donation_locks;     /* List of locks whose holder is this thread */

    int nice;                       /* Nice.*/
    int32_t recent_cpu;             /* Fixed-Point representation of Recent_cpu */

/* Owned by userprog/process.c. */
    uint32_t *pagedir;              /* Page directory. */
    int return_status;              /* Return status*/
    struct thread *parent;          /* Parent thread*/

    struct semaphore *exit_sema;    /* Used to control the exit of semaphore*/

    struct list child_list;         /* List to store child threads*/
    struct list_elem child_list_elem;/*child list elem*/
    bool is_waiting;                /* Bo*/
    struct list file_handler_list;  /* A list to store file handlers. */
    int fd;                         /* Accumulate fd and used to track the 
                                       current number of files opened. 
                                    */

    struct list sup_page_table;
    int accu_mapid;
    struct list vm_mfiles;

    /* Owned by thread.c. */
    unsigned magic; /* Detects stack overflow. */
};

/* File handler used to store the file descriptor
   and the corresponding opened file by the thread.
*/

struct file_handler {
    int fd; /* File descriptor. */
    struct file *file; /* Pointer to the file. */
    struct list_elem elem;
};

/* If false (default), use round-robin scheduler.
 If true, use multi-level feedback queue scheduler.
 Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);

void push_to_sleep_thread_list(struct list_elem *);
void wake_threads(void);
bool thread_compare(const struct list_elem *a, const struct list_elem *b,
        void *aux);
bool priority_compare(const struct list_elem *a, const struct list_elem *b,
        void *aux);

void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);
struct thread* get_child_thread(tid_t child_tid);
void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread *t, void *aux);
void thread_foreach(thread_action_func *, void *);

void thread_yield_safe(void);
int thread_get_priority(void);
void thread_set_priority(int);
void thread_calc_priority(struct thread *, void *);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
void thread_calc_recent_cpu(struct thread *, void *);
int thread_get_load_avg(void);
void thread_calc_load_avg(void);
void update_BSD_variables(void);

bool mfile_compare(const struct list_elem *first_, const struct list_elem *second_,
                   void *aux UNUSED);

#endif /* threads/thread.h */
