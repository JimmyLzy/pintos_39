#include "threads/palloc.h"
#include <list.h>
#include "threads/malloc.h"
#include "vm/frame.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include "filesys/file.h"

struct list frame_list;   /*frame table used to store all the frames and additional information*/
struct lock frame_lock;   /*lock used to prevent race condition when access frame_list*/

/*Initialise frame list and frame_lock*/
void frame_init() {
    list_init(&frame_list);
    lock_init(&frame_lock);
}

/*Find a frame using palloc_get_page() and put into frame_list*/
void *frame_get_page(enum palloc_flags flags, struct sup_page *upage) {
    void *kpage = palloc_get_page(flags);
    struct frame *f = (struct frame *) malloc(sizeof(struct frame));
    if (kpage) {
        f->frame = kpage;
    } else {
        f->frame = frame_eviction(flags);
    }
    f->page = upage;
    f->thread = thread_current();
    lock_acquire(&frame_lock);
    list_push_back(&frame_list, &f->frame_elem);
    lock_release(&frame_lock);
    return kpage;
}

/*Free a frame by using palloc_free_page() and remove the frame from frame_list*/
void frame_free_page(void *kpage) {
    struct list_elem *e;
    struct frame *f;
    lock_acquire(&frame_lock);
    if (!list_empty(&frame_list)) {
        for (e = list_begin(&frame_list); e != list_end(&frame_list); e =
                list_next(e)) {
            f = list_entry(e, struct frame, frame_elem);
            if (f->frame == kpage) {
                list_remove(e);
                palloc_free_page(kpage);
                lock_release(&frame_lock);
                return;
            }
        }
    }
    lock_release(&frame_lock);
    return;
}

/*Evict a frame when no frame is available by using swap table*/
void *frame_eviction(enum palloc_flags flags) {
    lock_acquire(&frame_lock);
    struct frame *f = list_entry(list_begin(&frame_list), struct frame,
            frame_elem);

    if (f->page->type == MMAP) {
        lock_acquire(&filesys_lock);
        file_write_at(&(f->page)->file, f->frame, f->page->read_bytes, f->page->offset);
        lock_release(&filesys_lock);
    } else {
        f->page->type = SWAP;
        f->page->pos = swap_write(f->frame);
    }
    f->page->loaded = false;
    frame_free_page(f->frame);
    lock_release(&frame_lock);
    return palloc_get_page(flags);
}

