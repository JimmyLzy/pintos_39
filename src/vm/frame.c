#include "threads/palloc.h"
#include <list.h>
#include "threads/malloc.h"
#include "vm/frame.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"

struct list frame_list;

void frame_init() {
    list_init(&frame_list);
}

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
    enum intr_level old_level = intr_disable();
    list_push_back(&frame_list, &f->frame_elem);
    intr_set_level(old_level);
    return kpage;
}

void frame_free_page(void *kpage) {
    struct list_elem *e;
    struct frame *f;
    enum intr_level old_level = intr_disable();
    if (!list_empty(&frame_list)) {
        for (e = list_begin(&frame_list); e != list_end(&frame_list); e =
                list_next(e)) {
            f = list_entry(e, struct frame, frame_elem);
            if (f->frame == kpage) {
                list_remove(e);
                palloc_free_page(kpage);
                intr_set_level(old_level);
                return;
            }
        }
    }
    intr_set_level(old_level);
    return;
}

void *frame_eviction(enum palloc_flags flags) {
    struct frame *f = list_entry(list_begin(&frame_list), struct frame,
            frame_elem);
    if (f->page->type == MMAP) {
        PANIC("MMAP\n");
    } else {
        f->page->type = SWAP;
        f->page->pos = swap_write(f->frame);
    }
    f->page->loaded = false;
    frame_free_page(f->frame);
    return palloc_get_page(flags);
}

