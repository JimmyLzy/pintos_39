#include "threads/palloc.h"
#include <list.h>
#include "threads/malloc.h"
#include "vm/frame.h"
#include "threads/interrupt.h"


struct list frame_list;

void frame_init() {
    list_init(&frame_list);
}

void *frame_get_page(enum palloc_flags flags, struct sup_page *upage) {
    void *kpage = palloc_get_page(flags);
    if (kpage) {
        struct frame *f = (struct frame *) malloc(sizeof(struct frame));
        f->frame = kpage;
        f->page = upage;
        f->thread = thread_current();
        enum intr_level old_level = intr_disable();
        list_push_back(&frame_list, &f->frame_elem);
        intr_set_level(old_level);
    } else {
        PANIC("Run out of page!");
    }
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

