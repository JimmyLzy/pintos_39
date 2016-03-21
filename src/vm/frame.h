#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "vm/page.h"

void frame_init();
void *frame_get_page(enum palloc_flags flags, struct sup_page *upage);
void frame_free_page (void *kpage);
void *frame_eviction(enum palloc_flags flags);



struct frame {
    void *frame;
    struct sup_page *page;
    struct thread* thread;
    struct list_elem frame_elem;

};






















#endif
