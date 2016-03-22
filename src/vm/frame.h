#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "vm/page.h"

void frame_init();
void *frame_get_page(enum palloc_flags flags, struct sup_page *upage);
void frame_free_page (void *kpage);
void *frame_eviction(enum palloc_flags flags);

struct frame {
    void *frame;                   /*The frame being obtained*/
    struct sup_page *page;         /*The sup_page in the frame*/
    struct thread* thread;         /*The process belong to this frame*/
    struct list_elem frame_elem;   /*List elem used to access the frame_list*/

};

#endif
