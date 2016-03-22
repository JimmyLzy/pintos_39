#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

struct sup_page* init_sup_page(struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    struct sup_page *p = (struct sup_page *) malloc(sizeof(struct sup_page));
    if (p == NULL) {
        return NULL;
    }
    p->type = FILE;
    p->writable = writable;
    p->upage = upage;
    p->file = *file;
    p->offset = ofs;
    p->read_bytes = read_bytes;
    p->zero_bytes = zero_bytes;
    p->loaded = false;
    lock_acquire(&page_lock);
    list_push_back(&thread_current()->sup_page_table, &p->page_elem);
    lock_release(&page_lock);
    return p;
}

struct sup_page* get_sup_page(void *addr) {
    struct sup_page *spage;
    void *closest_page = pg_round_down(addr);

   // enum intr_level old_level = intr_disable();
    lock_acquire(&page_lock);
    struct list_elem *e;
    struct thread *cur = thread_current();

    if (!list_empty(&cur->sup_page_table)) {
        for (e = list_begin(&cur->sup_page_table);
                e != list_end(&cur->sup_page_table); e = list_next(e)) {
            spage = list_entry(e, struct sup_page, page_elem);
            if (spage->upage == closest_page) {
                lock_release(&page_lock);
                //intr_set_level (old_level);
                return spage;
            }
        }
    }
    lock_release(&page_lock);
   // intr_set_level(old_level);
    return NULL;
}

bool load_file(struct sup_page *sup_page) {
    /* Get a page of memory. */
    uint8_t *kpage;
    if (sup_page->read_bytes == 0) {
        kpage = frame_get_page(PAL_USER | PAL_ZERO, sup_page);
    } else {
        kpage = frame_get_page(PAL_USER, sup_page);
    }
    if (kpage == NULL) {
        return false;
    }

//    enum intr_level old_level = intr_disable ();

    /* Load this page. */
    if (sup_page->read_bytes > 0) {
        int read_bytes = file_read_at(&sup_page->file,  kpage,
               sup_page->read_bytes, sup_page->offset);

        if (read_bytes != (int) sup_page->read_bytes) {
            frame_free_page(kpage);
            return false;
        }
        memset(kpage + sup_page->read_bytes, 0, sup_page->zero_bytes);
    }

    /* Add the page to the process's address space. */
    if (!install_page(sup_page->upage, kpage, sup_page->writable)) {
        frame_free_page(kpage);
        return false;
    }

    sup_page->loaded = true;
//    intr_set_level (old_level);
    return true;
}


bool load_swap(struct sup_page *sup_page) {
    void *f = frame_get_page(PAL_USER, sup_page);
    if (!install_page(sup_page->upage, f, sup_page->writable)) {
        frame_free_page(f);
        return false;
    }
    swap_read(f, sup_page->pos);
    sup_page->loaded = true;
    return true;
}

bool stack_growth(void *addr) {
    void *upage = pg_round_down(addr);

    if ((size_t) (PHYS_BASE - upage <= STACK_LIMIT)) {
        struct sup_page *p = (struct sup_page *) malloc(
                sizeof(struct sup_page));
        p->upage = upage;
        p->writable = true;
        p->loaded = true;
        p->type = SWAP;

        uint8_t *kpage = frame_get_page(PAL_USER | PAL_ZERO, p);
        if (!install_page(upage, kpage, p->writable)) {
            frame_free_page(kpage);
            PANIC("install page failed\n");
            return false;
        }
        list_push_back(&thread_current()->sup_page_table, &p->page_elem);
        return true;
    } else {
        return false;
    }
}

void free_sup_page(struct sup_page *spage) {
    list_remove(&spage->page_elem);
    free(spage);
}



