#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/off_t.h"
#include "filesys/file.h"

#define FILE 0
#define SWAP 1
#define MMAP 2
#define STACK_LIMIT 8388608

struct sup_page {
    int type;
    bool writable;
    void *upage;
    struct file file;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    struct list_elem page_elem;
    size_t pos;
    bool loaded;
};

struct sup_page* init_sup_page(struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes, bool writable);

struct sup_page* get_sup_page(void *addr);

bool stack_growth(void *upage);

void free_sup_page(struct sup_page *spage);

#endif
