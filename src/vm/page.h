#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/off_t.h"
#include "filesys/file.h"

#define FILE 0                            /*Indicates file sup_page*/
#define SWAP 1                            /*Indicates swap sup_page*/
#define MMAP 2                            /*Indicates mmap sup_page*/
#define STACK_LIMIT 8388608               /*Indicates 8MB maximum stack size*/

struct lock page_lock;                    /*The page_lock is used to prevent race condition when access sup_page_table*/

struct sup_page {
    int type;                             /*The type of the sup_page, FILE, SWAP or MMAP*/
    bool writable;                        /*Indicates whether this is a read only or read/write sup_page*/
    void *upage;                          /*The page address*/
    void *kpage;                          /*The frame allocated for this sup_page*/
    struct file file;                     /*The file for the page*/
    size_t offset;                        /*The offset of the file*/
    size_t read_bytes;                    /*The number of bytes need to be read*/
    size_t zero_bytes;                    /*The number of zero bytes at the end of the file*/
    struct list_elem page_elem;           /*list elem used to access sup_page_table*/
    size_t pos;                           /*The position that the page is written into swap table*/
    bool loaded;                          /*Bool that indicates if the page is loaded*/
};

struct sup_page* init_sup_page(struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes, bool writable);

struct sup_page* get_sup_page(void *addr);

bool stack_growth(void *upage);

void free_sup_page(struct sup_page *spage);

#endif
