#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include <bitmap.h>

#define PAGE_BLOCKS (PGSIZE / BLOCK_SECTOR_SIZE)
#define BITMAP_SIZE (block_size(block) / PAGE_BLOCKS)

struct block *block;

struct bitmap *bitmap;

void init_swap(void) {
    block = block_get_role(BLOCK_SWAP);
    bitmap = bitmap_create(BITMAP_SIZE);
    bitmap_set_all(bitmap, 0);
}

size_t swap_write(void *frame) {
    size_t pos = bitmap_scan_and_flip(bitmap, 0, 1, 0);
    size_t i;
    for (i = 0; i < PAGE_BLOCKS; i++) {
        block_write(bitmap, pos * PAGE_BLOCKS + i,
                (uint8_t *) frame + i * (BLOCK_SECTOR_SIZE));
    }
    return pos;
}

void swap_read(void *frame, size_t pos) {
    bitmap_flip(bitmap, pos);
    size_t i;
    for (i = 0; i < PAGE_BLOCKS; i++) {
        block_read(bitmap, pos * PAGE_BLOCKS + i,
                (uint8_t *) frame + i * (BLOCK_SECTOR_SIZE));
    }
}
