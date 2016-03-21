#include "devices/block.h"
#include "threads/vaddr.h"
#include <bitmap.h>

void swap_read(void *frame, size_t pos);

size_t swap_write(void *frame);

void init_swap(void);
