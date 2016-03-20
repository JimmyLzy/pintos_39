#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "threads/thread.h"

typedef int mapid_t;

struct vm_mfile
  {
    mapid_t mapid;
    int fd;
    struct list_elem list_elem;
    void *start_addr;
    void *end_addr;
  };

void vm_add_mfile(mapid_t mapid, int fd, void *start_addr, void *end_addr);
struct vm_mfile* vm_find_mfile(mapid_t mapid);
bool vm_delete_mfile(mapid_t mapid);

#endif /* vm/mmap.h */
