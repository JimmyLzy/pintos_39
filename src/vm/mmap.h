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

typedef int mapid_t;           /* Declare mapid_t type as int */

struct vm_mfile
  {
    mapid_t mapid;             /* The mapid related to the map */
    int fd;                    /*The file descriptor value of the file it map*/
    struct list_elem list_elem;/* Created for the list to store mfile */
    void *start_addr;          /* The start address of the map page */
    void *end_addr;            /* The end address of the map page */
  };

void vm_init_mfile(void);
void vm_add_mfile(mapid_t mapid, int fd, void *start_addr, void *end_addr);
struct vm_mfile* vm_find_mfile(mapid_t mapid);
bool vm_delete_mfile(mapid_t mapid);

#endif /* vm/mmap.h */
