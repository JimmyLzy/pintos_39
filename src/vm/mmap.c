#include "vm/mmap.h"

void
vm_add_mfile(mapid_t mapid, int fd, void *start_addr, void *end_addr) {
    struct vm_mfile *mfile = (struct vm_mfile*) malloc(sizeof (struct vm_mfile));
    mfile->mapid = mapid;
    mfile->fd = fd;
    mfile->start_addr = start_addr;
    mfile->end_addr = end_addr;
    struct thread *current = thread_current();
    list_insert_ordered(&current->vm_mfiles, &mfile->list_elem, mfile_compare, 0);
}

struct vm_mfile*
vm_find_mfile(mapid_t mapid) {

    struct vm_mfile *mfile;
    struct thread *cur = thread_current();
    struct list_elem *e;

    if(!list_empty(&cur->vm_mfiles)) {
      for (e = list_begin(&cur->vm_mfiles); e != list_end(&cur->vm_mfiles);
              e = list_next(e)) {
          mfile = list_entry(e, struct vm_mfile, list_elem);
          if (mfile->mapid == mapid) {
              return mfile;
          }
       }
    }
    return NULL;
}

bool
vm_delete_mfile(mapid_t mapid) {
    struct vm_mfile *mfile = vm_find_mfile(mapid);
    if (mfile = NULL) {
        return false;
    }

    struct thread *current = thread_current();
    list_remove(&mfile->list_elem);
    free(mfile);
    return true;
}
