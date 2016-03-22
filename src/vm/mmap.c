#include "vm/mmap.h"
#include "vm/mmap.h"
#include "threads/interrupt.h"
#include "threads/synch.h"

struct lock mfile_lock;            /* The lock to prevent race condition */

/* Initialize the lock and it is called in init_thread() */
void
vm_init_mfile(void) {
  lock_init(&mfile_lock);
}

/* Create and add the map file with mapid, relative file descriptor, page start
   address and end address to the mfile list in thread.
*/
void
vm_add_mfile(mapid_t mapid, int fd, void *start_addr, void *end_addr) {
    struct vm_mfile *mfile = (struct vm_mfile*) malloc(sizeof (struct vm_mfile));
    mfile->mapid = mapid;
    mfile->fd = fd;
    mfile->start_addr = start_addr;
    mfile->end_addr = end_addr;
    struct thread *current = thread_current();
    lock_acquire(&mfile_lock);
    list_insert_ordered(&current->vm_mfiles, &mfile->list_elem, mfile_compare, 0);
    lock_release(&mfile_lock);
}

/* Looping through the mfile list in thread to find the map file with mapid, return
   NULL if there is no such map.
*/
struct vm_mfile*
vm_find_mfile(mapid_t mapid) {

    struct vm_mfile *mfile;
    struct thread *cur = thread_current();
    struct list_elem *e;
    lock_acquire(&mfile_lock);
    if(!list_empty(&cur->vm_mfiles)) {
      for (e = list_begin(&cur->vm_mfiles); e != list_end(&cur->vm_mfiles);
              e = list_next(e)) {
          mfile = list_entry(e, struct vm_mfile, list_elem);
          if (mfile->mapid == mapid) {
              lock_release(&mfile_lock);
              return mfile;
          }
       }
    }
    lock_release(&mfile_lock);
    return NULL;
}

/* Delete the mfile with mapid from the lsit in thread. False if there is no such
   mfile and true on success. It also free the struct we malloced.
*/
bool
vm_delete_mfile(mapid_t mapid) {
    struct vm_mfile *mfile = vm_find_mfile(mapid);
    if (mfile == NULL) {
        return false;
    }

    struct thread *current = thread_current();
    lock_acquire(&mfile_lock);
    list_remove(&mfile->list_elem);
    free(mfile);
    lock_release(&mfile_lock);
    return true;
}
