#ifndef VM_MMAP_H
#define VM_MMAP_H

#include "threads/thread.h"
#include "vm/page.h"
#include <hash.h>
#include <list.h>

#define MAX_MMAPPED_FILES (128) // Maximum number of mapped files

struct map_file {
    int mapid; // mapid of this file
    struct file *file;
    struct list sup_pte_list; // list of sup_ptes of this file

    struct hash_elem mf_elem; // linked to map_file_table
};

struct map_file_table {
    struct hash map_file_hash;
    int map_file_cnt;
    bool mapid[MAX_MMAPPED_FILES];

    struct sup_page_table *spt; // All sup_ptes of mmaped files
};

struct map_file_table *map_file_table_create(void);

void map_file_table_destroy(struct map_file_table *mft);

int do_mmap(int fd, void *addr);

void do_munmap(int mapid);

struct sup_pte *is_mmaped_page(struct thread *t, void *fault_page);

#endif /* vm/mmap.h */