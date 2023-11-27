// supplemental page

#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdint.h>
#include "filesys/off_t.h"
#include "filesys/file.h"

typedef enum page_location {
    FILESYS,                    // in file system
    SWAP,                       // in swap slot
    FRAME,                     //  in physical frame
    ZERO,                       // all zero
} page_location;

struct sup_pte {
    void *upage ;               // user virtual address
    bool writable ;             // writable or not
    page_location location ;    // location of page

    // for page in file system
    struct file *file ;         // file pointer
    off_t offset ;              // offset in file
    uint32_t read_bytes ;       // bytes to read
    uint32_t zero_bytes ;       // bytes to zero

    // for page in swap slot
    size_t swap_index ;         // index of swap slot

    // for page in physical frame
    void *kpage ;               // kernel virtual address

    // for hash table
    struct hash_elem elem ;
};

#endif /* vm/page.h */