// supplemental page

#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/file.h"
#include "filesys/off_t.h"
#include "threads/vaddr.h"
#include "vm/swap.h"
#include <hash.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_STACK_SIZE (8 * 1024 * 1024)

typedef enum page_location {
    IN_FILESYS, // in file system
    SWAP,       // in swap slot
    FRAME,      //  in physical frame
    ZERO,       // should be zero
} page_location;

typedef enum page_type {
    BIN,   // ELF binary
    STACK, // stack segment
    MMAP,  // memory mapped file
} page_type;

struct sup_pte {
    void *upage;            // user virtual address
    bool writable;          // writable or not
    page_type type;         // type of page
    page_location location; // location of page

    // for page in file system
    struct file *file;   // file pointer
    off_t offset;        // offset in file
    uint32_t read_bytes; // bytes to read
    uint32_t zero_bytes; // bytes to zero

    // for page in swap slot
    swap_index_t swap_index; // index of swap slot

    // for page in physical frame
    void *kpage; // kernel virtual address

    // for hash table
    struct hash_elem hash_elem;
    // for list
    struct list_elem list_elem;
};

struct sup_page_table {
    struct hash page_table;
};

struct sup_page_table *sup_page_table_create(void);

void sup_page_table_destroy(struct sup_page_table *spt);

struct sup_pte *sup_pte_alloc(void *upage, bool writable, page_type type,
                              page_location location);

bool sup_pte_insert(struct sup_page_table *spt, struct sup_pte *pte);

bool sup_pte_remove(struct sup_page_table *spt, struct sup_pte *pte);

struct sup_pte *sup_pte_lookup(struct sup_page_table *spt, void *upage);

struct sup_pte *need_grow_stack(struct thread *t, void *fault_addr, void *esp);

#endif /* vm/page.h */