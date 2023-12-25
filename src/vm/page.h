// supplemental page

#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/file.h"
#include "filesys/off_t.h"
#include "vm/swap.h"
#include <hash.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_MMAPPED_FILES (128) // Maximum number of mapped files

typedef enum page_location
{
    IN_FILESYS, // in file system
    SWAP,       // in swap slot
    FRAME,      //  in physical frame
    ZERO,       // should be zero
} page_location;

typedef enum page_type
{
    BIN,   // ELF binary
    STACK, // stack segment
    MMAP,  // memory mapped file
} page_type;

struct sup_pte
{
    void *upage;            // user virtual address
    bool writable;          // writable or not
    page_type type;         // type of page
    page_location location; // location of page

    // for page in file system
    struct file *file;   // file pointer
    off_t offset;        // offset in file
    uint32_t read_bytes; // bytes to read
    uint32_t zero_bytes; // bytes to zero
    bool last_page;      // last page or not

    // for page in swap slot
    swap_index_t swap_index; // index of swap slot

    // for page in physical frame
    void *kpage; // kernel virtual address

    // for hash table
    struct hash_elem hash_elem;
    // for list
    struct list_elem list_elem;
};

struct sup_page_table
{
    struct hash page_table;
};

struct sup_page_table *sup_page_table_create(void);

void sup_page_table_destroy(struct sup_page_table **spt);

struct sup_pte *sup_pte_alloc(void *upage, bool writable, page_type type,
                              page_location location);

bool sup_pte_insert(struct sup_page_table *spt, struct sup_pte *pte);

bool sup_pte_remove(struct sup_page_table *spt, struct sup_pte *pte);

struct sup_pte *sup_pte_lookup(struct sup_page_table *spt, void *upage);

struct map_file
{
    int mapid;                // mapid
    int sup_pte_num;          // number of sup_pte
    struct file *file;        // file pointer
    struct list sup_pte_list; // list of sup_pte

    // linked to hash table
    struct hash_elem map_file_hash_elem; // hash element
};

struct map_file_table
{
    struct hash map_file_hash;
    struct hash sup_pte_hash;
    int map_file_cnt;
    int sup_pte_cnt;
    bool mapid[MAX_MMAPPED_FILES];
};

struct map_file_table *map_file_table_create(void);

void map_file_table_destroy(struct map_file_table *mft);

int do_mmap(int fd, void *addr);

void do_munmap(int mapid);


#endif /* vm/page.h */