#ifndef VM_SWAP_H
#define VM_SWAP_H
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <bitmap.h>
#include <stdbool.h>
#include <stddef.h>

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)
/* Size of swap partition is 4MB */
#define MAX_SWAP_SIZE (4 * 1024 * 1024)
/* The unit of swap partition is page */
#define MAX_SLOT_NUM (MAX_SWAP_SIZE / PGSIZE)

typedef size_t swap_index_t; /* Page index in swap partition */

#define INVALID_SWAP_INDEX (MAX_SLOT_NUM + 1)

typedef struct swap_table {
    struct bitmap *swap_bitmap; /* 0 for free, 1 for occupied */
    struct block *swap_block;
    struct lock swap_lock;
} swap_table;

void swap_init(swap_table *swap_table);
void do_swap_in(swap_table *swap_table, swap_index_t swap_index, void *kpage);
swap_index_t do_swap_out(swap_table *swap_table, void *kpage);
void swap_free(swap_table *swap_table, swap_index_t swap_index);

#endif