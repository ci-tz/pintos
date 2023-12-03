#include "vm/swap.h"

void swap_init(swap_table *swap_table)
{
    swap_table->swap_block = block_get_role(BLOCK_SWAP);
    swap_table->swap_bitmap = bitmap_create(MAX_SLOT_NUM);
    bitmap_set_all(swap_table->swap_bitmap, 0);
    lock_init(&swap_table->swap_lock);
}

void do_swap_in(swap_table *swap_table, swap_index_t swap_index, void *kpage)
{
    lock_acquire(&swap_table->swap_lock);
    ASSERT(bitmap_test(swap_table->swap_bitmap, swap_index));
    bitmap_flip(swap_table->swap_bitmap, swap_index);
    int i;
    for (i = 0; i < SECTORS_PER_PAGE; i++) {
        block_read(swap_table->swap_block, swap_index * SECTORS_PER_PAGE + i,
                   (uint8_t *)kpage + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&swap_table->swap_lock);
}

swap_index_t do_swap_out(swap_table *swap_table, void *kpage)
{
    lock_acquire(&swap_table->swap_lock);
    swap_index_t swap_index =
        bitmap_scan_and_flip(swap_table->swap_bitmap, 0, 1, 0);
    ASSERT(swap_index != BITMAP_ERROR);
    int i;
    for (i = 0; i < SECTORS_PER_PAGE; i++) {
        block_write(swap_table->swap_block, swap_index * SECTORS_PER_PAGE + i,
                    (uint8_t *)kpage + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&swap_table->swap_lock);
    return swap_index;
}

void swap_free(swap_table *swap_table, swap_index_t swap_index)
{
    lock_acquire(&swap_table->swap_lock);
    ASSERT(bitmap_test(swap_table->swap_bitmap, swap_index));
    bitmap_flip(swap_table->swap_bitmap, swap_index);
    lock_release(&swap_table->swap_lock);
}
