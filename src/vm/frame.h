#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/page.h"
#include <hash.h>
#include <list.h>
#include <stdbool.h>

/**
 * Data structure representing each physical page that contains a user page.
 */
typedef struct frame_table_entry {
    void *kpage;                      /* Kernel virtual address of the frame. */
    struct page *page;                /* User page mapped to the frame. */
    struct thread *thread;            /* Thread that owns the frame. */
    struct list_elem frame_list_elem; /* List element for the frame table. */
    struct hash_elem frame_hash_elem; /* Hash element for the frame table. */
} frame_table_entry;

typedef struct frame_table {
    struct list frame_list; /* List of frame table entries. */
    struct hash frame_hash; /* Hash table of frame table entries. */
    struct lock frame_lock; /* Lock for the frame table. */
} frame_table;

extern frame_table global_frame_table;

void frame_table_init(frame_table *ft);

void *palloc_get_page_frame(void);
void palloc_free_page_frame(void *kpage);

#endif /* vm/frame.h */