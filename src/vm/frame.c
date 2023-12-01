#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include <debug.h>
#include <stdio.h>

extern frame_table global_frame_table;

static frame_table_entry *frame_table_entry_alloc(void);
static frame_table_entry *frame_table_find(frame_table *ft, void *kpage);
static bool frame_table_insert(frame_table *ft, frame_table_entry *fte);
static void frame_table_remove(frame_table *ft, frame_table_entry *fte);

static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b,
                       void *aux UNUSED);

void frame_table_init(frame_table *ft)
{
    list_init(&ft->frame_list);
    hash_init(&ft->frame_hash, frame_hash, frame_less, NULL);
    lock_init(&ft->frame_lock);
}

void *palloc_get_page_frame(void)
{
    void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    ASSERT(kpage != NULL); // TODO: implement swap
    // Add the frame to the frame table.
    frame_table_entry *fte = frame_table_entry_alloc();
    ASSERT(fte != NULL);
    fte->kpage = kpage;
    bool success = frame_table_insert(&global_frame_table, fte);
    ASSERT(success);
    return kpage;
}

void palloc_free_page_frame(void *kpage)
{
    frame_table_entry *fte = frame_table_find(&global_frame_table, kpage);
    if (fte == NULL) {
        return;
    }
    // TODO: Should i need to uninstall the page?
    frame_table_remove(&global_frame_table, fte);
    palloc_free_page(kpage);
    free(fte);
}

void frame_refer_to_page(void *kpage, struct sup_pte *pte)
{
    frame_table_entry *fte = frame_table_find(&global_frame_table, kpage);
    ASSERT(fte != NULL);
    fte->pte = pte;
    fte->thread = thread_current();
}

void frame_unrefer_to_page(void *kpage)
{
    frame_table_entry *fte = frame_table_find(&global_frame_table, kpage);
    ASSERT(fte != NULL);
    fte->pte = NULL;
    fte->thread = NULL;
}

void remove_related_frame_table_entry(struct thread *t)
{
    struct list_elem *e;
    struct list *frame_list = &global_frame_table.frame_list;
    for (e = list_begin(frame_list); e != list_end(frame_list);) {
        struct list_elem *next = list_next(e);
        frame_table_entry *fte =
            list_entry(e, frame_table_entry, frame_list_elem);
        if (fte->thread == t) {
            //printf("[DEBUG] PROCESS %s: remove frame %p\n", t->name, fte->kpage);
            frame_table_remove(&global_frame_table, fte);
            free(fte);
        }
        e = next;
    }
}

static bool frame_table_insert(frame_table *ft, frame_table_entry *fte)
{
    lock_acquire(&ft->frame_lock);
    struct hash_elem *e = hash_insert(&ft->frame_hash, &fte->frame_hash_elem);
    if (e == NULL)
        list_push_back(&ft->frame_list, &fte->frame_list_elem);
    lock_release(&ft->frame_lock);
    return e == NULL;
}

static void frame_table_remove(frame_table *ft, frame_table_entry *fte)
{
    lock_acquire(&ft->frame_lock);
    list_remove(&fte->frame_list_elem);
    hash_delete(&ft->frame_hash, &fte->frame_hash_elem);
    lock_release(&ft->frame_lock);
}

static frame_table_entry *frame_table_entry_alloc(void)
{
    frame_table_entry *fte = malloc(sizeof(frame_table_entry));
    if (fte == NULL)
        return NULL;
    fte->kpage = NULL;
    fte->pte = NULL;
    fte->thread = NULL;
    return fte;
}

static frame_table_entry *frame_table_find(frame_table *ft, void *kpage)
{
    struct hash_elem *e;
    frame_table_entry fte;
    fte.kpage = kpage;
    e = hash_find(&ft->frame_hash, &fte.frame_hash_elem);
    if (e == NULL)
        return NULL;
    return hash_entry(e, frame_table_entry, frame_hash_elem);
}

static bool frame_less(const struct hash_elem *a, const struct hash_elem *b,
                       void *aux UNUSED)
{
    const frame_table_entry *fte_a =
        hash_entry(a, frame_table_entry, frame_hash_elem);
    const frame_table_entry *fte_b =
        hash_entry(b, frame_table_entry, frame_hash_elem);
    return fte_a->kpage < fte_b->kpage;
}

static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
    const frame_table_entry *fte =
        hash_entry(e, frame_table_entry, frame_hash_elem);
    return hash_bytes(&fte->kpage, sizeof(fte->kpage));
}