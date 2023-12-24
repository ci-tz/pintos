#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include <debug.h>
#include <string.h>

extern swap_table global_swap_table;

static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);

static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
                      void *aux UNUSED);

static void page_destroy(struct hash_elem *p_, void *aux UNUSED);

static unsigned mmaped_hash(const struct hash_elem *m_, void *aux UNUSED);

static bool mmaped_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED);

static void mmaped_destroy(struct hash_elem *m_, void *aux UNUSED);

static int find_empty_mapid(struct mmaped_hash_table *table);

struct sup_page_table *sup_page_table_create(void)
{
    struct sup_page_table *spt = malloc(sizeof *spt);
    if (spt == NULL)
        return NULL;
    hash_init(&spt->page_table, page_hash, page_less, NULL);
    return spt;
}

void sup_page_table_destroy(struct sup_page_table **spt)
{
    hash_destroy(&(*spt)->page_table, page_destroy);
    free(*spt);
    *spt = NULL;
}

struct sup_pte *sup_pte_alloc(void *upage, bool writable, page_type type,
                              page_location location)
{
    struct sup_pte *pte = malloc(sizeof *pte);
    if (pte == NULL)
        return NULL;
    pte->upage = upage;
    pte->writable = writable;
    pte->type = type;
    pte->location = location;

    pte->file = NULL;
    pte->swap_index = INVALID_SWAP_INDEX;
    pte->kpage = NULL;

    return pte;
}

bool sup_pte_insert(struct sup_page_table *spt, struct sup_pte *pte)
{
    struct hash_elem *e = hash_insert(&spt->page_table, &pte->hash_elem);
    return e == NULL;
}

struct sup_pte *sup_pte_lookup(struct sup_page_table *spt, void *upage)
{
    struct sup_pte pte;
    pte.upage = upage;
    struct hash_elem *e = hash_find(&spt->page_table, &pte.hash_elem);
    return e != NULL ? hash_entry(e, struct sup_pte, hash_elem) : NULL;
}

struct mmaped_hash_table *mmaped_hash_table_create(void)
{
    struct mmaped_hash_table *table = malloc(sizeof *table);
    if (table == NULL)
        return NULL;
    memset(table->mapid, 0, sizeof table->mapid);
    hash_init(&table->mmap_hash_table, mmaped_hash, mmaped_less, NULL);
    return table;
}

void mmaped_hash_table_destroy(struct mmaped_hash_table **mmaped_hash_table)
{
    hash_destroy(&(*mmaped_hash_table)->mmap_hash_table, mmaped_destroy);
    free(*mmaped_hash_table);
    *mmaped_hash_table = NULL;
}

int mmaped_file_alloc(struct mmaped_file **file_ptr)
{
    struct mmaped_file *file = malloc(sizeof *file);
    if (file == NULL)
        return -1;
    file->mapid = find_empty_mapid(&thread_current()->mmaped_hash_table);
    if (file->mapid == -1)
    {
        free(file);
        return -1;
    }
    file->sup_pte_num = 0;
    memset(file->ptes, 0, sizeof file->ptes);
    *file_ptr = file;
    return file->mapid;
}

bool mmaped_file_insert(struct mmaped_hash_table *table,
                        struct mmaped_file *file)
{
    struct hash_elem *e =
        hash_insert(&table->mmap_hash_table, &file->mmap_hash_elem);
    return e == NULL;
}

struct mmaped_file *mmaped_file_lookup(struct mmaped_hash_table *table,
                                       int mapid)
{
    struct mmaped_file file;
    file.mapid = mapid;
    struct hash_elem *e =
        hash_find(&table->mmap_hash_table, &file.mmap_hash_elem);
    return e != NULL ? hash_entry(e, struct mmaped_file, mmap_hash_elem) : NULL;
}

void mmaped_file_remove(struct mmaped_hash_table *table,
                        struct mmaped_file *file)
{
    hash_delete(&table->mmap_hash_table, &file->mmap_hash_elem);
}

static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct sup_pte *p = hash_entry(p_, struct sup_pte, hash_elem);
    return hash_bytes(&p->upage, sizeof p->upage);
}

static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
                      void *aux UNUSED)
{
    const struct sup_pte *a = hash_entry(a_, struct sup_pte, hash_elem);
    const struct sup_pte *b = hash_entry(b_, struct sup_pte, hash_elem);

    return a->upage < b->upage;
}

static void page_destroy(struct hash_elem *p_, void *aux UNUSED)
{
    struct sup_pte *p = hash_entry(p_, struct sup_pte, hash_elem);
    struct thread *t = thread_current();

    switch (p->location)
    {
    case SWAP:
        ASSERT(p->swap_index != INVALID_SWAP_INDEX);
        swap_free(&global_swap_table, p->swap_index);
        break;
    case FRAME:
        if (pagedir_is_dirty(t->pagedir, p->upage) && p->type == MMAP)
        {
            // TODO: write back the dirty mmap page to file
        }
        break;
    default:
        break;
    }
    free(p);
}

static unsigned mmaped_hash(const struct hash_elem *m_, void *aux UNUSED)
{
    const struct mmaped_file *m =
        hash_entry(m_, struct mmaped_file, mmap_hash_elem);
    return hash_bytes(&m->mapid, sizeof m->mapid);
}

static bool mmaped_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED)
{
    const struct mmaped_file *a =
        hash_entry(a_, struct mmaped_file, mmap_hash_elem);
    const struct mmaped_file *b =
        hash_entry(b_, struct mmaped_file, mmap_hash_elem);

    return a->mapid < b->mapid;
}

static void mmaped_destroy(struct hash_elem *m_, void *aux UNUSED)
{
    struct mmaped_file *m = hash_entry(m_, struct mmaped_file, mmap_hash_elem);
    /* Just free the mmaped_file struct, the sup_pte will be freed by
     * page_destroy */
    free(m);
}

static int find_empty_mapid(struct mmaped_hash_table *table)
{
    int i;
    for (i = 0; i < MAX_MMAPPED_FILES; i++)
    {
        if (table->mapid[i] == 0)
            return i + 1;
    }
    return -1;
}