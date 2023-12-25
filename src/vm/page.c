#include "vm/page.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include <debug.h>
#include <string.h>

extern swap_table global_swap_table;

extern struct lock filesys_lock;

static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);

static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
                      void *aux UNUSED);

static void page_destroy(struct hash_elem *p_, void *aux UNUSED);

static unsigned map_file_hash(const struct hash_elem *m_, void *aux UNUSED);

static bool map_file_less(const struct hash_elem *a_,
                          const struct hash_elem *b_, void *aux UNUSED);

static void map_file_destroy(struct hash_elem *m_, void *aux UNUSED);

static int find_set_empty_mapid(struct map_file_table *mft);

static bool map_is_overlaps(struct sup_page_table *spt, void *upage,
                            int num_pages);

static struct map_file *map_file_alloc(int mapid);

static struct map_file *map_file_lookup(struct map_file_table *mft, int mapid);

static bool map_file_insert(struct map_file_table *mft, struct map_file *mfile)
{
    struct hash_elem *e = hash_insert(&mft->map_hash, &mfile->map_hash_elem);
    return e == NULL;
}

static bool map_file_remove(struct map_file_table *mft, struct map_file *mfile)
{
    struct hash_elem *e = hash_delete(&mft->map_hash, &mfile->map_hash_elem);
    return e != NULL;
}

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

bool sup_pte_remove(struct sup_page_table *spt, struct sup_pte *pte)
{
    struct hash_elem *e = hash_delete(&spt->page_table, &pte->hash_elem);
    return e != NULL;
}

struct sup_pte *sup_pte_lookup(struct sup_page_table *spt, void *upage)
{
    struct sup_pte pte;
    pte.upage = upage;
    struct hash_elem *e = hash_find(&spt->page_table, &pte.hash_elem);
    return e != NULL ? hash_entry(e, struct sup_pte, hash_elem) : NULL;
}

struct map_file_table *map_file_table_create(void)
{
    struct map_file_table *mft = malloc(sizeof *mft);
    if (mft == NULL)
        return NULL;
    hash_init(&mft->map_file_hash, map_file_hash, map_file_less, NULL);
    hash_init(&mft->sup_pte_hash, page_hash, page_less, NULL);
    mft->map_file_cnt = 0;
    mft->sup_pte_cnt = 0;
    memset(mft->mapid, 0, sizeof mft->mapid);
    return mft;
}

void map_file_table_destroy(struct map_file_table *mft)
{
    hash_destroy(&mft->map_file_hash, map_file_destroy);
    hash_destroy(&mft->sup_pte_hash, NULL); // sup_ptes are freed by munmap
    free(mft);
}

static bool map_is_overlaps(struct sup_page_table *spt, void *upage,
                            int num_pages)
{
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(num_pages > 0);
    for (int i = 0; i < num_pages; i++)
    {
        struct sup_pte *pte = sup_pte_lookup(spt, upage + i * PGSIZE);
        if (pte != NULL)
            return true;
    }
    return false;
}

int do_mmap(int fd, void *addr)
{
    // Check validity of fd and addr
    if (fd == 0 || fd == 1 || addr == 0 || pg_ofs(addr) != 0)
        return -1;

    struct thread *t = thread_current();
    struct file *file = t->fdt[fd];
    if (file == NULL)
        return -1;

    off_t file_size = file_length(file);
    if (file_size == 0)
        return -1;

    struct sup_page_table *spt = t->spt;
    int num_pages = (file_size + PGSIZE - 1) / PGSIZE;
    if (map_is_overlaps(spt, addr, num_pages))
        return -1;

    // All checks passed, do the real mmap
    struct map_file *mfile = NULL;
    struct sup_pte **ptes = NULL;
    struct map_file_table *mft = t->mft;
    struct file *file_copy = file_reopen(file);
    if (file_copy == NULL)
        return -1;

    int mapid = find_set_empty_mapid(mft);
    if (mapid == -1)
        return -1;

    mfile = map_file_alloc(mapid);
    if (mfile == NULL)
        goto error;

    void *upage = addr;
    ptes = calloc(num_pages, sizeof *ptes);
    if (ptes == NULL)
        goto error;

    for (int i = 0; i < num_pages; i++)
    {
        struct sup_pte *pte = sup_pte_alloc(upage, true, MMAP, IN_FILESYS);
        if (pte == NULL)
            goto error;

        pte->file = file_copy;
        pte->offset = i * PGSIZE;
        pte->read_bytes = i == num_pages - 1 ? file_size % PGSIZE : PGSIZE;
        pte->zero_bytes = PGSIZE - pte->read_bytes;
        pte->last_page = i == num_pages - 1;
        ptes[i] = pte;
        upage = (uint8_t *)upage + PGSIZE;
    }

    for (int i = 0; i < num_pages; i++)
    {
        ASSERT(sup_pte_insert(spt, ptes[i]));
    }

    mfile->sup_pte_num = num_pages;
    memcpy(mfile->ptes, ptes, num_pages * sizeof *ptes);
    ASSERT(map_file_insert(mft, mfile));
    free(ptes);
    return mapid;

error:
    if (mfile != NULL)
        free(mfile);

    if (ptes != NULL)
    {
        for (int i = 0; i < num_pages; i++)
        {
            if (ptes[i] != NULL)
                free(ptes[i]);
        }
        free(ptes);
    }
    return -1;
}

void do_munmap(int mapid)
{
    struct thread *t = thread_current();
    struct map_file_table *mft = t->mft;

    struct map_file *mfile = map_file_lookup(mft, mapid);
    if (mfile == NULL)
        return;
    
    struct sup_page_table *spt = t->spt;
    struct sup_pte **ptes = mfile->ptes;
    int num_pages = mfile->sup_pte_num;
    struct file *file = ptes[0]->file;
    for(int i = 0; i < num_pages; i++)
    {
        struct sup_pte *pte = ptes[i];
        if(pte->location == FRAME)
        {
            if(pagedir_is_dirty(t->pagedir, pte->upage))
            {
                lock_acquire(&filesys_lock);
                file_write_at(file, pte->kpage, pte->read_bytes, pte->offset);
                lock_release(&filesys_lock);
            }
            pagedir_clear_page(t->pagedir, pte->upage);
            palloc_free_page_frame(pte->kpage);
        }

        sup_pte_remove(spt, pte);
        free(pte);
    }
    ASSERT(map_file_remove(mft, mfile));
    file_close(file);
    free(mfile);
}

static int find_set_empty_mapid(struct map_file_table *mft)
{
    int i;
    for (i = 0; i < MAX_MMAPPED_FILES; i++)
    {
        if (!mft->mapid[i])
        {
            mft->mapid[i] = true;
            return i;
        }
    }
    return -1;
}

struct map_file *map_file_alloc(int mapid)
{
    struct map_file *file = malloc(sizeof *file);
    if (file == NULL)
        return NULL;
    file->mapid = mapid;
    file->sup_pte_num = 0;
    memset(file->ptes, 0, sizeof file->ptes);
    return file;
}

static struct map_file *map_file_lookup(struct map_file_table *mft, int mapid)
{
    struct map_file file;
    file.mapid = mapid;
    struct hash_elem *e = hash_find(&mft->map_hash, &file.map_hash_elem);
    return e != NULL ? hash_entry(e, struct map_file, map_hash_elem) : NULL;
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
        // TODO: should mmaped file page be written back to file there?
        if (pagedir_is_dirty(t->pagedir, p->upage) && p->type == MMAP)
        {
            lock_acquire(&filesys_lock);
            file_write_at(p->file, p->kpage, p->read_bytes, p->offset);
            lock_release(&filesys_lock);
        }
        break;
    default:
        break;
    }
    free(p);
}

static unsigned map_file_hash(const struct hash_elem *m_, void *aux UNUSED)
{
    const struct map_file *m = hash_entry(m_, struct map_file, map_file_hash_elem);
    return hash_int(m->mapid);
}

static bool map_file_less(const struct hash_elem *a_,
                          const struct hash_elem *b_, void *aux UNUSED)
{
    const struct map_file *a = hash_entry(a_, struct map_file, map_file_hash_elem);
    const struct map_file *b = hash_entry(b_, struct map_file, map_file_hash_elem);
    return a->mapid < b->mapid;
}

static void map_file_destroy(struct hash_elem *m_, void *aux UNUSED)
{
    struct map_file *m = hash_entry(m_, struct map_file, map_file_hash_elem);
    do_munmap(m->mapid);
    free(m);
}
