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

static unsigned map_file_hash(const struct hash_elem *m_, void *aux UNUSED);

static bool map_file_less(const struct hash_elem *a_,
                          const struct hash_elem *b_, void *aux UNUSED);

static void map_file_destroy(struct hash_elem *m_, void *aux UNUSED);

static int find_set_empty_mapid(struct map_file_table *mft);

static bool map_is_overlaps(struct sup_page_table *spt, void *upage,
                            int num_pages);

static struct map_file *map_file_alloc(int mapid);

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

struct map_file_table *map_file_table_create(void)
{
    struct map_file_table *mft = malloc(sizeof *mft);
    if (mft == NULL)
        return NULL;
    hash_init(&mft->map_hash, map_file_hash, map_file_less, NULL);
    memset(mft->mapid, 0, sizeof mft->mapid);
    return mft;
}

void map_file_table_destroy(struct map_file_table *mft)
{
    hash_destroy(&mft->map_hash, map_file_destroy);
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

bool do_mmap(int fd, void *addr)
{
    // Check validity of fd and addr
    if (fd == 0 || fd == 1 || addr == 0 || pg_ofs(addr) != 0)
        return false;

    struct thread *t = thread_current();
    struct file *file = t->fdt[fd];
    if (file == NULL)
        return false;

    off_t file_size = file_length(file);
    if (file_size == 0)
        return false;

    struct sup_page_table *spt = t->spt;
    int num_pages = (file_size + PGSIZE - 1) / PGSIZE;
    if (map_is_overlaps(spt, addr, num_pages))
        return false;

    // All checks passed, do the real mmap
    struct map_file *mfile = NULL;
    struct sup_pte **ptes = NULL;
    struct map_file_table *mft = t->mft;

    int mapid = find_set_empty_mapid(mft);
    if (mapid == -1)
        return false;

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

        pte->file = file;
        pte->offset = i * PGSIZE;
        pte->read_bytes = i == num_pages - 1 ? file_size % PGSIZE : PGSIZE;
        pte->zero_bytes = PGSIZE - pte->read_bytes;
        ptes[i] = pte;
        upage += PGSIZE;
    }

    for (int i = 0; i < num_pages; i++)
    {
        ASSERT(sup_pte_insert(spt, ptes[i]));
    }

    mfile->sup_pte_num = num_pages;
    memcpy(mfile->ptes, ptes, num_pages * sizeof *ptes);
    ASSERT(hash_insert(&mft->map_hash, &mfile->map_hash_elem) == NULL);
    free(ptes);
    return true;

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
    return false;
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
            // TODO: write back the dirty map page to file
        }
        break;
    default:
        break;
    }
    free(p);
}

static unsigned map_file_hash(const struct hash_elem *m_, void *aux UNUSED)
{
    const struct map_file *m = hash_entry(m_, struct map_file, map_hash_elem);
    return hash_int(m->mapid);
}

static bool map_file_less(const struct hash_elem *a_,
                          const struct hash_elem *b_, void *aux UNUSED)
{
    const struct map_file *a = hash_entry(a_, struct map_file, map_hash_elem);
    const struct map_file *b = hash_entry(b_, struct map_file, map_hash_elem);
    return a->mapid < b->mapid;
}

static void map_file_destroy(struct hash_elem *m_, void *aux UNUSED)
{
    struct map_file *m = hash_entry(m_, struct map_file, map_hash_elem);
    /* Just free the map_file struct, the sup_pte will be freed by
     * page_destroy() */
    free(m);
}
