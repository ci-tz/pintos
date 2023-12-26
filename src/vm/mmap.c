#include "vm/mmap.h"
#include <debug.h>

static unsigned map_file_hash(const struct hash_elem *m_, void *aux UNUSED);

static bool map_file_less(const struct hash_elem *a_,
                          const struct hash_elem *b_, void *aux UNUSED);

static void map_file_destroy(struct hash_elem *m_, void *aux UNUSED);

static void sup_pte_destroy(struct hash_elem *p_, void *aux UNUSED);

static int find_set_empty_mapid(struct map_file_table *mft);

static struct sup_pte *sup_pte_lookup_map_file_table(struct map_file_table *mft,
                                                     void *upage);

static bool map_is_overlaps(struct thread *t, void *upage, int num_pages);

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

struct map_file_table *map_file_table_create(void)
{
    struct map_file_table *mft = malloc(sizeof *mft);
    if (mft == NULL)
        return NULL;
    hash_init(&mft->map_file_hash, map_file_hash, map_file_less, NULL);
    mft->map_file_cnt = 0;
    memset(mft->mapid, 0, sizeof mft->mapid);

    mft->spt = sup_page_table_create(destroy_func);

    return mft;
}

void map_file_table_destroy(struct map_file_table *mft)
{
    hash_destroy(&mft->map_file_hash, map_file_destroy);
    /* sup_ptes are freed in do_munmap() */
    hash_destroy(&mft->sup_pte_hash, NULL);
    free(mft);
}

static bool map_is_overlaps(struct thread *t, void *upage, int num_pages)
{
    struct sup_page_table *spt = t->spt;
    struct map_file_table *mft = t->mft;
    void *addr = upage;
    for (int i = 0; i < num_pages; i++) {
        struct sup_pte *pte = sup_pte_lookup(spt, addr);
        if (pte != NULL)
            return true;

        struct map_file *mfile = sup_pte_lookup_map_file_table(mft, addr);
        if (mfile != NULL)
            return true;

        addr = (uint8_t *)addr + PGSIZE;
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
    if (map_is_overlaps(t, addr, num_pages))
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

    for (int i = 0; i < num_pages; i++) {
        struct sup_pte *pte = sup_pte_alloc(upage, true, MMAP, IN_FILESYS);
        if (pte == NULL)
            goto error;

        pte->file = file_copy;
        pte->offset = i * PGSIZE;
        pte->read_bytes = i == num_pages - 1 ? file_size % PGSIZE : PGSIZE;
        pte->zero_bytes = PGSIZE - pte->read_bytes;
        ptes[i] = pte;
        upage = (uint8_t *)upage + PGSIZE;
    }

    for (int i = 0; i < num_pages; i++) {
        struct sup_pte *pte = ptes[i];
        sup_pte_insert()
    }

    mfile->sup_pte_num = num_pages;
    memcpy(mfile->ptes, ptes, num_pages * sizeof *ptes);
    ASSERT(map_file_insert(mft, mfile));
    free(ptes);
    return mapid;

error:
    if (mfile != NULL)
        free(mfile);

    if (ptes != NULL) {
        for (int i = 0; i < num_pages; i++) {
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
    for (int i = 0; i < num_pages; i++) {
        struct sup_pte *pte = ptes[i];
        if (pte->location == FRAME) {
            if (pagedir_is_dirty(t->pagedir, pte->upage)) {
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
    for (i = 0; i < MAX_MMAPPED_FILES; i++) {
        if (!mft->mapid[i]) {
            mft->mapid[i] = true;
            return i;
        }
    }
    return -1;
}

static struct sup_pte *sup_pte_lookup_map_file_table(struct map_file_table *mft,
                                                     void *upage)
{
    struct sup_pte pte;
    pte.upage = upage;
    struct hash_elem *e = hash_find(&mft->sup_pte_hash, &pte.hash_elem);
    return e != NULL ? hash_entry(e, struct sup_pte, hash_elem) : NULL;
}

struct map_file *map_file_alloc(int mapid)
{
    struct map_file *file = malloc(sizeof *file);
    if (file == NULL)
        return NULL;
    file->mapid = mapid;
    file->sup_pte_num = 0;
    list_init(&file->sup_pte_list);
    return file;
}

static struct map_file *map_file_lookup(struct map_file_table *mft, int mapid)
{
    struct map_file file;
    file.mapid = mapid;
    struct hash_elem *e = hash_find(&mft->map_hash, &file.map_hash_elem);
    return e != NULL ? hash_entry(e, struct map_file, map_hash_elem) : NULL;
}

static unsigned map_file_hash(const struct hash_elem *m_, void *aux UNUSED)
{
    const struct map_file *m =
        hash_entry(m_, struct map_file, map_file_hash_elem);
    return hash_int(m->mapid);
}

static bool map_file_less(const struct hash_elem *a_,
                          const struct hash_elem *b_, void *aux UNUSED)
{
    const struct map_file *a =
        hash_entry(a_, struct map_file, map_file_hash_elem);
    const struct map_file *b =
        hash_entry(b_, struct map_file, map_file_hash_elem);
    return a->mapid < b->mapid;
}

static void map_file_destroy(struct hash_elem *m_, void *aux UNUSED)
{
    struct map_file *m = hash_entry(m_, struct map_file, map_file_hash_elem);
    do_munmap(m->mapid);
    free(m);
}

static void sup_pte_destroy(struct hash_elem *p_, void *aux UNUSED)
{
    struct sup_pte *p = hash_entry(p_, struct sup_pte, hash_elem);
    free(p);
}
