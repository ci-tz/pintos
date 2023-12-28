#include "vm/mmap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include <debug.h>
#include <string.h>

static unsigned map_file_hash(const struct hash_elem *m_, void *aux UNUSED);

static bool map_file_less(const struct hash_elem *a_,
                          const struct hash_elem *b_, void *aux UNUSED);

static void map_file_destroy(struct hash_elem *m_, void *aux UNUSED);

static int find_mapid(struct map_file_table *mft);

static bool map_is_overlaps(struct thread *t, void *upage, int num_pages);

static struct map_file *map_file_alloc(int mapid);

static bool sup_pte_insert_mft(struct map_file_table *mft, struct sup_pte *pte);

static bool sup_pte_remove_mft(struct map_file_table *mft, struct sup_pte *pte);

static struct sup_pte *sup_pte_lookup_mft(struct map_file_table *mft,
                                          void *upage);

static void sup_pte_insert_mf(struct map_file *mfile, struct sup_pte *pte);

static bool map_file_insert(struct map_file_table *mft, struct map_file *mfile);

static bool map_file_remove(struct map_file_table *mft, struct map_file *mfile);

static struct map_file *map_file_lookup(struct map_file_table *mft, int mapid);

static void write_back_dirty_page(struct thread *t, struct sup_pte *pte);

static void free_mfile_ptes(struct thread *t, struct map_file *mfile);

extern struct lock filesys_lock;

struct map_file_table *map_file_table_create(void)
{
    struct map_file_table *mft = malloc(sizeof *mft);
    if (mft == NULL)
        return NULL;

    hash_init(&mft->map_file_hash, map_file_hash, map_file_less, NULL);
    mft->map_file_cnt = 0;
    memset(mft->mapid, 0, sizeof mft->mapid);
    mft->spt = sup_page_table_create();
    return mft;
}

void map_file_table_destroy(struct map_file_table *mft)
{
    hash_destroy(&mft->map_file_hash, map_file_destroy);
    sup_page_table_destroy(mft->spt);
    free(mft);
}

static bool map_is_overlaps(struct thread *t, void *upage, int num_pages)
{
    struct sup_page_table *spt = t->spt;
    struct map_file_table *mft = t->mft;
    for (int i = 0; i < num_pages; i++) {
        struct sup_pte *pte = sup_pte_lookup(spt, upage);
        if (pte != NULL)
            return true;

        pte = sup_pte_lookup_mft(mft, upage);
        if (pte != NULL)
            return true;

        upage = (uint8_t *)upage + PGSIZE;
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

    int num_pages = (file_size + PGSIZE - 1) / PGSIZE;
    if (map_is_overlaps(t, addr, num_pages))
        return -1;

    // All checks passed, do the real mmap
    struct map_file *mfile = NULL;
    struct sup_pte **pte_array = NULL;
    struct map_file_table *mft = t->mft;

    int mapid = find_mapid(mft);
    if (mapid == -1)
        return -1;

    struct file *file_copy = file_reopen(file);
    if (file_copy == NULL)
        return -1;

    mfile = map_file_alloc(mapid);
    if (mfile == NULL)
        goto error;
    mfile->file = file_copy;

    pte_array = calloc(num_pages, sizeof *pte_array);
    if (pte_array == NULL)
        goto error;

    void *upage = addr;
    for (int i = 0; i < num_pages; i++) {
        struct sup_pte *pte = sup_pte_alloc(upage, true, MMAP, IN_FILESYS);
        if (pte == NULL)
            goto error;

        pte->file = file_copy;
        pte->offset = i * PGSIZE;
        pte->read_bytes = i == num_pages - 1 ? file_size % PGSIZE : PGSIZE;
        pte->zero_bytes = PGSIZE - pte->read_bytes;
        pte_array[i] = pte;
        upage = (uint8_t *)upage + PGSIZE;
    }

    for (int i = 0; i < num_pages; i++) {
        struct sup_pte *pte = pte_array[i];
        sup_pte_insert_mf(mfile, pte);
        sup_pte_insert_mft(mft, pte);
    }

    map_file_insert(mft, mfile);
    free(pte_array);
    return mapid;

error:
    if (file_copy != NULL)
        file_close(file_copy);

    if (mfile != NULL)
        free(mfile);

    if (pte_array != NULL) {
        for (int i = 0; i < num_pages; i++) {
            if (pte_array[i] != NULL)
                free(pte_array[i]);
        }
        free(pte_array);
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

    free_mfile_ptes(t, mfile);

    map_file_remove(mft, mfile);
    file_close(mfile->file);
    free(mfile);
}

struct sup_pte *is_mmaped_page(struct thread *t, void *fault_page)
{
    struct map_file_table *mft = t->mft;
    struct sup_pte *pte = sup_pte_lookup_mft(mft, fault_page);
    return pte;
}

static int find_mapid(struct map_file_table *mft)
{
    for (int i = 0; i < MAX_MMAPPED_FILES; i++) {
        if (!mft->mapid[i]) {
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
    list_init(&file->sup_pte_list);
    return file;
}

static bool sup_pte_insert_mft(struct map_file_table *mft, struct sup_pte *pte)
{
    return sup_pte_insert(mft->spt, pte);
}

static bool sup_pte_remove_mft(struct map_file_table *mft, struct sup_pte *pte)
{
    return sup_pte_remove(mft->spt, pte);
}

static struct sup_pte *sup_pte_lookup_mft(struct map_file_table *mft,
                                          void *upage)
{
    return sup_pte_lookup(mft->spt, upage);
}

static void sup_pte_insert_mf(struct map_file *mfile, struct sup_pte *pte)
{
    list_push_back(&mfile->sup_pte_list, &pte->list_elem);
}

static bool map_file_insert(struct map_file_table *mft, struct map_file *mfile)
{
    struct hash_elem *e = hash_insert(&mft->map_file_hash, &mfile->mf_elem);
    mft->map_file_cnt++;
    mft->mapid[mfile->mapid] = true;
    return e == NULL;
}

static bool map_file_remove(struct map_file_table *mft, struct map_file *mfile)
{
    struct hash_elem *e = hash_delete(&mft->map_file_hash, &mfile->mf_elem);
    mft->map_file_cnt--;
    mft->mapid[mfile->mapid] = false;
    return e != NULL;
}

static struct map_file *map_file_lookup(struct map_file_table *mft, int mapid)
{
    struct map_file mfile;
    mfile.mapid = mapid;
    struct hash_elem *e = hash_find(&mft->map_file_hash, &mfile.mf_elem);
    return e != NULL ? hash_entry(e, struct map_file, mf_elem) : NULL;
}

static void write_back_dirty_page(struct thread *t, struct sup_pte *pte)
{
    bool dirty = pagedir_is_dirty(t->pagedir, pte->upage);
    if (dirty) {
        lock_acquire(&filesys_lock);
        file_write_at(pte->file, pte->upage, pte->read_bytes, pte->offset);
        lock_release(&filesys_lock);
    }
}

static void free_mfile_ptes(struct thread *t, struct map_file *mfile)
{
    struct map_file_table *mft = t->mft;

    /* Clean up all sup_ptes of this file. */
    struct list_elem *e;
    while (!list_empty(&mfile->sup_pte_list)) {
        e = list_pop_front(&mfile->sup_pte_list);
        struct sup_pte *pte = list_entry(e, struct sup_pte, list_elem);
        write_back_dirty_page(t, pte);
        sup_pte_remove_mft(mft, pte);
        free(pte);
    }
}

static unsigned map_file_hash(const struct hash_elem *m_, void *aux UNUSED)
{
    const struct map_file *m = hash_entry(m_, struct map_file, mf_elem);
    return hash_int(m->mapid);
}

static bool map_file_less(const struct hash_elem *a_,
                          const struct hash_elem *b_, void *aux UNUSED)
{
    const struct map_file *a = hash_entry(a_, struct map_file, mf_elem);
    const struct map_file *b = hash_entry(b_, struct map_file, mf_elem);
    return a->mapid < b->mapid;
}

static void map_file_destroy(struct hash_elem *m_, void *aux UNUSED)
{
    struct map_file *m = hash_entry(m_, struct map_file, mf_elem);
    struct thread *t = thread_current();
    free_mfile_ptes(t, m);
    file_close(m->file);
    free(m);
}
