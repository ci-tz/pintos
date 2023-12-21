#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <debug.h>

extern swap_table global_swap_table;

static void vm_set_cnt(struct vm_occupancy *vm, void *upage, size_t page_num,
                       bool set);

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

    switch (p->location) {
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

struct vm_occupancy *vm_occupancy_create(void *vm_base, void *vm_end,
                                         size_t page_size)
{
    ASSERT(pg_ofs(vm_base) == 0);
    ASSERT(pg_ofs(vm_end) == 0);
    ASSERT(vm_base < vm_end);

    size_t page_num = ((uint32_t)vm_end - (uint32_t)vm_base) / page_size;

    struct vm_occupancy *occupancy = malloc(sizeof *occupancy);
    if (occupancy == NULL)
        return NULL;

    occupancy->vm_bitmap = bitmap_create(page_num);
    if (occupancy->vm_bitmap == NULL)
    {
        free(occupancy);
        return NULL;
    }

    occupancy->page_num = page_num;
    occupancy->page_size = page_size;
    occupancy->vm_base = vm_base;
    return occupancy;
}

void vm_occupancy_destroy(struct vm_occupancy **vm_occupancy)
{
    bitmap_destroy((*vm_occupancy)->vm_bitmap);
    free(*vm_occupancy);
    *vm_occupancy = NULL;
}

void vm_set_occupied(struct vm_occupancy *occupancy, void *upage)
{
    vm_set_cnt(occupancy, upage, 1, true);
}

void vm_set_occupied_cnt(struct vm_occupancy *occupancy, void *upage,
                         size_t page_num)
{
    vm_set_cnt(occupancy, upage, page_num, true);
}

void vm_set_free(struct vm_occupancy *occupancy, void *upage)
{
    vm_set_cnt(occupancy, upage, 1, false);
}

void vm_set_free_cnt(struct vm_occupancy *occupancy, void *upage,
                     size_t page_num)
{
    vm_set_cnt(occupancy, upage, page_num, false);
}

static void vm_set_cnt(struct vm_occupancy *occupancy, void *upage,
                       size_t page_num, bool set)
{
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(page_num > 0);

    size_t start = (upage - occupancy->vm_base) / occupancy->page_size;
    bitmap_set_multiple(occupancy->vm_bitmap, start, page_num, set);
}

bool vm_check_free(struct vm_occupancy *occupancy, void *upage, size_t page_num)
{
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(page_num > 0);

    size_t start = (upage - occupancy->vm_base) / occupancy->page_size;
    return bitmap_none(occupancy->vm_bitmap, start, page_num);
}