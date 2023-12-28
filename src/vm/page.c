#include "vm/page.h"
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

struct sup_page_table *sup_page_table_create(void)
{
    struct sup_page_table *spt = malloc(sizeof *spt);
    if (spt == NULL)
        return NULL;
    hash_init(&spt->page_table, page_hash, page_less, NULL);
    return spt;
}

void sup_page_table_destroy(struct sup_page_table *spt)
{
    hash_destroy(&spt->page_table, page_destroy);
    free(spt);
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

struct sup_pte *need_grow_stack(struct thread *t, void *fault_addr, void *esp)
{
    bool need_grow =
        (fault_addr <= PHYS_BASE) &&
        (fault_addr >= (void *)((uint8_t *)esp - 32)) &&
        (fault_addr >= (void *)((uint8_t *)PHYS_BASE - MAX_STACK_SIZE));

    if (need_grow) {
        struct sup_page_table *spt = t->spt;
        void *fault_page = pg_round_down(fault_addr);
        struct sup_pte *pte = sup_pte_alloc(fault_page, true, STACK, ZERO);
        if (pte == NULL) {
            return NULL;
        }
        if (!sup_pte_insert(spt, pte)) {
            free(pte);
            return NULL;
        }
        return pte;
    } else {
        return NULL;
    }
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
    /* MMAP sup_pte is not freed here. */
    ASSERT(p->type != MMAP);
    /* Free the occupied swap slot. */
    if (p->location == SWAP) {
        ASSERT(p->swap_index != INVALID_SWAP_INDEX);
        swap_free(&global_swap_table, p->swap_index);
    }
    free(p);
}