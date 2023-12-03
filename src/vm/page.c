#include "vm/page.h"
#include "threads/malloc.h"
#include <debug.h>

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
    // TODO: free resources

    switch (p->location) {
    case IN_FILESYS:
        break;
    case SWAP:
        break;
    case FRAME:
        break;
    case ZERO:
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
