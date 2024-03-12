/*
* [DirectSwap] directswap.h 
*/

#ifndef _LINUX_DIRECTSWAP_H
#define _LINUX_DIRECTSWAP_H

#include <linux/swap.h>
#include <linux/atomic.h>
#include <linux/kfifo.h>

#define NUM_REMOTE_SWAP_AREA 1

#define NUM_KFIFOS_ALLOC 64
#define PAGES_PER_KFIFO_ALLOC 256
#define NUM_KFIFOS_FREE 64
#define PAGES_PER_KFIFO_FREE 1024

extern bool __direct_swap_enabled;

extern struct kfifo kfifos_alloc[NUM_KFIFOS_ALLOC];
extern struct kfifo kfifos_free[NUM_KFIFOS_FREE];

int direct_swap_alloc_remote_pages(int n_goal, unsigned long entry_size, swp_entry_t swp_entries[]);
int direct_swap_free_remote_page(swp_entry_t entry);


typedef struct {
    unsigned long val;
} remote_address_t;


//DEFINE_KFIFO(kfifos_alloc[NUM_KFIFOS_ALLOC], swp_entry_t, PAGES_PER_KFIFO_ALLOC);
//DEFINE_KFIFO(kfifos_free[NUM_KFIFOS_FREE], swp_entry_t, PAGES_PER_KFIFO_FREE);

static inline bool direct_swap_enabled(void)
{
    return __direct_swap_enabled;
}

static inline bool is_direct_swap_area(int type)
{
    return type >= MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA;
}

static inline int remote_area_id(int type)
{
    return MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA - type;
}

#endif /* _LINUX_DIRECTSWAP_H */
