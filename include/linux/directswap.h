/*
* [DirectSwap] directswap.h 
*/

#ifndef _LINUX_DIRECTSWAP_H
#define _LINUX_DIRECTSWAP_H

#include <linux/swap.h>
#include <linux/atomic.h>
#include <linux/kfifo.h>


#define NUM_REMOTE_SWAP_AREA 1
#define NUM_PAGES_PER_REMOTE_SWAP_AREA (10 << 20)
#define DIRECT_SWAP_PRIORITY -999

// Originally defined in mm/swapfile.c
#define SWAPFILE_CLUSTER	256 // If huge page swapping is enabled, set to HPAGE_PMD_NR
#define SWAP_CLUSTER_INFO_COLS						\
	DIV_ROUND_UP(L1_CACHE_BYTES, sizeof(struct swap_cluster_info))
#define SWAP_CLUSTER_SPACE_COLS						\
	DIV_ROUND_UP(SWAP_ADDRESS_SPACE_PAGES, SWAPFILE_CLUSTER)
#define SWAP_CLUSTER_COLS						\
	max_t(unsigned int, SWAP_CLUSTER_INFO_COLS, SWAP_CLUSTER_SPACE_COLS)

#define NUM_KFIFOS_ALLOC 64
#define PAGES_PER_KFIFO_ALLOC 256
#define NUM_KFIFOS_FREE 64
#define PAGES_PER_KFIFO_FREE 1024

/* Defined in directswap/directswap.c */
extern bool __direct_swap_enabled;
extern struct kfifo kfifos_alloc[NUM_KFIFOS_ALLOC];
extern struct kfifo kfifos_free[NUM_KFIFOS_FREE];
extern inline bool is_direct_swap_area(int type);
extern inline int remote_area_id(int type);

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

#endif /* _LINUX_DIRECTSWAP_H */
