/*
* [DirectSwap] directswap.h 
*/

#ifndef _LINUX_DIRECTSWAP_H
#define _LINUX_DIRECTSWAP_H

#include <linux/swap.h>
#include <linux/atomic.h>
#include <linux/kfifo.h>
#include <linux/atomic.h>

//#define FASTSWAP_RECLAIM_CPU 28
//#define FASTSWAP_RECLAIM_CPU_NUM 4

//#define NUM_REMOTE_SWAP_AREA 1
//#define NUM_PAGES_PER_REMOTE_SWAP_AREA (16 << 20)

// Originally defined in mm/swapfile.c
#define SWAPFILE_CLUSTER	256 // If huge page swapping is enabled, set to HPAGE_PMD_NR
#define SWAP_CLUSTER_INFO_COLS						\
	DIV_ROUND_UP(L1_CACHE_BYTES, sizeof(struct swap_cluster_info))
#define SWAP_CLUSTER_SPACE_COLS						\
	DIV_ROUND_UP(SWAP_ADDRESS_SPACE_PAGES, SWAPFILE_CLUSTER)
#define SWAP_CLUSTER_COLS						\
	max_t(unsigned int, SWAP_CLUSTER_INFO_COLS, SWAP_CLUSTER_SPACE_COLS)

#define ALLOCATE_BUFFER_SIZE (512UL) // 2 MB
#define	REFILL_BATCH_SIZE (ALLOCATE_BUFFER_SIZE/2)

#define NUM_KFIFOS_ALLOC 64
#define TOTAL_PAGES (8UL*1024*1024)


/* Defined in directswap/directswap.c */
extern bool __direct_swap_enabled;
extern bool __partition_is_direct_swap[32];


extern inline bool is_direct_swap_area(int type);

int direct_swap_alloc_remote_pages(int n_goal, unsigned long entry_size, swp_entry_t swp_entries[]);
int direct_swap_free_remote_page(swp_entry_t entry);
bool direct_swap_alloc_remote_page(swp_entry_t *entry);



struct allocator_page_queue {
    int begin;
    int end;
    int num;
    uint64_t pages[ALLOCATE_BUFFER_SIZE];
    spinlock_t q_lock;
};

struct allocator_page_queues {
  struct allocator_page_queue queues[NUM_KFIFOS_ALLOC];
};


struct free_idx_queue {
    int begin;
    int end;
    int num;
	  int capacity;
    uint64_t pages[TOTAL_PAGES];
    spinlock_t lock;
};

extern struct allocator_page_queues *queues_allocator;
extern struct free_idx_queue *global_fq;

static inline bool direct_swap_enabled(void)
{
    return __direct_swap_enabled;
}

extern uint64_t pop_queue_allocator(uint32_t id);
extern int push_queue_allocator(uint64_t page_addr, uint32_t id);


#endif /* _LINUX_DIRECTSWAP_H */
