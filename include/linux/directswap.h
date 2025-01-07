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

#define ALLOCATE_BUFFER_SIZE (4 << 10) // 16 MB
#define RECLAIM_ALLOCATE_BUFFER_SIZE (16 << 10) // 64 MB
#define DEALLOCATE_BUFFER_SIZE (16 << 10) // 64 MB
#define SWAP_AREA_SHIFT 35
#define NUM_KFIFOS_ALLOC 48
#define PAGES_PER_KFIFO_ALLOC 256
#define NUM_KFIFOS_FREE 48
#define PAGES_PER_KFIFO_FREE 20480
#define PAGES_IN_RECLAIM_KFIFO 1024
#define DIRECT_SWAP_AREA_SHIFT 35 // 32GiB

/* Defined in directswap/directswap.c */
extern bool __direct_swap_enabled;
extern bool __partition_is_direct_swap[32];
//extern int __direct_swap_type;
extern atomic_t num_kfifos_free_fail;

extern inline bool is_direct_swap_area(int type);

int direct_swap_alloc_remote_pages(int n_goal, unsigned long entry_size, swp_entry_t swp_entries[]);
int direct_swap_free_remote_page(swp_entry_t entry);


typedef struct {
    unsigned long val;
} remote_address_t;

struct allocator_page_queue {
    atomic_t rkey;
    atomic64_t begin;
    atomic64_t end;
    atomic64_t pages[ALLOCATE_BUFFER_SIZE];
};

struct reclaim_allocator_page_queue {
    atomic64_t begin;
    atomic64_t end;
    atomic64_t pages[RECLAIM_ALLOCATE_BUFFER_SIZE];
};

struct deallocator_page_queue {
    atomic64_t begin;
    atomic64_t end;
    atomic64_t pages[DEALLOCATE_BUFFER_SIZE];
};

struct allocator_page_queues {
  struct allocator_page_queue queues[NUM_KFIFOS_ALLOC];
  //struct reclaim_allocator_page_queue reclaim_queues[FASTSWAP_RECLAIM_CPU_NUM];
};

struct deallocator_page_queues {
  struct deallocator_page_queue queues[NUM_KFIFOS_FREE];
};

extern struct allocator_page_queues *queues_allocator;
extern struct deallocator_page_queues *queues_deallocator;

static inline bool direct_swap_enabled(void)
{
    return __direct_swap_enabled;
}

extern uint64_t get_length_allocator(uint32_t id);
extern uint64_t pop_queue_allocator(uint32_t id);
extern int push_queue_allocator(uint64_t page_addr, uint32_t id);

extern uint64_t get_length_deallocator(uint32_t id);
extern uint64_t pop_queue_deallocator(uint32_t id);
extern int push_queue_deallocator(u64 page_addr, uint32_t id);

extern uint64_t get_length_reclaim_allocator(uint32_t id);
extern uint64_t pop_queue_reclaim_allocator(uint32_t id);
extern int push_queue_reclaim_allocator(uint64_t page_addr, uint32_t id);

extern pgoff_t raddr2offset(uint64_t raddr);
extern uint64_t offset2raddr(pgoff_t offset);

#endif /* _LINUX_DIRECTSWAP_H */
