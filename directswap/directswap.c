#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/directswap.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/swapfile.h>
#include <linux/frontswap.h>
#include <linux/swap_cgroup.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/shmem_fs.h>

#include <asm/barrier.h>


bool __direct_swap_enabled = false;
EXPORT_SYMBOL(__direct_swap_enabled);

bool __partition_is_direct_swap[32];
EXPORT_SYMBOL(__partition_is_direct_swap);

//int __direct_swap_type = -1;
//EXPORT_SYMBOL(__direct_swap_type);

static struct swap_info_struct *alloc_swap_info_with_type(int type);
static void enable_swap_info(struct swap_info_struct *p, int prio,
				unsigned char *swap_map,
				struct swap_cluster_info *cluster_info,
				unsigned long *frontswap_map);
static void setup_swap_info(struct swap_info_struct *p, int prio,
			    unsigned char *swap_map,
			    struct swap_cluster_info *cluster_info);
static int setup_swap_map_and_extents(struct swap_info_struct *p,
					unsigned char *swap_map,
					struct swap_cluster_info *cluster_info,
					unsigned long maxpages);
static void inc_cluster_info_page(struct swap_info_struct *p,
	struct swap_cluster_info *cluster_info, unsigned long page_nr);

const uint64_t base_addr = ((uint64_t)1 << SWAP_AREA_SHIFT);

atomic_t num_kfifos_free_fail = ATOMIC_INIT(0);
EXPORT_SYMBOL(num_kfifos_free_fail);

struct allocator_page_queues *queues_allocator = NULL;
EXPORT_SYMBOL(queues_allocator);

struct free_idx_queue *global_fq = NULL;
EXPORT_SYMBOL(global_fq);

pgoff_t raddr2offset(uint64_t raddr) {
  return (raddr & (((uint64_t)1 << SWAP_AREA_SHIFT) - 1)) >> PAGE_SHIFT;
}
EXPORT_SYMBOL(raddr2offset);

uint64_t offset2raddr(pgoff_t offset) {
  return (offset << PAGE_SHIFT) + base_addr;
}
EXPORT_SYMBOL(offset2raddr);



SYSCALL_DEFINE1(set_direct_swap_enabled, const char __user *, specialfile)
{
	int i, j;
	struct allocator_page_queue *q;
	for(i = 0;i < MAX_SWAPFILES; ++i) {
		__partition_is_direct_swap[i] = false;
	}
	//__partition_is_direct_swap[MAX_SWAPFILES] = true;
	queues_allocator = (struct allocator_page_queues *)vzalloc(sizeof(struct allocator_page_queues));
	for(i = 0;i < NUM_KFIFOS_ALLOC; ++i) {
    	q = &queues_allocator->queues[i];
    	q->num = q->begin = q->end = 0;
		spin_lock_init(&q->q_lock);
  	}



 	__direct_swap_enabled = 1;
    printk("DirectSwap enabled successfully.");
 	return 0;

bad_set:
	return -1;
}

SYSCALL_DEFINE1(set_direct_swap_disabled, const char __user *, specialfile)
{

	vfree(queues_allocator);
	__direct_swap_enabled = 0;
	
	return 0;
}

static inline void direct_swap_range_alloc(struct swap_info_struct *si, unsigned int nr_entries) {
	si->inuse_pages += nr_entries;
}

int direct_swap_alloc_remote_pages(int n_goal, unsigned long entry_size, swp_entry_t swp_entries[]) {
	uint32_t nproc = raw_smp_processor_id();
	int count, type;
	uint64_t offset;
	struct swap_info_struct *si = NULL;
	uint32_t idx;
	uint64_t remote_addr;

	count = 0;
	
	/*Normal path*/
	for(; count < n_goal ; count++) {
		offset = pop_queue_allocator(nproc);
		/* Update corresponding swap_map entry*/
		type = core_id_to_swap_type[nproc];
		swp_entries[count] = swp_entry(type, offset);

		si = swap_info[type];
		if(unlikely(!si)) {
			printk(KERN_ERR "[DirectSwap]: Invalid remote entry with type = %d.\n", type);
			break;
		}
		WRITE_ONCE(si->swap_map[offset], SWAP_HAS_CACHE);
		direct_swap_range_alloc(si, 1);
	}
	
	return count;
}

int direct_swap_free_remote_page(swp_entry_t entry) {
	uint32_t nproc = raw_smp_processor_id();
	int type = swp_type(entry);
	int count = 0;
	uint64_t offset = swp_offset(entry);

	if(!is_direct_swap_area(type)) {
		return 1;
	} else {
		push_queue_allocator(offset, nproc);
		return 0;
	}
}

static struct swap_info_struct *alloc_swap_info_with_type(int type) {
	struct swap_info_struct *p;
	//struct swap_info_struct *defer = NULL;
	int i;

	p = kvzalloc(struct_size(p, avail_lists, nr_node_ids), GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	spin_lock(&swap_lock);
	if (type >= MAX_SWAPFILES) {
		spin_unlock(&swap_lock);
		percpu_ref_exit(&p->users);
		kvfree(p);
		return ERR_PTR(-EPERM);
	}
	p->type = type;
	smp_store_release(&swap_info[type], p);
	p->swap_extent_root = RB_ROOT;
	plist_node_init(&p->list, 0);
	for_each_node(i)
		plist_node_init(&p->avail_lists[i], 0);
	p->flags = SWP_USED;
	spin_unlock(&swap_lock);
	
	spin_lock_init(&p->lock);
	spin_lock_init(&p->cont_lock);
	init_completion(&p->comp);

	return p;
}

static void enable_swap_info(struct swap_info_struct *p, int prio,
				unsigned char *swap_map,
				struct swap_cluster_info *cluster_info,
				unsigned long *frontswap_map)
{
	frontswap_init(p->type, frontswap_map);
	spin_lock(&swap_lock);
	spin_lock(&p->lock);
	setup_swap_info(p, prio, swap_map, cluster_info);
	spin_unlock(&p->lock);
	spin_unlock(&swap_lock);
	/*
	 * Finished initializing swap device, now it's safe to reference it.
	 */
	//percpu_ref_resurrect(&p->users);
	spin_lock(&swap_lock);
	spin_lock(&p->lock);

	/*
		add necessary steps of _enable_swap_info(p);
	*/
	p->flags |= SWP_WRITEOK;
	atomic_long_add(p->pages, &nr_swap_pages);
	total_swap_pages += p->pages;

	spin_unlock(&p->lock);
	spin_unlock(&swap_lock);
}

static int setup_swap_map_and_extents(struct swap_info_struct *p,
					unsigned char *swap_map,
					struct swap_cluster_info *cluster_info,
					unsigned long maxpages)
{
	unsigned int j, k;
	unsigned int nr_good_pages;
	int nr_extents;
	unsigned long nr_clusters = DIV_ROUND_UP(maxpages, SWAPFILE_CLUSTER);
	unsigned long col = p->cluster_next / SWAPFILE_CLUSTER % SWAP_CLUSTER_COLS;
	unsigned long i, idx;

	nr_good_pages = maxpages - 1;	/* omit header page */

	if (nr_good_pages) {
		swap_map[0] = SWAP_MAP_BAD;
		/*
		 * Not mark the cluster free yet, no list
		 * operation involved
		 */
		p->max = maxpages;
		p->pages = nr_good_pages;
		nr_extents = 10240; //setup_swap_extents(p, span);
		if (nr_extents < 0)
			return nr_extents;
		nr_good_pages = p->pages;
	}
	if (!nr_good_pages) {
		pr_warn("Empty swap-file\n");
		return -EINVAL;
	}

	if (!cluster_info)
		return nr_extents;

	return nr_extents;
}

static void setup_swap_info(struct swap_info_struct *p, int prio,
			    unsigned char *swap_map,
			    struct swap_cluster_info *cluster_info)
{
	if (prio >= 0)
		p->prio = prio;
	else
		p->prio = -999;
	/*
	 * the plist prio is negated because plist ordering is
	 * low-to-high, while swap ordering is high-to-low
	 */
	p->list.prio = -p->prio;
	p->swap_map = swap_map;
	p->cluster_info = cluster_info;
}

inline bool is_direct_swap_area(int type)
{
    return __partition_is_direct_swap[type];
}
EXPORT_SYMBOL(is_direct_swap_area);

bool refill_allocator(uint64_t *allocator) {
	int first_chunk_size;
	spin_lock(&global_fq->lock);
    if(global_fq->num < REFILL_BATCH_SIZE) {
		pr_err("no free entries...");
	}
	first_chunk_size = min(REFILL_BATCH_SIZE, global_fq->capacity - global_fq->begin);
	memcpy(allocator, global_fq->pages + global_fq->begin, first_chunk_size * sizeof(uint64_t));
	if(unlikely(first_chunk_size < REFILL_BATCH_SIZE)) {
		memcpy(allocator + first_chunk_size, global_fq->pages, (REFILL_BATCH_SIZE - first_chunk_size) * sizeof(uint64_t));
	}
	global_fq->begin = (global_fq->begin + REFILL_BATCH_SIZE) % global_fq->capacity;
	global_fq->num -= REFILL_BATCH_SIZE;
	spin_unlock(&global_fq->lock);
    return true;
}

bool release_allocator(uint64_t *allocator) {
    int first_chunk_size;
	spin_lock(&global_fq->lock);
    if(global_fq->capacity - global_fq->num < REFILL_BATCH_SIZE) {
		pr_err("no space to hold free entries...");
	}
	first_chunk_size = min(REFILL_BATCH_SIZE, global_fq->capacity - global_fq->end);
	memcpy(global_fq->pages + global_fq->end, allocator, first_chunk_size * sizeof(uint64_t));
	if(unlikely(first_chunk_size < REFILL_BATCH_SIZE)) {
		memcpy(global_fq->pages, allocator + first_chunk_size, (REFILL_BATCH_SIZE - first_chunk_size) * sizeof(uint64_t));
	}
	global_fq->end = (global_fq->end + REFILL_BATCH_SIZE) % global_fq->capacity;
	global_fq->num += REFILL_BATCH_SIZE;
	spin_unlock(&global_fq->lock);
    return true;
}

uint64_t pop_queue_allocator(uint32_t id) {
    uint64_t ret = 0;
    struct allocator_page_queue *q = &(queues_allocator->queues[id]);
	spin_lock(&q->q_lock);
	if(q->num == 0) {
		refill_allocator(q->pages);
		q->begin = 1;
		q->end = REFILL_BATCH_SIZE-1;
		q->num = REFILL_BATCH_SIZE-1;
		ret = q->pages[0];
	} else {
		ret = q->pages[q->begin];
		q->begin = (q->begin + 1) % ALLOCATE_BUFFER_SIZE;
		q->num -= 1;
	}
	spin_unlock(&q->q_lock);
    return ret;
}


int push_queue_allocator(uint64_t offset, uint32_t id) {
    struct allocator_page_queue *q = &(queues_allocator->queues[id]);
	spin_lock(&q->q_lock);
    if(q->num == ALLOCATE_BUFFER_SIZE) {
		release_allocator(q->pages);
		q->begin = REFILL_BATCH_SIZE;
		q->end = 1;
		q->pages[0] = offset;
		q->num = REFILL_BATCH_SIZE+1;
	} else {
		q->pages[q->end] = offset;
		q->end = (q->end + 1) % ALLOCATE_BUFFER_SIZE;
		q->num += 1;
	}
	spin_unlock(&q->q_lock);
    return 0;
}