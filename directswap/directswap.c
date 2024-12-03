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

#define ALLOCATOR_FILE "/dev/shm/allocator_page_queue"
#define DEALLOCATOR_FILE "/dev/shm/deallocator_page_queue"

bool __direct_swap_enabled = false;
EXPORT_SYMBOL(__direct_swap_enabled);

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

struct allocator_page_queues *queues_allocator;
EXPORT_SYMBOL(queues_allocator);
struct deallocator_page_queues *queues_deallocator;
EXPORT_SYMBOL(queues_deallocator);

pgoff_t raddr2offset(uint64_t raddr) {
  return (raddr & (((uint64_t)1 << SWAP_AREA_SHIFT) - 1)) >> PAGE_SHIFT;
}
EXPORT_SYMBOL(raddr2offset);

uint64_t offset2raddr(pgoff_t offset) {
  return (offset << PAGE_SHIFT) + base_addr;
}
EXPORT_SYMBOL(offset2raddr);

int allocator_page_queue_init(void) {
    struct path path_;
    struct address_space *addr_space_;
    struct page *page_;
    struct page **pages_ = NULL;
    void **slot_;
    struct radix_tree_iter iter_;
    int i = 0;
    int ret;

    ret = kern_path(ALLOCATOR_FILE, LOOKUP_FOLLOW, &path_);
    if (ret != 0) {
        // handle error
        pr_err("debug: cannot find /allocator_page_queue_init with error code %d\n", ret);
        return -1;
    }

    addr_space_ = path_.dentry->d_inode->i_mapping;
    if(addr_space_ == NULL) {
        pr_err("cannot get address space\n");
        return -1;
    }
    pr_info("num of pages: %ld\n", addr_space_->nrpages);

    pages_ = (struct page **) kmalloc(sizeof(struct page *) * addr_space_->nrpages, GFP_KERNEL);
    if(pages_ == NULL) {
        pr_err("Bad alloc for pages_(struct page**)\n");
        return -1;
    }
    
    radix_tree_iter_init(&iter_, 0);
    radix_tree_for_each_slot(slot_, &addr_space_->i_pages, &iter_, 0) {
        page_ = radix_tree_deref_slot(slot_);
        // do something with page
        pages_[i] = page_;
        pr_info("%d page ptr: %p\n", i, pages_[i]);
        i++;
    }

    if(i != addr_space_->nrpages) {
        pr_info("i != nrpages\n");
    } else {
        pr_info("i == nrpages\n");
    }
    // return 0;

    queues_allocator = (struct allocator_page_queues *) vmap(pages_, addr_space_->nrpages, VM_MAP, PAGE_KERNEL);
    if(queues_allocator == NULL) {
        pr_err("Bad v-mapping for allocator_page_queue\n");
        kfree(pages_);
        return -1;
    }

    pr_info("allocator_page_queue address is %p\n", (void*)queues_allocator);

    kfree(pages_);
    return 0;
}

int deallocator_page_queue_init(void) {
    struct path path_;
    struct address_space *addr_space_;
    struct page *page_;
    struct page **pages_ = NULL;
    void **slot_;
    struct radix_tree_iter iter_;
    int i = 0;
    int ret;

    ret = kern_path(DEALLOCATOR_FILE, LOOKUP_FOLLOW, &path_);
    if (ret != 0) {
        // handle error
        pr_err("debug: cannot find /deallocator_page_queue_init with error code %d\n", ret);
        return -1;
    }

    addr_space_ = path_.dentry->d_inode->i_mapping;
    if(addr_space_ == NULL) {
        pr_err("cannot get address space\n");
        return -1;
    }
    pr_info("num of pages: %ld\n", addr_space_->nrpages);

    pages_ = (struct page **) kmalloc(sizeof(struct page *) * addr_space_->nrpages, GFP_KERNEL);
    if(pages_ == NULL) {
        pr_err("Bad alloc for pages_(struct page**)\n");
        return -1;
    }
    
    radix_tree_iter_init(&iter_, 0);
    radix_tree_for_each_slot(slot_, &addr_space_->i_pages, &iter_, 0) {
        page_ = radix_tree_deref_slot(slot_);
        // do something with page
        pages_[i] = page_;
        pr_info("%d page ptr: %p\n", i, pages_[i]);
        i++;
    }

    if(i != addr_space_->nrpages) {
        pr_info("i != nrpages\n");
    } else {
        pr_info("i == nrpages\n");
    }
    // return 0;

    queues_deallocator = (struct deallocator_page_queues *) vmap(pages_, addr_space_->nrpages, VM_MAP, PAGE_KERNEL);
    if(queues_deallocator == NULL) {
        pr_err("Bad v-mapping for deallocator_page_queue\n");
        kfree(pages_);
        return -1;
    }

    pr_info("deallocator_page_queue address is %p\n", (void*)queues_deallocator);

    kfree(pages_);
    return 0;
}


SYSCALL_DEFINE1(set_direct_swap_enabled, const char __user *, specialfile)
{
	int ret, i, type, prio, error, nr_extents;
	struct swap_info_struct *p;
	struct filename *name;
	struct file *swap_file = NULL;
	struct swap_cluster_info *cluster_info = NULL;
	//struct address_space *mapping;
	unsigned long *frontswap_map = NULL;
	unsigned char *swap_map = NULL;
	int maxpages = NUM_PAGES_PER_REMOTE_SWAP_AREA;

	allocator_page_queue_init();
	deallocator_page_queue_init();


	p = alloc_swap_info_with_type(MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA);
	if (IS_ERR(p)) {
		printk(KERN_ERR "Allo swap info with specific type failed.");
		goto bad_set;
	}
		
	name = getname(specialfile);
	if (IS_ERR(name)) {
		error = PTR_ERR(name);
		name = NULL;
		printk(KERN_ERR "Name of swap file is invalid.");
		goto bad_set;
	}

	swap_file = file_open_name(name, O_RDWR|O_LARGEFILE, 0);
	if (IS_ERR(swap_file)) {
		error = PTR_ERR(swap_file);
		swap_file = NULL;
		printk(KERN_ERR "Open swap file failed.");
		goto bad_set;
	}
	
	p->swap_file = swap_file;
	prio = -1;
	swap_map = vzalloc(maxpages);
	if (!swap_map) {
		error = -ENOMEM;
		printk(KERN_ERR "Alloc space for swap_map failed.");
		goto bad_set;
	}

	error = swap_cgroup_swapon(p->type, maxpages);
	if (error) {
		printk(KERN_ERR "Setup swap control group failed.");
		goto bad_set;
	}

	nr_extents = setup_swap_map_and_extents(p, swap_map,
		cluster_info, maxpages);
	if (unlikely(nr_extents < 0)) {
		error = nr_extents;
		printk(KERN_ERR "Setup swap_map and extents failed.");
		goto bad_set;
	}

	if (IS_ENABLED(CONFIG_FRONTSWAP))
	frontswap_map = kvcalloc(BITS_TO_LONGS(maxpages),
					sizeof(long),
					GFP_KERNEL);

	for(i = 0; i < NUM_REMOTE_SWAP_AREA; i++) {
		type = MAX_SWAPFILES - i - 1;
		ret = init_swap_address_space(type, NUM_PAGES_PER_REMOTE_SWAP_AREA);
		if(unlikely(ret)) {
			printk("init remote swap address space failed with error code %d.", ret);
			return ret;
		}
	}

	enable_swap_info(p, prio, swap_map, cluster_info, frontswap_map);

 	__direct_swap_enabled = 1;
    printk("DirectSwap enabled successfully.");
 	return 0;

bad_set:
	return -1;
}

SYSCALL_DEFINE1(set_direct_swap_disabled, const char __user *, specialfile)
{
	struct swap_info_struct *p = swap_info[MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA];
	int i, type;
	if(!p) {
		printk("No DirectSwap area found.");
		return -1;
	}
	
	vfree(p->swap_map);
	kvfree(p->cluster_info);
	kvfree(p->frontswap_map);

	__direct_swap_enabled = 0;
	
	return 0;
}

static inline void direct_swap_range_alloc(struct swap_info_struct *si, unsigned int nr_entries) {
	si->inuse_pages += nr_entries;
	if (si->inuse_pages == si->pages) {
		del_from_avail_list(si);
	}
}

int direct_swap_alloc_remote_pages(int n_goal, unsigned long entry_size, swp_entry_t swp_entries[]) {
	uint32_t nproc = raw_smp_processor_id();
	int count, ret, type;
	uint64_t offset;
	uint32_t offset_fake;
	struct swap_info_struct *si = NULL;
	uint32_t idx;
	uint64_t remote_addr;

	count = 0;

	/*Reclaim CPU path*/
	if(likely(nproc >= FASTSWAP_RECLAIM_CPU && nproc < FASTSWAP_RECLAIM_CPU + FASTSWAP_RECLAIM_CPU_NUM)) {
		idx = nproc - FASTSWAP_RECLAIM_CPU;
		while(get_length_reclaim_allocator(idx) > 0 && count < n_goal) {
			remote_addr = pop_queue_reclaim_allocator(idx);
			/* Update corresponding swap_map entry*/
			type = MAX_SWAPFILES - 1;
			offset = raddr2offset(remote_addr);
			swp_entries[count] = swp_entry(type, offset);

			si = swap_info[type];
			if(unlikely(!si)) {
				printk(KERN_ERR "[DirectSwap]: Invalid remote entry with type = %d.\n", type);
				break;
			}
			//offset_fake = real_offset_to_fake_offset(offset);
			WRITE_ONCE(si->swap_map[offset], SWAP_HAS_CACHE);
			direct_swap_range_alloc(si, 1);
			count++;
		}
	}
	
	/*Normal path*/
	for(; count < n_goal ; count++) {
		while(get_length_allocator(nproc) == 0)	;
		remote_addr = pop_queue_allocator(nproc);
		/* Update corresponding swap_map entry*/
		type = MAX_SWAPFILES - 1;
		offset = raddr2offset(remote_addr);
		swp_entries[count] = swp_entry(type, offset);

		si = swap_info[type];
		if(unlikely(!si)) {
			printk(KERN_ERR "[DirectSwap]: Invalid remote entry with type = %d.\n", type);
			break;
		}
		//offset_fake = real_offset_to_fake_offset(offset);
		WRITE_ONCE(si->swap_map[offset], SWAP_HAS_CACHE);
		direct_swap_range_alloc(si, 1);
	}
	
	return count;
}

int direct_swap_free_remote_page(swp_entry_t entry) {
	uint32_t nproc = raw_smp_processor_id();
	int type = swp_type(entry);
	int count = 0;
	uint64_t remote_addr;

	if(type < MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA) {
		return 1;
	} else {
		while(get_length_deallocator(nproc) == DEALLOCATE_BUFFER_SIZE - 1 && count < 100) {
			count++;
		}
		if(count >= 100) {
			atomic_inc(&num_kfifos_free_fail);
			return 0;
		}
		remote_addr = offset2raddr(swp_offset(entry));
		push_queue_deallocator(remote_addr, nproc);
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

static u32 real_offset_to_fake_offset(u64 real_offset) 
{
	u32 fake_offset;
	fake_offset = (real_offset & ((1 << DIRECT_SWAP_AREA_SHIFT) - 1)) >> 12; //TODO: PAGE_SHIFT
	return fake_offset;
}

inline bool is_direct_swap_area(int type)
{
    return type >= MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA;
}
EXPORT_SYMBOL(is_direct_swap_area);

inline int remote_area_id(int type)
{
    return MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA - type;
}
EXPORT_SYMBOL(remote_area_id);

uint64_t get_length_allocator(uint32_t id) {
    struct allocator_page_queue *queue_allocator = &(queues_allocator->queues[id]);
    uint64_t begin = atomic64_read(&queue_allocator->begin);
    uint64_t end = atomic64_read(&queue_allocator->end);
    if (begin == end) {
        return 0;
    }
    if (end > begin) {
        return (end - begin);
    } else {
        return (ALLOCATE_BUFFER_SIZE - begin + end);
    }
}
EXPORT_SYMBOL(get_length_allocator);

uint64_t get_length_reclaim_allocator(uint32_t id) {
    struct reclaim_allocator_page_queue *queue_allocator = &(queues_allocator->reclaim_queues[id]);
    uint64_t begin = atomic64_read(&queue_allocator->begin);
    uint64_t end = atomic64_read(&queue_allocator->end);
    if (begin == end) {
        return 0;
    }
    if (end > begin) {
        return (end - begin);
    } else {
        return (RECLAIM_ALLOCATE_BUFFER_SIZE - begin + end);
    }
}
EXPORT_SYMBOL(get_length_reclaim_allocator);

uint64_t pop_queue_allocator(uint32_t id) {
    uint64_t ret = 0;
    uint64_t prev_begin;
	struct allocator_page_queue *queue_allocator = &(queues_allocator->queues[id]);
    while(get_length_allocator(id) == 0) ;
    prev_begin = atomic64_read(&queue_allocator->begin);
    atomic64_set(&queue_allocator->begin, (prev_begin + 1) % ALLOCATE_BUFFER_SIZE);
    while(atomic64_read(&queue_allocator->pages[prev_begin]) == 0) ;
    ret = atomic64_read(&queue_allocator->pages[prev_begin]);
    atomic64_set(&queue_allocator->pages[prev_begin], 0);
    //pr_info("pop_queue_allocator success.\n");
    return ret;
}
EXPORT_SYMBOL(pop_queue_allocator);

uint64_t pop_queue_reclaim_allocator(uint32_t id) {
    uint64_t ret = 0;
    uint64_t prev_begin;
	struct reclaim_allocator_page_queue *queue_allocator = &(queues_allocator->reclaim_queues[id]);
    while(get_length_reclaim_allocator(id) == 0) ;
    prev_begin = atomic64_read(&queue_allocator->begin);
    atomic64_set(&queue_allocator->begin, (prev_begin + 1) % RECLAIM_ALLOCATE_BUFFER_SIZE);
    while(atomic64_read(&queue_allocator->pages[prev_begin]) == 0) ;
    ret = atomic64_read(&queue_allocator->pages[prev_begin]);
    atomic64_set(&queue_allocator->pages[prev_begin], 0);
    //pr_info("pop_queue_allocator success.\n");
    return ret;
}
EXPORT_SYMBOL(pop_queue_reclaim_allocator);

int push_queue_allocator(uint64_t page_addr, uint32_t id) {
    return 0;
}
EXPORT_SYMBOL(push_queue_allocator);

uint64_t get_length_deallocator(uint32_t id) {
	struct deallocator_page_queue *queue_deallocator = &queues_deallocator->queues[id];
    uint64_t begin = atomic64_read(&queue_deallocator->begin);
    uint64_t end = atomic64_read(&queue_deallocator->end);
    if (begin == end) {
        return 0;
    }
    if (end > begin) {
        return (end - begin);
    } else {
        return (DEALLOCATE_BUFFER_SIZE - begin + end);
    }
}
EXPORT_SYMBOL(get_length_deallocator);


int push_queue_deallocator(uint64_t page_addr, uint32_t id) {
	struct deallocator_page_queue *queue_deallocator = &(queues_deallocator->queues[id]);
    int ret = 0;
    uint64_t prev_end = atomic64_read(&queue_deallocator->end);
    while(get_length_deallocator(id) >= DEALLOCATE_BUFFER_SIZE - 1) ;
    atomic64_set(&queue_deallocator->end, (prev_end + 1) % DEALLOCATE_BUFFER_SIZE);
    atomic64_set(&queue_deallocator->pages[prev_end], page_addr);
    return ret;
}
EXPORT_SYMBOL(push_queue_deallocator);