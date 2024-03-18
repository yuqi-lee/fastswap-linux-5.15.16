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

#include <asm/barrier.h>

bool __direct_swap_enabled = false;
EXPORT_SYMBOL(__direct_swap_enabled);

struct kfifo kfifos_alloc[NUM_KFIFOS_ALLOC];
EXPORT_SYMBOL(kfifos_alloc);
struct kfifo kfifos_free[NUM_KFIFOS_FREE];
EXPORT_SYMBOL(kfifos_free);

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


	for(i = 0; i < NUM_KFIFOS_ALLOC; i++) {
		ret = kfifo_alloc(kfifos_alloc + i, sizeof(swp_entry)*PAGES_PER_KFIFO_ALLOC, GFP_KERNEL);
		if(unlikely(ret)) {
			printk("Alloc memory for kfifos_alloc failed with error code %d.", ret);
			return ret;
		}
	}
	for(i = 0; i < NUM_KFIFOS_FREE; i++) {
		ret = kfifo_alloc(kfifos_free + i, sizeof(swp_entry)*PAGES_PER_KFIFO_FREE, GFP_KERNEL);
		if(unlikely(ret)) {
			printk("Alloc memory for kfifos_free failed with error code %d.", ret);
			return ret;
		}
	}

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
	for(i = 0; i < NUM_KFIFOS_ALLOC; i++) {
		kfifo_free(kfifos_alloc + i);
	}
	for(i = 0; i < NUM_KFIFOS_FREE; i++) {
		kfifo_free(kfifos_free + i);
	}
	for(i = 0; i < NUM_REMOTE_SWAP_AREA; i++) {
		type = MAX_SWAPFILES - i - 1;
		exit_swap_address_space(type);
	}
	
	vfree(p->swap_map);
	kvfree(p->cluster_info);
	kvfree(p->frontswap_map);

	__direct_swap_enabled = 0;
	
	return 0;
}

int direct_swap_alloc_remote_pages(int n_goal, unsigned long entry_size, swp_entry_t swp_entries[]) {
	u32 nproc = raw_smp_processor_id();
	int count;
	//u32 total_cpus = num_online_cpus();
	//u32 idx = (nproc * NUM_KFIFOS_ALLOC) / total_cpus;
	if(kfifo_len(kfifos_alloc + nproc) >= n_goal) {
		for(count = 0; count < n_goal ; count++) {
			kfifo_out(kfifos_alloc + nproc, swp_entries + count, sizeof(swp_entry_t));
		}
		return count;
	}
	return 0;
}

int direct_swap_free_remote_page(swp_entry_t entry) {
	u32 nproc = raw_smp_processor_id();
	int type = swp_type(entry);

	if(type < MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA) {
		return 1;
	} else {
		kfifo_in(kfifos_free + nproc, &entry, sizeof(swp_entry_t));
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
	//_enable_swap_info(p);
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
    return type >= MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA;
}
EXPORT_SYMBOL(is_direct_swap_area);

inline bool is_direct_swap_area_with_entry(swp_entry_t entry)
{
    return swp_type(entry) >= MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA;
}
EXPORT_SYMBOL(is_direct_swap_area_with_entry);

inline int remote_area_id(int type)
{
    return MAX_SWAPFILES - NUM_REMOTE_SWAP_AREA - type;
}
EXPORT_SYMBOL(remote_area_id);