#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/directswap.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/swap.h>
#include <linux/swapops.h>

bool __direct_swap_enabled = false;
EXPORT_SYMBOL(__direct_swap_enabled);

struct kfifo kfifos_alloc[NUM_KFIFOS_ALLOC];
EXPORT_SYMBOL(kfifos_alloc);
struct kfifo kfifos_free[NUM_KFIFOS_FREE];
EXPORT_SYMBOL(kfifos_free);

SYSCALL_DEFINE1(set_direct_swap_enabled, int, enable)
{
	int ret, i;
	if(enable) {
		for(i = 0; i < NUM_KFIFOS_ALLOC; i++) {
			ret = kfifo_alloc(kfifos_alloc + i, sizeof(swp_entry)*PAGES_PER_KFIFO_ALLOC, GFP_KERNEL);
			if(unlikely(ret)) {
				printk("Alloc memory for kfifos_alloc failed with error code %d.", ret);
			}
		}
		for(i = 0; i < NUM_KFIFOS_FREE; i++) {
			ret = kfifo_alloc(kfifos_free + i, sizeof(swp_entry)*PAGES_PER_KFIFO_FREE, GFP_KERNEL);
			if(unlikely(ret)) {
				printk("Alloc memory for kfifos_free failed with error code %d.", ret);
			}
		}
	} else {
		for(i = 0; i < NUM_KFIFOS_ALLOC; i++) {
			kfifo_free(kfifos_alloc + i);
		}
		for(i = 0; i < NUM_KFIFOS_FREE; i++) {
			kfifo_free(kfifos_free + i);
		}
	}

 	__direct_swap_enabled = enable;
    printk("DirectSwap enable: %s\n", enable ? "enabled" : "disabled");
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