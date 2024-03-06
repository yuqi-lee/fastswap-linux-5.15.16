#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/directswap.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/swap.h>

bool __direct_swap_enabled = true;
EXPORT_SYMBOL(__direct_swap_enabled);


SYSCALL_DEFINE1(set_direct_swap_enabled, int, enable)
{
 	__direct_swap_enabled = enable;
    printk("DirectSwap enable: %s\n", enable ? "enabled" : "disabled");
 	return 0;
}

int direct_swap_alloc_remote_pages(int n_goal, unsigned long entry_size, swp_entry_t swp_entries[]) {
	u32 nproc = raw_smp_processor_id();
	int count;
	//u32 total_cpus = num_online_cpus();
	//u32 idx = (nproc * NUM_KFIFOS_ALLOC) / total_cpus;
	if(kfifo_len(fifos_alloc + nproc) >= n_goal) {
		for(count = 0; count < n_goal ; count++) {
			kfifo_out(fifos_alloc + nproc, swp_entries + count, sizeof(swp_entry_t));
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
		kfifo_in(fifos_free + nproc, &entry, sizeof(swp_entry_t));
		return 0;
	}
}