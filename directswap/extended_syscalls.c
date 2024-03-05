#include <linux/swap_stats.h>
#include <linux/syscalls.h>
#include <linux/printk.h>

SYSCALL_DEFINE0(set_direct_swap_enabled, int, enable)
{
 	set_direct_swap_enabled(enable);
    printk("DirectSwap enable: %s\n", enable ? "enabled" : "disabled");
 	return 0;
}