#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/directswap.h>
#include <linux/printk.h>

bool __direct_swap_enabled = false;
EXPORT_SYMBOL(__direct_swap_enabled);

SYSCALL_DEFINE1(set_direct_swap_enabled, int, enable)
{
 	__direct_swap_enabled = enable;
    printk("DirectSwap enable: %s\n", enable ? "enabled" : "disabled");
 	return 0;
}