#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/directswap.h>

SYSCALL_DEFINE1(set_direct_swap_enabled, int, enable)
{
 	set_direct_swap_enabled(enable);
    printk("DirectSwap enable: %s\n", enable ? "enabled" : "disabled");
 	return 0;
}