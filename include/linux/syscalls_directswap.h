#ifndef _LINUX_SYSCALLS_DIRECTSWAP_H
#define _LINUX_SYSCALLS_DIRECTSWAP_H

asmlinkage long sys_set_direct_swap_enabled(const char __user *specialfile);
asmlinkage long sys_set_direct_swap_disabled(const char __user *specialfile);

#endif