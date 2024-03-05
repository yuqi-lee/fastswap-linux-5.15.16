/*
* [DirectSwap] directswap.h 
*/

#ifndef _LINUX_DIRECTSWAP_H
#define _LINUX_DIRECTSWAP_H

#include <linux/swap.h>
#include <linux/atomic.h>

extern bool __direct_swap_enabled;

static inline bool direct_swap_enabled(void)
{
    return __direct_swap_enabled;
}

static inline void set_direct_swap_enabled(bool value)
{
    __direct_swap_enabled = value;
}

#endif /* _LINUX_DIRECTSWAP_H */