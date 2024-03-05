/*
* [DirectSwap] swap_stats.h - collect swap stats
*/

#ifndef _LINUX_SWAP_STATS_H
#define _LINUX_SWAP_STATS_H

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