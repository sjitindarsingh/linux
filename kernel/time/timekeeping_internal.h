/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TIMEKEEPING_INTERNAL_H
#define _TIMEKEEPING_INTERNAL_H
/*
 * timekeeping debug functions
 */
#include <linux/clocksource.h>
#include <linux/time.h>

#ifdef CONFIG_DEBUG_FS
extern void tk_debug_account_sleep_time(struct timespec64 *t);
#else
#define tk_debug_account_sleep_time(x)
#endif

static inline u64 clocksource_delta(u64 now, u64 last, u64 mask)
{
	u64 ret = (now - last) & mask;

	/*
	 * Prevent time going backwards by checking the MSB of mask in
	 * the result. If set, return 0.
	 */
	if (ret & ~(mask >> 1)) {
		pr_emerg("now: 0x%.16llx last: 0x%.16llx mask 0x%.16llx\n", now, last, mask);
		//pr_emerg("%d ret & ~(mask >> 1)!!!\n%ld\n\n", smp_processor_id(), (signed long) ret);
	}
	return ret;
}

#endif /* _TIMEKEEPING_INTERNAL_H */
