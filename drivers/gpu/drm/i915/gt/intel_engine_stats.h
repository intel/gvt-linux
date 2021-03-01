/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2020 Intel Corporation
 */

#ifndef __INTEL_ENGINE_STATS_H__
#define __INTEL_ENGINE_STATS_H__

#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/seqlock.h>

#include "i915_gem.h" /* GEM_BUG_ON */
#include "intel_engine.h"

static inline void intel_engine_context_in(struct intel_engine_cs *engine)
{
	if (engine->stats.active++)
		return;

	smp_wmb(); /* pairs with intel_engine_get_busy_time() */
	WRITE_ONCE(engine->stats.start, ktime_get());
}

static inline void intel_engine_context_out(struct intel_engine_cs *engine)
{
	ktime_t total;

	GEM_BUG_ON(!engine->stats.active);
	if (--engine->stats.active)
		return;

	total = ktime_sub(ktime_get(), engine->stats.start);
	total = ktime_add(engine->stats.total, total);

	WRITE_ONCE(engine->stats.start, 0);
	smp_wmb(); /* pairs with intel_engine_get_busy_time() */
	engine->stats.total = total;
}

#endif /* __INTEL_ENGINE_STATS_H__ */
