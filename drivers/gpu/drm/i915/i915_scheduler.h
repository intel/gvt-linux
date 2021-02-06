/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2018 Intel Corporation
 */

#ifndef _I915_SCHEDULER_H_
#define _I915_SCHEDULER_H_

#include <linux/bitops.h>
#include <linux/list.h>
#include <linux/kernel.h>

#include "i915_scheduler_types.h"
#include "i915_request.h"

struct drm_printer;
struct intel_engine_cs;

#define SCHED_TRACE(se, fmt, ...) do {					\
	const struct i915_sched *se__ __maybe_unused = (se);		\
	GEM_TRACE("%s sched:%s: " fmt,					\
		  dev_name(se__->dbg.dev), se__->dbg.name,		\
		  ##__VA_ARGS__);					\
} while (0)

#define priolist_for_each_request(it, plist) \
	list_for_each_entry(it, &(plist)->requests, sched.link)

#define priolist_for_each_request_consume(it, n, plist) \
	list_for_each_entry_safe(it, n, &(plist)->requests, sched.link)

void i915_sched_node_init(struct i915_sched_node *node);
void i915_sched_node_reinit(struct i915_sched_node *node);

bool __i915_sched_node_add_dependency(struct i915_sched_node *node,
				      struct i915_sched_node *signal,
				      struct i915_dependency *dep,
				      unsigned long flags);

int i915_sched_node_add_dependency(struct i915_sched_node *node,
				   struct i915_sched_node *signal,
				   unsigned long flags);

void i915_sched_node_retire(struct i915_sched_node *node);

void i915_sched_init(struct i915_sched *se,
		     struct device *dev,
		     const char *name,
		     unsigned long mask,
		     unsigned int subclass);
void i915_sched_park(struct i915_sched *se);
void i915_sched_fini(struct i915_sched *se);

void i915_request_set_priority(struct i915_request *request, int prio);

void i915_request_enqueue(struct i915_request *request);

struct i915_request *
__i915_sched_rewind_requests(struct intel_engine_cs *engine);
void __i915_sched_defer_request(struct intel_engine_cs *engine,
				struct i915_request *request);

bool __i915_sched_suspend_request(struct intel_engine_cs *engine,
				  struct i915_request *rq);
void __i915_sched_resume_request(struct intel_engine_cs *engine,
				 struct i915_request *request);

bool i915_sched_suspend_request(struct intel_engine_cs *engine,
				struct i915_request *request);
void i915_sched_resume_request(struct intel_engine_cs *engine,
			       struct i915_request *rq);

void __i915_sched_cancel_queue(struct i915_sched *se);

void __i915_priolist_free(struct i915_priolist *p);
static inline void i915_priolist_free(struct i915_priolist *p)
{
	if (p->priority != I915_PRIORITY_NORMAL)
		__i915_priolist_free(p);
}

static inline bool i915_sched_is_idle(const struct i915_sched *se)
{
	return RB_EMPTY_ROOT(&se->queue.rb_root);
}

static inline bool
i915_sched_is_last_request(const struct i915_sched *se,
			   const struct i915_request *rq)
{
	return list_is_last_rcu(&rq->sched.link, &se->requests);
}

void i915_request_show_with_schedule(struct drm_printer *m,
				     const struct i915_request *rq,
				     const char *prefix,
				     int indent);

#endif /* _I915_SCHEDULER_H_ */
