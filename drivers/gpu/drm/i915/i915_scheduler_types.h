/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2018 Intel Corporation
 */

#ifndef _I915_SCHEDULER_TYPES_H_
#define _I915_SCHEDULER_TYPES_H_

#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/workqueue.h>

#include "i915_priolist_types.h"

struct drm_printer;
struct i915_request;

/**
 * struct i915_sched - funnels requests towards hardware
 *
 * The struct i915_sched captures all the requests as they become ready
 * to execute (on waking the i915_request.submit fence) puts them into
 * a queue where they may be reordered according to priority and then
 * wakes the backend tasklet to feed the queue to HW.
 */
struct i915_sched {
	spinlock_t lock; /* protects the scheduling lists and queue */

	unsigned long mask; /* available scheduling channels */

	/*
	 * Pass the request to the submission backend (e.g. directly into
	 * the legacy ringbuffer, or to the end of an execlist, or to the GuC).
	 *
	 * This is called from an atomic context with irqs disabled; must
	 * be irq safe.
	 */
	void (*submit_request)(struct i915_request *rq);

	struct i915_request *(*active_request)(const struct i915_sched *se);

	void (*show)(struct drm_printer *m,
		     struct i915_sched *se,
		     void (*show_request)(struct drm_printer *m,
					  const struct i915_request *rq,
					  const char *prefix,
					  int indent),
		     unsigned int max);

	struct list_head requests; /* active request, on HW */
	struct list_head hold; /* ready requests, but on hold */

	/**
	 * @queue: queue of requests, in priority lists
	 *
	 * During request construction, we build a list of fence dependencies
	 * that must be completed before the fence is executed. Then when the
	 * request is committed, it waits for all of those fences before it is
	 * submitted to the scheduler.
	 *
	 * The scheduler only sees requests that are ready to be executed.
	 * However, the number that we may execute at any one time may be
	 * limited, and so we store them in the @queue. This queue is sorted
	 * in execution order, such that when the backend may submit more
	 * requests to the HW, it can fill the HW submission ports from the
	 * head of the queue. It also allows the backends to inspect the head
	 * of the queue against the currently active requests to see if
	 * we need to preempt the current execution in order to run higher
	 * priority requests from the queue.
	 *
	 * In the simplest cases where the HW can consume everything, the
	 * @queue is only used to transfer requests from the scheduler
	 * frontend to the back.
	 */
	struct rb_root_cached queue;

	/**
	 * @tasklet: softirq tasklet for bottom half
	 *
	 * The tasklet is responsible for transferring the priority queue
	 * to HW, and for handling responses from HW.
	 */
	struct tasklet_struct tasklet;

	/* Inter-engine scheduling delegate */
	struct i915_sched_ipi {
		struct i915_request *list;
		struct work_struct work;
	} ipi;

	/**
	 * @default_priolist: priority list for I915_PRIORITY_NORMAL
	 */
	struct i915_priolist default_priolist;

	/**
	 * @no_priolist: priority lists disabled
	 */
	bool no_priolist;

	/* Pretty device names for debug messages */
	struct {
		struct device *dev;
		const char *name;
	} dbg;
};

struct i915_sched_attr {
	/**
	 * @priority: execution and service priority
	 *
	 * All clients are equal, but some are more equal than others!
	 *
	 * Requests from a context with a greater (more positive) value of
	 * @priority will be executed before those with a lower @priority
	 * value, forming a simple QoS.
	 *
	 * The &drm_i915_private.kernel_context is assigned the lowest priority.
	 */
	int priority;
};

/*
 * "People assume that time is a strict progression of cause to effect, but
 * actually, from a nonlinear, non-subjective viewpoint, it's more like a big
 * ball of wibbly-wobbly, timey-wimey ... stuff." -The Doctor, 2015
 *
 * Requests exist in a complex web of interdependencies. Each request
 * has to wait for some other request to complete before it is ready to be run
 * (e.g. we have to wait until the pixels have been rendering into a texture
 * before we can copy from it). We track the readiness of a request in terms
 * of fences, but we also need to keep the dependency tree for the lifetime
 * of the request (beyond the life of an individual fence). We use the tree
 * at various points to reorder the requests whilst keeping the requests
 * in order with respect to their various dependencies.
 *
 * There is no active component to the "scheduler". As we know the dependency
 * DAG of each request, we are able to insert it into a sorted queue when it
 * is ready, and are able to reorder its portion of the graph to accommodate
 * dynamic priority changes.
 *
 * Ok, there is now one active element to the "scheduler" in the backends.
 * We let a new context run for a small amount of time before re-evaluating
 * the run order. As we re-evaluate, we maintain the strict ordering of
 * dependencies, but attempt to rotate the active contexts (the current context
 * is put to the back of its priority queue, then reshuffling its dependents).
 * This provides minimal timeslicing and prevents a userspace hog (e.g.
 * something waiting on a user semaphore [VkEvent]) from denying service to
 * others.
 */
struct i915_sched_node {
	spinlock_t lock; /* protect the lists */

	struct list_head signalers_list; /* those before us, we depend upon */
	struct list_head waiters_list; /* those after us, they depend upon us */
	struct list_head link; /* guarded by i915_sched.lock */
	struct i915_sched_stack {
		/* Branch memoization used during depth-first search */
		struct i915_request *prev;
		struct list_head *pos;
	} dfs; /* guarded by i915_sched.lock */
	struct i915_sched_attr attr;
	unsigned long flags;
#define I915_SCHED_HAS_EXTERNAL_CHAIN	BIT(0)
	unsigned long semaphores;

	/* handle being scheduled for PI from outside of our active.lock */
	struct i915_request *ipi_link;
	int ipi_priority;
};

struct i915_dependency {
	struct i915_sched_node *signaler;
	struct i915_sched_node *waiter;
	struct list_head signal_link;
	struct list_head wait_link;
	struct rcu_head rcu;
	unsigned long flags;
#define I915_DEPENDENCY_ALLOC		BIT(0)
#define I915_DEPENDENCY_EXTERNAL	BIT(1)
#define I915_DEPENDENCY_WEAK		BIT(2)
};

#define for_each_waiter(p__, rq__) \
	list_for_each_entry_lockless(p__, \
				     &(rq__)->sched.waiters_list, \
				     wait_link)

#define for_each_signaler(p__, rq__) \
	list_for_each_entry_rcu(p__, \
				&(rq__)->sched.signalers_list, \
				signal_link)

#endif /* _I915_SCHEDULER_TYPES_H_ */
