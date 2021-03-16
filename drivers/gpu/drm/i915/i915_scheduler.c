/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2018 Intel Corporation
 */

#include <linux/mutex.h>

#include "gt/intel_ring.h"
#include "gt/intel_lrc_reg.h"

#include "i915_drv.h"
#include "i915_globals.h"
#include "i915_request.h"
#include "i915_scheduler.h"
#include "i915_utils.h"

static struct i915_global_scheduler {
	struct i915_global base;
	struct kmem_cache *slab_dependencies;
	struct kmem_cache *slab_priorities;
} global;

/*
 * Virtual engines complicate acquiring the engine timeline lock,
 * as their rq->engine pointer is not stable until under that
 * engine lock. The simple ploy we use is to take the lock then
 * check that the rq still belongs to the newly locked engine.
 */
#define lock_engine_irqsave(rq, flags) ({ \
	struct i915_request * const rq__ = (rq); \
	struct intel_engine_cs *engine__ = READ_ONCE(rq__->engine); \
\
	spin_lock_irqsave(&engine__->sched.lock, (flags)); \
	while (engine__ != READ_ONCE((rq__)->engine)) { \
		spin_unlock(&engine__->sched.lock); \
		engine__ = READ_ONCE(rq__->engine); \
		spin_lock(&engine__->sched.lock); \
	} \
\
	engine__; \
})

static struct i915_sched_node *node_get(struct i915_sched_node *node)
{
	i915_request_get(container_of(node, struct i915_request, sched));
	return node;
}

static void node_put(struct i915_sched_node *node)
{
	i915_request_put(container_of(node, struct i915_request, sched));
}

static inline int rq_prio(const struct i915_request *rq)
{
	return READ_ONCE(rq->sched.attr.priority);
}

static int ipi_get_prio(struct i915_request *rq)
{
	if (READ_ONCE(rq->sched.ipi_priority) == I915_PRIORITY_INVALID)
		return I915_PRIORITY_INVALID;

	return xchg(&rq->sched.ipi_priority, I915_PRIORITY_INVALID);
}

static void ipi_schedule(struct work_struct *wrk)
{
	struct i915_sched_ipi *ipi = container_of(wrk, typeof(*ipi), work);
	struct i915_request *rq = xchg(&ipi->list, NULL);

	do {
		struct i915_request *rn = xchg(&rq->sched.ipi_link, NULL);
		int prio;

		prio = ipi_get_prio(rq);

		/*
		 * For cross-engine scheduling to work we rely on one of two
		 * things:
		 *
		 * a) The requests are using dma-fence fences and so will not
		 * be scheduled until the previous engine is completed, and
		 * so we cannot cross back onto the original engine and end up
		 * queuing an earlier request after the first (due to the
		 * interrupted DFS).
		 *
		 * b) The requests are using semaphores and so may be already
		 * be in flight, in which case if we cross back onto the same
		 * engine, we will already have put the interrupted DFS into
		 * the priolist, and the continuation will now be queued
		 * afterwards [out-of-order]. However, since we are using
		 * semaphores in this case, we also perform yield on semaphore
		 * waits and so will reorder the requests back into the correct
		 * sequence. This occurrence (of promoting a request chain
		 * that crosses the engines using semaphores back unto itself)
		 * should be unlikely enough that it probably does not matter...
		 */
		local_bh_disable();
		i915_request_set_priority(rq, prio);
		local_bh_enable();

		i915_request_put(rq);
		rq = ptr_mask_bits(rn, 1);
	} while (rq);
}

static void init_ipi(struct i915_sched_ipi *ipi)
{
	INIT_WORK(&ipi->work, ipi_schedule);
	ipi->list = NULL;
}

static struct i915_request *
i915_sched_default_active_request(const struct i915_sched *se)
{
	struct i915_request *rq, *active = NULL;

	/*
	 * We assume the simplest in-order execution queue with no preemption,
	 * i.e. the order of se->erquests matches exactly the execution order
	 * of the HW.
	 */
	list_for_each_entry(rq, &se->requests, sched.link) {
		if (__i915_request_is_complete(rq))
			continue;

		if (__i915_request_has_started(rq))
			active = rq;

		break;
	}

	return active;
}

void i915_sched_init(struct i915_sched *se,
		     struct device *dev,
		     const char *name,
		     unsigned long mask,
		     unsigned int subclass)
{
	spin_lock_init(&se->lock);
	lockdep_set_subclass(&se->lock, subclass);
	mark_lock_used_irq(&se->lock);

	se->dbg.dev = dev;
	se->dbg.name = name;

	se->mask = mask;

	INIT_LIST_HEAD(&se->requests);
	INIT_LIST_HEAD(&se->hold);
	se->queue = RB_ROOT_CACHED;

	init_ipi(&se->ipi);

	se->submit_request = i915_request_enqueue;
	se->active_request = i915_sched_default_active_request;
}

void i915_sched_park(struct i915_sched *se)
{
	GEM_BUG_ON(!i915_sched_is_idle(se));
	se->no_priolist = false;
}

void i915_sched_fini(struct i915_sched *se)
{
	GEM_BUG_ON(!list_empty(&se->requests));

	tasklet_kill(&se->tasklet); /* flush the callback */
	i915_sched_park(se);
}

static void __ipi_add(struct i915_request *rq)
{
#define STUB ((struct i915_request *)1)
	struct i915_sched *se = i915_request_get_scheduler(rq);
	struct i915_request *first;

	if (!i915_request_get_rcu(rq))
		return;

	/*
	 * We only want to add the request once into the ipi.list (or else
	 * the chain will be broken). The worker must be guaranteed to run
	 * at least once for every call to ipi_add, but it is allowed to
	 * coalesce multiple ipi_add into a single pass using the final
	 * property value.
	 */
	if (__i915_request_is_complete(rq) ||
	    cmpxchg(&rq->sched.ipi_link, NULL, STUB)) { /* already queued */
		i915_request_put(rq);
		return;
	}

	/* Carefully insert ourselves into the head of the llist */
	first = READ_ONCE(se->ipi.list);
	do {
		rq->sched.ipi_link = ptr_pack_bits(first, 1, 1);
	} while (!try_cmpxchg(&se->ipi.list, &first, rq));

	if (!first)
		queue_work(system_unbound_wq, &se->ipi.work);
}

static const struct i915_request *
node_to_request(const struct i915_sched_node *node)
{
	return container_of(node, const struct i915_request, sched);
}

static inline bool node_signaled(const struct i915_sched_node *node)
{
	return i915_request_completed(node_to_request(node));
}

static inline struct i915_priolist *to_priolist(struct rb_node *rb)
{
	return rb_entry(rb, struct i915_priolist, node);
}

static void assert_priolists(struct i915_sched * const se)
{
	struct rb_node *rb;
	long last_prio;

	if (!IS_ENABLED(CONFIG_DRM_I915_DEBUG_GEM))
		return;

	GEM_BUG_ON(rb_first_cached(&se->queue) !=
		   rb_first(&se->queue.rb_root));

	last_prio = INT_MAX;
	for (rb = rb_first_cached(&se->queue); rb; rb = rb_next(rb)) {
		const struct i915_priolist *p = to_priolist(rb);

		GEM_BUG_ON(p->priority > last_prio);
		last_prio = p->priority;
	}
}

static struct list_head *
lookup_priolist(struct i915_sched *se, int prio)
{
	struct i915_priolist *p;
	struct rb_node **parent, *rb;
	bool first = true;

	lockdep_assert_held(&se->lock);
	assert_priolists(se);

	if (unlikely(se->no_priolist))
		prio = I915_PRIORITY_NORMAL;

find_priolist:
	/* most positive priority is scheduled first, equal priorities fifo */
	rb = NULL;
	parent = &se->queue.rb_root.rb_node;
	while (*parent) {
		rb = *parent;
		p = to_priolist(rb);
		if (prio > p->priority) {
			parent = &rb->rb_left;
		} else if (prio < p->priority) {
			parent = &rb->rb_right;
			first = false;
		} else {
			return &p->requests;
		}
	}

	if (prio == I915_PRIORITY_NORMAL) {
		p = &se->default_priolist;
	} else {
		p = kmem_cache_alloc(global.slab_priorities, GFP_ATOMIC);
		/* Convert an allocation failure to a priority bump */
		if (unlikely(!p)) {
			prio = I915_PRIORITY_NORMAL; /* recurses just once */

			/* To maintain ordering with all rendering, after an
			 * allocation failure we have to disable all scheduling.
			 * Requests will then be executed in fifo, and schedule
			 * will ensure that dependencies are emitted in fifo.
			 * There will be still some reordering with existing
			 * requests, so if userspace lied about their
			 * dependencies that reordering may be visible.
			 */
			se->no_priolist = true;
			goto find_priolist;
		}
	}

	p->priority = prio;
	INIT_LIST_HEAD(&p->requests);

	rb_link_node(&p->node, rb, parent);
	rb_insert_color_cached(&p->node, &se->queue, first);

	return &p->requests;
}

void __i915_priolist_free(struct i915_priolist *p)
{
	kmem_cache_free(global.slab_priorities, p);
}

static struct i915_request *
stack_push(struct i915_request *rq,
	   struct i915_request *prev,
	   struct list_head *pos)
{
	prev->sched.dfs.pos = pos;
	rq->sched.dfs.prev = prev;
	return rq;
}

static struct i915_request *
stack_pop(struct i915_request *rq,
	  struct list_head **pos)
{
	rq = rq->sched.dfs.prev;
	if (rq)
		*pos = rq->sched.dfs.pos;
	return rq;
}

static inline bool need_preempt(int prio, int active)
{
	/*
	 * Allow preemption of low -> normal -> high, but we do
	 * not allow low priority tasks to preempt other low priority
	 * tasks under the impression that latency for low priority
	 * tasks does not matter (as much as background throughput),
	 * so kiss.
	 */
	return prio >= max(I915_PRIORITY_NORMAL, active);
}

static void kick_submission(struct intel_engine_cs *engine,
			    const struct i915_request *rq,
			    int prio)
{
	const struct i915_request *inflight;

	/*
	 * We only need to kick the tasklet once for the high priority
	 * new context we add into the queue.
	 */
	if (prio <= engine->execlists.queue_priority_hint)
		return;

	/* Nothing currently active? We're overdue for a submission! */
	inflight = execlists_active(&engine->execlists);
	if (!inflight)
		return;

	/*
	 * If we are already the currently executing context, don't
	 * bother evaluating if we should preempt ourselves.
	 */
	if (inflight->context == rq->context)
		return;

	SCHED_TRACE(&engine->sched,
		    "bumping queue-priority-hint:%d for rq:" RQ_FMT ", inflight:" RQ_FMT " prio %d\n",
		    prio,
		    RQ_ARG(rq), RQ_ARG(inflight),
		    inflight->sched.attr.priority);

	engine->execlists.queue_priority_hint = prio;
	if (need_preempt(prio, rq_prio(inflight)))
		intel_engine_kick_scheduler(engine);
}

static void ipi_priority(struct i915_request *rq, int prio)
{
	int old = READ_ONCE(rq->sched.ipi_priority);

	do {
		if (prio <= old)
			return;
	} while (!try_cmpxchg(&rq->sched.ipi_priority, &old, prio));

	__ipi_add(rq);
}

static void __i915_request_set_priority(struct i915_request *rq, int prio)
{
	struct intel_engine_cs *engine = rq->engine;
	struct i915_sched *se = intel_engine_get_scheduler(engine);
	struct list_head *pos = &rq->sched.signalers_list;
	struct list_head *plist;

	SCHED_TRACE(&engine->sched, "PI for " RQ_FMT ", prio:%d\n",
		    RQ_ARG(rq), prio);

	plist = lookup_priolist(se, prio);

	/*
	 * Recursively bump all dependent priorities to match the new request.
	 *
	 * A naive approach would be to use recursion:
	 * static void update_priorities(struct i915_sched_node *node, prio) {
	 *	list_for_each_entry(dep, &node->signalers_list, signal_link)
	 *		update_priorities(dep->signal, prio)
	 *	queue_request(node);
	 * }
	 * but that may have unlimited recursion depth and so runs a very
	 * real risk of overunning the kernel stack. Instead, we build
	 * a flat list of all dependencies starting with the current request.
	 * As we walk the list of dependencies, we add all of its dependencies
	 * to the end of the list (this may include an already visited
	 * request) and continue to walk onwards onto the new dependencies. The
	 * end result is a topological list of requests in reverse order, the
	 * last element in the list is the request we must execute first.
	 */
	rq->sched.dfs.prev = NULL;
	do {
		list_for_each_continue(pos, &rq->sched.signalers_list) {
			struct i915_dependency *p =
				list_entry(pos, typeof(*p), signal_link);
			struct i915_request *s =
				container_of(p->signaler, typeof(*s), sched);

			if (rq_prio(s) >= prio)
				continue;

			if (__i915_request_is_complete(s))
				continue;

			if (s->engine != engine) {
				ipi_priority(s, prio);
				continue;
			}

			/* Remember our position along this branch */
			rq = stack_push(s, rq, pos);
			pos = &rq->sched.signalers_list;
		}

		RQ_TRACE(rq, "set-priority:%d\n", prio);
		WRITE_ONCE(rq->sched.attr.priority, prio);

		/*
		 * Once the request is ready, it will be placed into the
		 * priority lists and then onto the HW runlist. Before the
		 * request is ready, it does not contribute to our preemption
		 * decisions and we can safely ignore it, as it will, and
		 * any preemption required, be dealt with upon submission.
		 * See engine->submit_request()
		 */
		if (!i915_request_is_ready(rq))
			continue;

		GEM_BUG_ON(rq->engine != engine);
		if (i915_request_in_priority_queue(rq))
			list_move_tail(&rq->sched.link, plist);

		/* Defer (tasklet) submission until after all updates. */
		kick_submission(engine, rq, prio);
	} while ((rq = stack_pop(rq, &pos)));
}

#define all_signalers_checked(p, rq) \
	list_entry_is_head(p, &(rq)->sched.signalers_list, signal_link)

void i915_request_set_priority(struct i915_request *rq, int prio)
{
	struct intel_engine_cs *engine;
	unsigned long flags;

	if (prio <= rq_prio(rq))
		return;

	/*
	 * If we are setting the priority before being submitted, see if we
	 * can quickly adjust our own priority in-situ and avoid taking
	 * the contended engine->active.lock. If we need priority inheritance,
	 * take the slow route.
	 */
	if (rq_prio(rq) == I915_PRIORITY_INVALID) {
		struct i915_dependency *p;

		rcu_read_lock();
		for_each_signaler(p, rq) {
			struct i915_request *s =
				container_of(p->signaler, typeof(*s), sched);

			if (rq_prio(s) >= prio)
				continue;

			if (__i915_request_is_complete(s))
				continue;

			break;
		}
		rcu_read_unlock();

		/* Update priority in place if no PI required */
		if (all_signalers_checked(p, rq) &&
		    cmpxchg(&rq->sched.attr.priority,
			    I915_PRIORITY_INVALID,
			    prio) == I915_PRIORITY_INVALID)
			return;
	}

	engine = lock_engine_irqsave(rq, flags);
	if (prio <= rq_prio(rq))
		goto unlock;

	if (__i915_request_is_complete(rq))
		goto unlock;

	if (!intel_engine_has_scheduler(engine)) {
		rq->sched.attr.priority = prio;
		goto unlock;
	}

	rcu_read_lock();
	__i915_request_set_priority(rq, prio);
	rcu_read_unlock();
	GEM_BUG_ON(rq_prio(rq) != prio);

unlock:
	spin_unlock_irqrestore(&engine->sched.lock, flags);
}

void __i915_sched_defer_request(struct intel_engine_cs *engine,
				struct i915_request *rq)
{
	struct i915_sched *se = intel_engine_get_scheduler(engine);
	struct list_head *pl;
	LIST_HEAD(list);

	SCHED_TRACE(se, "defer request " RQ_FMT "\n", RQ_ARG(rq));

	lockdep_assert_held(&se->lock);
	GEM_BUG_ON(!test_bit(I915_FENCE_FLAG_PQUEUE, &rq->fence.flags));

	/*
	 * When we defer a request, we must maintain its order with respect
	 * to those that are waiting upon it. So we traverse its chain of
	 * waiters and move any that are earlier than the request to after it.
	 */
	pl = lookup_priolist(se, rq_prio(rq));
	do {
		struct i915_dependency *p;

		GEM_BUG_ON(i915_request_is_active(rq));
		list_move_tail(&rq->sched.link, pl);

		for_each_waiter(p, rq) {
			struct i915_request *w =
				container_of(p->waiter, typeof(*w), sched);

			if (p->flags & I915_DEPENDENCY_WEAK)
				continue;

			/* Leave semaphores spinning on the other engines */
			if (w->engine != engine)
				continue;

			/* No waiter should start before its signaler */
			GEM_BUG_ON(i915_request_has_initial_breadcrumb(w) &&
				   __i915_request_has_started(w) &&
				   !__i915_request_is_complete(rq));

			if (!i915_request_is_ready(w))
				continue;

			if (rq_prio(w) < rq_prio(rq))
				continue;

			GEM_BUG_ON(rq_prio(w) > rq_prio(rq));
			GEM_BUG_ON(i915_request_is_active(w));
			list_move_tail(&w->sched.link, &list);
		}

		rq = list_first_entry_or_null(&list, typeof(*rq), sched.link);
	} while (rq);
}

static void queue_request(struct i915_sched *se, struct i915_request *rq)
{
	GEM_BUG_ON(!list_empty(&rq->sched.link));
	list_add_tail(&rq->sched.link, lookup_priolist(se, rq_prio(rq)));
	set_bit(I915_FENCE_FLAG_PQUEUE, &rq->fence.flags);
}

static bool submit_queue(struct intel_engine_cs *engine,
			 const struct i915_request *rq)
{
	struct intel_engine_execlists *execlists = &engine->execlists;

	if (rq_prio(rq) <= execlists->queue_priority_hint)
		return false;

	execlists->queue_priority_hint = rq_prio(rq);
	return true;
}

static bool hold_request(const struct i915_request *rq)
{
	struct i915_dependency *p;
	bool result = false;

	/*
	 * If one of our ancestors is on hold, we must also be put on hold,
	 * otherwise we will bypass it and execute before it.
	 */
	rcu_read_lock();
	for_each_signaler(p, rq) {
		const struct i915_request *s =
			container_of(p->signaler, typeof(*s), sched);

		if (s->engine != rq->engine)
			continue;

		result = i915_request_on_hold(s);
		if (result)
			break;
	}
	rcu_read_unlock();

	return result;
}

static bool ancestor_on_hold(const struct i915_sched *se,
			     const struct i915_request *rq)
{
	GEM_BUG_ON(i915_request_on_hold(rq));
	return unlikely(!list_empty(&se->hold)) && hold_request(rq);
}

void i915_request_enqueue(struct i915_request *rq)
{
	struct intel_engine_cs *engine = rq->engine;
	struct i915_sched *se = intel_engine_get_scheduler(engine);
	unsigned long flags;
	bool kick = false;

	SCHED_TRACE(se, "queue request " RQ_FMT "\n", RQ_ARG(rq));

	/* Will be called from irq-context when using foreign fences. */
	spin_lock_irqsave(&se->lock, flags);
	GEM_BUG_ON(test_bit(I915_FENCE_FLAG_PQUEUE, &rq->fence.flags));

	if (unlikely(ancestor_on_hold(se, rq))) {
		RQ_TRACE(rq, "ancestor on hold\n");
		list_add_tail(&rq->sched.link, &se->hold);
		i915_request_set_hold(rq);
	} else {
		queue_request(se, rq);

		GEM_BUG_ON(i915_sched_is_idle(se));

		kick = submit_queue(engine, rq);
	}

	GEM_BUG_ON(list_empty(&rq->sched.link));
	spin_unlock_irqrestore(&se->lock, flags);
	if (kick)
		i915_sched_kick(se);
}

struct i915_request *
__i915_sched_rewind_requests(struct intel_engine_cs *engine)
{
	struct i915_sched *se = intel_engine_get_scheduler(engine);
	struct i915_request *rq, *rn, *active = NULL;
	struct list_head *pl;
	int prio = I915_PRIORITY_INVALID;

	lockdep_assert_held(&se->lock);

	list_for_each_entry_safe_reverse(rq, rn, &se->requests, sched.link) {
		if (__i915_request_is_complete(rq)) {
			list_del_init(&rq->sched.link);
			continue;
		}

		__i915_request_unsubmit(rq);

		GEM_BUG_ON(rq_prio(rq) == I915_PRIORITY_INVALID);
		if (rq_prio(rq) != prio) {
			prio = rq_prio(rq);
			pl = lookup_priolist(se, prio);
		}
		GEM_BUG_ON(i915_sched_is_idle(se));

		list_move(&rq->sched.link, pl);
		set_bit(I915_FENCE_FLAG_PQUEUE, &rq->fence.flags);

		/* Check in case we rollback so far we wrap [size/2] */
		if (intel_ring_direction(rq->ring,
					 rq->tail,
					 rq->ring->tail + 8) > 0)
			rq->context->lrc.desc |= CTX_DESC_FORCE_RESTORE;

		active = rq;
	}

	SCHED_TRACE(se,
		    "rewind requests, active request " RQ_FMT "\n",
		    RQ_ARG(active));

	return active;
}

bool __i915_sched_suspend_request(struct intel_engine_cs *engine,
				  struct i915_request *rq)
{
	struct i915_sched *se = intel_engine_get_scheduler(engine);
	LIST_HEAD(list);

	lockdep_assert_held(&se->lock);
	GEM_BUG_ON(rq->engine != engine);

	if (__i915_request_is_complete(rq)) /* too late! */
		return false;

	if (i915_request_on_hold(rq))
		return false;

	SCHED_TRACE(se, "suspending request " RQ_FMT "\n", RQ_ARG(rq));

	/*
	 * Transfer this request onto the hold queue to prevent it
	 * being resumbitted to HW (and potentially completed) before we have
	 * released it. Since we may have already submitted following
	 * requests, we need to remove those as well.
	 */
	do {
		struct i915_dependency *p;

		if (i915_request_is_active(rq))
			__i915_request_unsubmit(rq);

		list_move_tail(&rq->sched.link, &se->hold);
		clear_bit(I915_FENCE_FLAG_PQUEUE, &rq->fence.flags);
		i915_request_set_hold(rq);
		RQ_TRACE(rq, "on hold\n");

		for_each_waiter(p, rq) {
			struct i915_request *w =
				container_of(p->waiter, typeof(*w), sched);

			if (p->flags & I915_DEPENDENCY_WEAK)
				continue;

			/* Leave semaphores spinning on the other engines */
			if (w->engine != engine)
				continue;

			if (!i915_request_is_ready(w))
				continue;

			if (__i915_request_is_complete(w))
				continue;

			if (i915_request_on_hold(w)) /* acts as a visited bit */
				continue;

			list_move_tail(&w->sched.link, &list);
		}

		rq = list_first_entry_or_null(&list, typeof(*rq), sched.link);
	} while (rq);

	GEM_BUG_ON(list_empty(&se->hold));

	return true;
}

bool i915_sched_suspend_request(struct intel_engine_cs *engine,
				struct i915_request *rq)
{
	struct i915_sched *se = intel_engine_get_scheduler(engine);
	bool result;

	if (i915_request_on_hold(rq))
		return false;

	spin_lock_irq(&se->lock);
	result = __i915_sched_suspend_request(engine, rq);
	spin_unlock_irq(&se->lock);

	return result;
}

void __i915_sched_resume_request(struct intel_engine_cs *engine,
				 struct i915_request *rq)
{
	struct i915_sched *se = intel_engine_get_scheduler(engine);
	LIST_HEAD(list);

	lockdep_assert_held(&se->lock);

	if (rq_prio(rq) > engine->execlists.queue_priority_hint) {
		engine->execlists.queue_priority_hint = rq_prio(rq);
		i915_sched_kick(se);
	}

	if (!i915_request_on_hold(rq))
		return;

	SCHED_TRACE(se, "resuming request " RQ_FMT "\n", RQ_ARG(rq));

	/*
	 * Move this request back to the priority queue, and all of its
	 * children and grandchildren that were suspended along with it.
	 */
	do {
		struct i915_dependency *p;

		RQ_TRACE(rq, "hold release\n");

		GEM_BUG_ON(!i915_request_on_hold(rq));
		GEM_BUG_ON(!i915_sw_fence_signaled(&rq->submit));

		i915_request_clear_hold(rq);
		list_del_init(&rq->sched.link);

		queue_request(se, rq);

		/* Also release any children on this engine that are ready */
		for_each_waiter(p, rq) {
			struct i915_request *w =
				container_of(p->waiter, typeof(*w), sched);

			if (p->flags & I915_DEPENDENCY_WEAK)
				continue;

			/* Propagate any change in error status */
			if (rq->fence.error)
				i915_request_set_error_once(w, rq->fence.error);

			if (w->engine != engine)
				continue;

			/* We also treat the on-hold status as a visited bit */
			if (!i915_request_on_hold(w))
				continue;

			/* Check that no other parents are also on hold [BFS] */
			if (hold_request(w))
				continue;

			list_move_tail(&w->sched.link, &list);
		}

		rq = list_first_entry_or_null(&list, typeof(*rq), sched.link);
	} while (rq);
}

void i915_sched_resume_request(struct intel_engine_cs *engine,
			       struct i915_request *rq)
{
	struct i915_sched *se = intel_engine_get_scheduler(engine);

	spin_lock_irq(&se->lock);
	__i915_sched_resume_request(engine, rq);
	spin_unlock_irq(&se->lock);
}

void __i915_sched_cancel_queue(struct i915_sched *se)
{
	struct i915_request *rq, *rn;
	struct rb_node *rb;

	lockdep_assert_held(&se->lock);

	/* Mark all executing requests as skipped. */
	list_for_each_entry(rq, &se->requests, sched.link)
		i915_request_put(i915_request_mark_eio(rq));

	/* Flush the queued requests to the timeline list (for retiring). */
	while ((rb = rb_first_cached(&se->queue))) {
		struct i915_priolist *p = to_priolist(rb);

		priolist_for_each_request_consume(rq, rn, p) {
			i915_request_put(i915_request_mark_eio(rq));
			__i915_request_submit(rq);
		}

		rb_erase_cached(&p->node, &se->queue);
		i915_priolist_free(p);
	}
	GEM_BUG_ON(!i915_sched_is_idle(se));

	/* On-hold requests will be flushed to timeline upon their release */
	list_for_each_entry(rq, &se->hold, sched.link)
		i915_request_put(i915_request_mark_eio(rq));

	/* Remaining _unready_ requests will be nop'ed when submitted */
}

void i915_sched_node_init(struct i915_sched_node *node)
{
	spin_lock_init(&node->lock);

	INIT_LIST_HEAD(&node->signalers_list);
	INIT_LIST_HEAD(&node->waiters_list);
	INIT_LIST_HEAD(&node->link);

	node->ipi_link = NULL;

	i915_sched_node_reinit(node);
}

void i915_sched_node_reinit(struct i915_sched_node *node)
{
	node->attr.priority = I915_PRIORITY_INVALID;
	node->semaphores = 0;
	node->flags = 0;

	GEM_BUG_ON(node->ipi_link);
	node->ipi_priority = I915_PRIORITY_INVALID;

	GEM_BUG_ON(!list_empty(&node->signalers_list));
	GEM_BUG_ON(!list_empty(&node->waiters_list));
	GEM_BUG_ON(!list_empty(&node->link));
}

static struct i915_dependency *
i915_dependency_alloc(void)
{
	return kmem_cache_alloc(global.slab_dependencies, GFP_KERNEL);
}

static void
rcu_dependency_free(struct rcu_head *rcu)
{
	kmem_cache_free(global.slab_dependencies,
			container_of(rcu, typeof(struct i915_dependency), rcu));
}

static void
i915_dependency_free(struct i915_dependency *dep)
{
	call_rcu(&dep->rcu, rcu_dependency_free);
}

bool __i915_sched_node_add_dependency(struct i915_sched_node *node,
				      struct i915_sched_node *signal,
				      struct i915_dependency *dep,
				      unsigned long flags)
{
	bool ret = false;

	/* The signal->lock is always the outer lock in this double-lock. */
	spin_lock(&signal->lock);

	if (!node_signaled(signal)) {
		dep->signaler = signal;
		dep->waiter = node_get(node);
		dep->flags = flags;

		/* All set, now publish. Beware the lockless walkers. */
		spin_lock_nested(&node->lock, SINGLE_DEPTH_NESTING);
		list_add_rcu(&dep->signal_link, &node->signalers_list);
		list_add_rcu(&dep->wait_link, &signal->waiters_list);
		spin_unlock(&node->lock);

		/* Propagate the chains */
		node->flags |= signal->flags;
		ret = true;
	}

	spin_unlock(&signal->lock);

	return ret;
}

int i915_sched_node_add_dependency(struct i915_sched_node *node,
				   struct i915_sched_node *signal,
				   unsigned long flags)
{
	struct i915_dependency *dep;

	dep = i915_dependency_alloc();
	if (!dep)
		return -ENOMEM;

	if (!__i915_sched_node_add_dependency(node, signal, dep,
					      flags | I915_DEPENDENCY_ALLOC))
		i915_dependency_free(dep);

	return 0;
}

void i915_sched_node_retire(struct i915_sched_node *node)
{
	struct i915_dependency *dep, *tmp;
	LIST_HEAD(waiters);

	/*
	 * Everyone we depended upon (the fences we wait to be signaled)
	 * should retire before us and remove themselves from our list.
	 * However, retirement is run independently on each timeline and
	 * so we may be called out-of-order. As we need to avoid taking
	 * the signaler's lock, just mark up our completion and be wary
	 * in traversing the signalers->waiters_list.
	 */

	/* Remove ourselves from everyone who depends upon us */
	spin_lock(&node->lock);
	if (!list_empty(&node->waiters_list)) {
		list_replace_rcu(&node->waiters_list, &waiters);
		INIT_LIST_HEAD_RCU(&node->waiters_list);
	}
	spin_unlock(&node->lock);

	list_for_each_entry_safe(dep, tmp, &waiters, wait_link) {
		struct i915_sched_node *w = dep->waiter;

		GEM_BUG_ON(dep->signaler != node);

		spin_lock(&w->lock);
		list_del_rcu(&dep->signal_link);
		spin_unlock(&w->lock);
		node_put(w);

		if (dep->flags & I915_DEPENDENCY_ALLOC)
			i915_dependency_free(dep);
	}
}

void i915_sched_disable_tasklet(struct i915_sched *se)
{
	__tasklet_disable_sync_once(&se->tasklet);
	GEM_BUG_ON(!__i915_sched_tasklet_is_disabled(se));
	SCHED_TRACE(se, "disable:%d\n", atomic_read(&se->tasklet.count));
}

void i915_sched_enable_tasklet(struct i915_sched *se)
{
	SCHED_TRACE(se, "enable:%d\n", atomic_read(&se->tasklet.count));
	GEM_BUG_ON(!__i915_sched_tasklet_is_disabled(se));

	/* And kick in case we missed a new request submission. */
	if (__tasklet_enable(&se->tasklet))
		i915_sched_kick(se);
}

void __i915_sched_flush(struct i915_sched *se, bool sync)
{
	struct tasklet_struct *t = &se->tasklet;

	if (!t->callback)
		return;

	local_bh_disable();
	if (tasklet_trylock(t)) {
		/* Must wait for any GPU reset in progress. */
		if (__tasklet_is_enabled(t))
			t->callback(t);
		tasklet_unlock(t);
	}
	local_bh_enable();

	/* Synchronise and wait for the tasklet on another CPU */
	if (sync)
		tasklet_unlock_wait(t);
}

void i915_request_show_with_schedule(struct drm_printer *m,
				     const struct i915_request *rq,
				     const char *prefix,
				     int indent)
{
	struct i915_dependency *dep;

	i915_request_show(m, rq, prefix, indent);
	if (i915_request_completed(rq))
		return;

	rcu_read_lock();
	for_each_signaler(dep, rq) {
		const struct i915_request *signaler =
			node_to_request(dep->signaler);

		/* Dependencies along the same timeline are expected. */
		if (signaler->timeline == rq->timeline)
			continue;

		if (__i915_request_is_complete(signaler))
			continue;

		i915_request_show(m, signaler, prefix, indent + 2);
	}
	rcu_read_unlock();
}

static void hexdump(struct drm_printer *m, const void *buf, size_t len)
{
	const size_t rowsize = 8 * sizeof(u32);
	const void *prev = NULL;
	bool skip = false;
	size_t pos;

	for (pos = 0; pos < len; pos += rowsize) {
		char line[128];

		if (prev && !memcmp(prev, buf + pos, rowsize)) {
			if (!skip) {
				drm_printf(m, "*\n");
				skip = true;
			}
			continue;
		}

		WARN_ON_ONCE(hex_dump_to_buffer(buf + pos, len - pos,
						rowsize, sizeof(u32),
						line, sizeof(line),
						false) >= sizeof(line));
		drm_printf(m, "[%04zx] %s\n", pos, line);

		prev = buf + pos;
		skip = false;
	}
}

static void
print_request_ring(struct drm_printer *m, const struct i915_request *rq)
{
	void *ring;
	int size;

	drm_printf(m,
		   "[head %04x, postfix %04x, tail %04x, batch 0x%08x_%08x]:\n",
		   rq->head, rq->postfix, rq->tail,
		   rq->batch ? upper_32_bits(rq->batch->node.start) : ~0u,
		   rq->batch ? lower_32_bits(rq->batch->node.start) : ~0u);

	size = rq->tail - rq->head;
	if (rq->tail < rq->head)
		size += rq->ring->size;

	ring = kmalloc(size, GFP_ATOMIC);
	if (ring) {
		const void *vaddr = rq->ring->vaddr;
		unsigned int head = rq->head;
		unsigned int len = 0;

		if (rq->tail < head) {
			len = rq->ring->size - head;
			memcpy(ring, vaddr + head, len);
			head = 0;
		}
		memcpy(ring + len, vaddr + head, size - len);

		hexdump(m, ring, size);
		kfree(ring);
	}
}

void i915_sched_show(struct drm_printer *m,
		     struct i915_sched *se,
		     void (*show_request)(struct drm_printer *m,
					  const struct i915_request *rq,
					  const char *prefix,
					  int indent),
		     unsigned int max)
{
	const struct i915_request *rq, *last;
	unsigned long flags;
	unsigned int count;
	struct rb_node *rb;

	rcu_read_lock();
	spin_lock_irqsave(&se->lock, flags);

	rq = i915_sched_get_active_request(se);
	if (rq) {
		i915_request_show(m, rq, "Active ", 0);

		drm_printf(m, "\tring->start:  0x%08x\n",
			   i915_ggtt_offset(rq->ring->vma));
		drm_printf(m, "\tring->head:   0x%08x\n",
			   rq->ring->head);
		drm_printf(m, "\tring->tail:   0x%08x\n",
			   rq->ring->tail);
		drm_printf(m, "\tring->emit:   0x%08x\n",
			   rq->ring->emit);
		drm_printf(m, "\tring->space:  0x%08x\n",
			   rq->ring->space);
		drm_printf(m, "\tring->hwsp:   0x%08x\n",
			   i915_request_active_timeline(rq)->hwsp_offset);

		print_request_ring(m, rq);

		if (rq->context->lrc_reg_state) {
			drm_printf(m, "Logical Ring Context:\n");
			hexdump(m, rq->context->lrc_reg_state, PAGE_SIZE);
		}
	}

	drm_printf(m, "Tasklet queued? %s (%s)\n",
		   yesno(test_bit(TASKLET_STATE_SCHED, &se->tasklet.state)),
		   enableddisabled(!atomic_read(&se->tasklet.count)));

	drm_printf(m, "Requests:\n");

	last = NULL;
	count = 0;
	list_for_each_entry(rq, &se->requests, sched.link) {
		if (count++ < max - 1)
			show_request(m, rq, "\t", 0);
		else
			last = rq;
	}
	if (last) {
		if (count > max) {
			drm_printf(m,
				   "\t...skipping %d executing requests...\n",
				   count - max);
		}
		show_request(m, last, "\t", 0);
	}

	last = NULL;
	count = 0;
	for (rb = rb_first_cached(&se->queue); rb; rb = rb_next(rb)) {
		struct i915_priolist *p = rb_entry(rb, typeof(*p), node);

		priolist_for_each_request(rq, p) {
			if (count++ < max - 1)
				show_request(m, rq, "\t", 0);
			else
				last = rq;
		}
	}
	if (last) {
		if (count > max) {
			drm_printf(m,
				   "\t...skipping %d queued requests...\n",
				   count - max);
		}
		show_request(m, last, "\t", 0);
	}

	last = NULL;
	count = 0;
	list_for_each_entry(rq, &se->hold, sched.link) {
		if (count++ < max - 1)
			show_request(m, rq, "\t", 0);
		else
			last = rq;
	}
	if (last) {
		if (count > max) {
			drm_printf(m,
				   "\t...skipping %d suspended requests...\n",
				   count - max);
		}
		show_request(m, last, "\t", 0);
	}

	spin_unlock_irqrestore(&se->lock, flags);
	rcu_read_unlock();

	if (se->show)
		se->show(m, se, show_request, max);
}

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftests/i915_scheduler.c"
#endif

static void i915_global_scheduler_shrink(void)
{
	kmem_cache_shrink(global.slab_dependencies);
	kmem_cache_shrink(global.slab_priorities);
}

static void i915_global_scheduler_exit(void)
{
	kmem_cache_destroy(global.slab_dependencies);
	kmem_cache_destroy(global.slab_priorities);
}

static struct i915_global_scheduler global = { {
	.shrink = i915_global_scheduler_shrink,
	.exit = i915_global_scheduler_exit,
} };

int __init i915_global_scheduler_init(void)
{
	global.slab_dependencies = KMEM_CACHE(i915_dependency,
					      SLAB_HWCACHE_ALIGN);
	if (!global.slab_dependencies)
		return -ENOMEM;

	global.slab_priorities = KMEM_CACHE(i915_priolist, 0);
	if (!global.slab_priorities)
		goto err_priorities;

	i915_global_register(&global.base);
	return 0;

err_priorities:
	kmem_cache_destroy(global.slab_priorities);
	return -ENOMEM;
}
