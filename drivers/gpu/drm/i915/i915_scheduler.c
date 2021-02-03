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
	spin_lock_irqsave(&engine__->active.lock, (flags)); \
	while (engine__ != READ_ONCE((rq__)->engine)) { \
		spin_unlock(&engine__->active.lock); \
		engine__ = READ_ONCE(rq__->engine); \
		spin_lock(&engine__->active.lock); \
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

void i915_sched_init_ipi(struct i915_sched_ipi *ipi)
{
	INIT_WORK(&ipi->work, ipi_schedule);
	ipi->list = NULL;
}

static void __ipi_add(struct i915_request *rq)
{
#define STUB ((struct i915_request *)1)
	struct intel_engine_cs *engine = READ_ONCE(rq->engine);
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
	first = READ_ONCE(engine->execlists.ipi.list);
	do {
		rq->sched.ipi_link = ptr_pack_bits(first, 1, 1);
	} while (!try_cmpxchg(&engine->execlists.ipi.list, &first, rq));

	if (!first)
		queue_work(system_unbound_wq, &engine->execlists.ipi.work);
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

static void assert_priolists(struct intel_engine_execlists * const execlists)
{
	struct rb_node *rb;
	long last_prio;

	if (!IS_ENABLED(CONFIG_DRM_I915_DEBUG_GEM))
		return;

	GEM_BUG_ON(rb_first_cached(&execlists->queue) !=
		   rb_first(&execlists->queue.rb_root));

	last_prio = INT_MAX;
	for (rb = rb_first_cached(&execlists->queue); rb; rb = rb_next(rb)) {
		const struct i915_priolist *p = to_priolist(rb);

		GEM_BUG_ON(p->priority > last_prio);
		last_prio = p->priority;
	}
}

struct list_head *
i915_sched_lookup_priolist(struct intel_engine_cs *engine, int prio)
{
	struct intel_engine_execlists * const execlists = &engine->execlists;
	struct i915_priolist *p;
	struct rb_node **parent, *rb;
	bool first = true;

	lockdep_assert_held(&engine->active.lock);
	assert_priolists(execlists);

	if (unlikely(execlists->no_priolist))
		prio = I915_PRIORITY_NORMAL;

find_priolist:
	/* most positive priority is scheduled first, equal priorities fifo */
	rb = NULL;
	parent = &execlists->queue.rb_root.rb_node;
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
		p = &execlists->default_priolist;
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
			execlists->no_priolist = true;
			goto find_priolist;
		}
	}

	p->priority = prio;
	INIT_LIST_HEAD(&p->requests);

	rb_link_node(&p->node, rb, parent);
	rb_insert_color_cached(&p->node, &execlists->queue, first);

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

	ENGINE_TRACE(engine,
		     "bumping queue-priority-hint:%d for rq:%llx:%lld, inflight:%llx:%lld prio %d\n",
		     prio,
		     rq->fence.context, rq->fence.seqno,
		     inflight->fence.context, inflight->fence.seqno,
		     inflight->sched.attr.priority);

	engine->execlists.queue_priority_hint = prio;
	if (need_preempt(prio, rq_prio(inflight)))
		tasklet_hi_schedule(&engine->execlists.tasklet);
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
	struct list_head *pos = &rq->sched.signalers_list;
	struct list_head *plist;

	plist = i915_sched_lookup_priolist(engine, prio);

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
	spin_unlock_irqrestore(&engine->active.lock, flags);
}

static void queue_request(struct intel_engine_cs *engine,
			  struct i915_request *rq)
{
	GEM_BUG_ON(!list_empty(&rq->sched.link));
	list_add_tail(&rq->sched.link,
		      i915_sched_lookup_priolist(engine, rq_prio(rq)));
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

static bool ancestor_on_hold(const struct intel_engine_cs *engine,
			     const struct i915_request *rq)
{
	GEM_BUG_ON(i915_request_on_hold(rq));
	return unlikely(!list_empty(&engine->active.hold)) && hold_request(rq);
}

void i915_request_enqueue(struct i915_request *rq)
{
	struct intel_engine_cs *engine = rq->engine;
	unsigned long flags;
	bool kick = false;

	/* Will be called from irq-context when using foreign fences. */
	spin_lock_irqsave(&engine->active.lock, flags);
	GEM_BUG_ON(test_bit(I915_FENCE_FLAG_PQUEUE, &rq->fence.flags));

	if (unlikely(ancestor_on_hold(engine, rq))) {
		RQ_TRACE(rq, "ancestor on hold\n");
		list_add_tail(&rq->sched.link, &engine->active.hold);
		i915_request_set_hold(rq);
	} else {
		queue_request(engine, rq);

		GEM_BUG_ON(RB_EMPTY_ROOT(&engine->execlists.queue.rb_root));

		kick = submit_queue(engine, rq);
	}

	GEM_BUG_ON(list_empty(&rq->sched.link));
	spin_unlock_irqrestore(&engine->active.lock, flags);
	if (kick)
		tasklet_hi_schedule(&engine->execlists.tasklet);
}

struct i915_request *
__i915_sched_rewind_requests(struct intel_engine_cs *engine)
{
	struct i915_request *rq, *rn, *active = NULL;
	struct list_head *pl;
	int prio = I915_PRIORITY_INVALID;

	lockdep_assert_held(&engine->active.lock);

	list_for_each_entry_safe_reverse(rq, rn,
					 &engine->active.requests,
					 sched.link) {
		if (__i915_request_is_complete(rq)) {
			list_del_init(&rq->sched.link);
			continue;
		}

		__i915_request_unsubmit(rq);

		GEM_BUG_ON(rq_prio(rq) == I915_PRIORITY_INVALID);
		if (rq_prio(rq) != prio) {
			prio = rq_prio(rq);
			pl = i915_sched_lookup_priolist(engine, prio);
		}
		GEM_BUG_ON(RB_EMPTY_ROOT(&engine->execlists.queue.rb_root));

		list_move(&rq->sched.link, pl);
		set_bit(I915_FENCE_FLAG_PQUEUE, &rq->fence.flags);

		/* Check in case we rollback so far we wrap [size/2] */
		if (intel_ring_direction(rq->ring,
					 rq->tail,
					 rq->ring->tail + 8) > 0)
			rq->context->lrc.desc |= CTX_DESC_FORCE_RESTORE;

		active = rq;
	}

	return active;
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
