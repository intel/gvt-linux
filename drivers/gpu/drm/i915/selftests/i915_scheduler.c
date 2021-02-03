// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include "i915_selftest.h"

#include "gt/intel_context.h"
#include "gt/intel_gpu_commands.h"
#include "gt/selftest_engine_heartbeat.h"
#include "selftests/igt_spinner.h"
#include "selftests/i915_random.h"

static void scheduling_disable(struct intel_engine_cs *engine)
{
	engine->props.preempt_timeout_ms = 0;
	engine->props.timeslice_duration_ms = 0;

	st_engine_heartbeat_disable(engine);
}

static void scheduling_enable(struct intel_engine_cs *engine)
{
	st_engine_heartbeat_enable(engine);

	engine->props.preempt_timeout_ms =
		engine->defaults.preempt_timeout_ms;
	engine->props.timeslice_duration_ms =
		engine->defaults.timeslice_duration_ms;
}

static int first_engine(struct drm_i915_private *i915,
			int (*chain)(struct intel_engine_cs *engine,
				     unsigned long param,
				     bool (*fn)(struct i915_request *rq,
						unsigned long v,
						unsigned long e)),
			unsigned long param,
			bool (*fn)(struct i915_request *rq,
				   unsigned long v, unsigned long e))
{
	struct intel_engine_cs *engine;

	for_each_uabi_engine(engine, i915) {
		if (!intel_engine_has_scheduler(engine))
			continue;

		return chain(engine, param, fn);
	}

	return 0;
}

static int all_engines(struct drm_i915_private *i915,
		       int (*chain)(struct intel_engine_cs *engine,
				    unsigned long param,
				    bool (*fn)(struct i915_request *rq,
					       unsigned long v,
					       unsigned long e)),
		       unsigned long param,
		       bool (*fn)(struct i915_request *rq,
				  unsigned long v, unsigned long e))
{
	struct intel_engine_cs *engine;
	int err;

	for_each_uabi_engine(engine, i915) {
		if (!intel_engine_has_scheduler(engine))
			continue;

		err = chain(engine, param, fn);
		if (err)
			return err;
	}

	return 0;
}

static bool check_context_order(struct intel_engine_cs *engine)
{
	u64 last_seqno, last_context;
	unsigned long count;
	bool result = false;
	struct rb_node *rb;
	int last_prio;

	/* We expect the execution order to follow ascending fence-context */
	spin_lock_irq(&engine->active.lock);

	count = 0;
	last_context = 0;
	last_seqno = 0;
	last_prio = 0;
	for (rb = rb_first_cached(&engine->execlists.queue); rb; rb = rb_next(rb)) {
		struct i915_priolist *p = rb_entry(rb, typeof(*p), node);
		struct i915_request *rq;

		priolist_for_each_request(rq, p) {
			if (rq->fence.context < last_context ||
			    (rq->fence.context == last_context &&
			     rq->fence.seqno < last_seqno)) {
				pr_err("[%lu] %llx:%lld [prio:%d] after %llx:%lld [prio:%d]\n",
				       count,
				       rq->fence.context,
				       rq->fence.seqno,
				       rq_prio(rq),
				       last_context,
				       last_seqno,
				       last_prio);
				goto out_unlock;
			}

			last_context = rq->fence.context;
			last_seqno = rq->fence.seqno;
			last_prio = rq_prio(rq);
			count++;
		}
	}
	result = true;
out_unlock:
	spin_unlock_irq(&engine->active.lock);

	return result;
}

static int __single_chain(struct intel_engine_cs *engine, unsigned long length,
			  bool (*fn)(struct i915_request *rq,
				     unsigned long v, unsigned long e))
{
	struct intel_context *ce;
	struct igt_spinner spin;
	struct i915_request *rq;
	unsigned long count;
	unsigned long min;
	int err = 0;

	if (!intel_engine_can_store_dword(engine))
		return 0;

	scheduling_disable(engine);

	if (igt_spinner_init(&spin, engine->gt)) {
		err = -ENOMEM;
		goto err_heartbeat;
	}

	ce = intel_context_create(engine);
	if (IS_ERR(ce)) {
		err = PTR_ERR(ce);
		goto err_spin;
	}
	ce->ring = __intel_context_ring_size(SZ_512K);

	rq = igt_spinner_create_request(&spin, ce, MI_NOOP);
	if (IS_ERR(rq)) {
		err = PTR_ERR(rq);
		goto err_context;
	}
	i915_request_add(rq);
	min = ce->ring->size - ce->ring->space;

	count = 1;
	while (count < length && ce->ring->space > min) {
		rq = intel_context_create_request(ce);
		if (IS_ERR(rq)) {
			err = PTR_ERR(rq);
			break;
		}
		i915_request_add(rq);
		count++;
	}
	intel_engine_flush_submission(engine);

	execlists_active_lock_bh(&engine->execlists);
	if (fn(rq, count, count - 1) && !check_context_order(engine))
		err = -EINVAL;
	execlists_active_unlock_bh(&engine->execlists);

	igt_spinner_end(&spin);
err_context:
	intel_context_put(ce);
err_spin:
	igt_spinner_fini(&spin);
err_heartbeat:
	scheduling_enable(engine);
	return err;
}

static int __wide_chain(struct intel_engine_cs *engine, unsigned long width,
			bool (*fn)(struct i915_request *rq,
				   unsigned long v, unsigned long e))
{
	struct intel_context **ce;
	struct i915_request **rq;
	struct igt_spinner spin;
	unsigned long count;
	unsigned long i, j;
	int err = 0;

	if (!intel_engine_can_store_dword(engine))
		return 0;

	scheduling_disable(engine);

	if (igt_spinner_init(&spin, engine->gt)) {
		err = -ENOMEM;
		goto err_heartbeat;
	}

	ce = kmalloc_array(width, sizeof(*ce), GFP_KERNEL);
	if (!ce) {
		err = -ENOMEM;
		goto err_spin;
	}

	for (i = 0; i < width; i++) {
		ce[i] = intel_context_create(engine);
		if (IS_ERR(ce[i])) {
			err = PTR_ERR(ce[i]);
			width = i;
			goto err_context;
		}
	}

	rq = kmalloc_array(width, sizeof(*rq), GFP_KERNEL);
	if (!rq) {
		err = -ENOMEM;
		goto err_context;
	}

	rq[0] = igt_spinner_create_request(&spin, ce[0], MI_NOOP);
	if (IS_ERR(rq[0])) {
		err = PTR_ERR(rq[0]);
		goto err_free;
	}
	i915_request_add(rq[0]);

	count = 0;
	for (i = 1; i < width; i++) {
		GEM_BUG_ON(i915_request_completed(rq[0]));

		rq[i] = intel_context_create_request(ce[i]);
		if (IS_ERR(rq[i])) {
			err = PTR_ERR(rq[i]);
			break;
		}
		for (j = 0; j < i; j++) {
			err = i915_request_await_dma_fence(rq[i],
							   &rq[j]->fence);
			if (err)
				break;
			count++;
		}
		i915_request_add(rq[i]);
	}
	intel_engine_flush_submission(engine);

	execlists_active_lock_bh(&engine->execlists);
	if (fn(rq[i - 1], i, count) && !check_context_order(engine))
		err = -EINVAL;
	execlists_active_unlock_bh(&engine->execlists);

	igt_spinner_end(&spin);
err_free:
	kfree(rq);
err_context:
	for (i = 0; i < width; i++)
		intel_context_put(ce[i]);
	kfree(ce);
err_spin:
	igt_spinner_fini(&spin);
err_heartbeat:
	scheduling_enable(engine);
	return err;
}

static int __inv_chain(struct intel_engine_cs *engine, unsigned long width,
		       bool (*fn)(struct i915_request *rq,
				  unsigned long v, unsigned long e))
{
	struct intel_context **ce;
	struct i915_request **rq;
	struct igt_spinner spin;
	unsigned long count;
	unsigned long i, j;
	int err = 0;

	if (!intel_engine_can_store_dword(engine))
		return 0;

	scheduling_disable(engine);

	if (igt_spinner_init(&spin, engine->gt)) {
		err = -ENOMEM;
		goto err_heartbeat;
	}

	ce = kmalloc_array(width, sizeof(*ce), GFP_KERNEL);
	if (!ce) {
		err = -ENOMEM;
		goto err_spin;
	}

	for (i = 0; i < width; i++) {
		ce[i] = intel_context_create(engine);
		if (IS_ERR(ce[i])) {
			err = PTR_ERR(ce[i]);
			width = i;
			goto err_context;
		}
	}

	rq = kmalloc_array(width, sizeof(*rq), GFP_KERNEL);
	if (!rq) {
		err = -ENOMEM;
		goto err_context;
	}

	rq[0] = igt_spinner_create_request(&spin, ce[0], MI_NOOP);
	if (IS_ERR(rq[0])) {
		err = PTR_ERR(rq[0]);
		goto err_free;
	}
	i915_request_add(rq[0]);

	count = 0;
	for (i = 1; i < width; i++) {
		GEM_BUG_ON(i915_request_completed(rq[0]));

		rq[i] = intel_context_create_request(ce[i]);
		if (IS_ERR(rq[i])) {
			err = PTR_ERR(rq[i]);
			break;
		}
		for (j = i; j > 0; j--) {
			err = i915_request_await_dma_fence(rq[i],
							   &rq[j - 1]->fence);
			if (err)
				break;
			count++;
		}
		i915_request_add(rq[i]);
	}
	intel_engine_flush_submission(engine);

	execlists_active_lock_bh(&engine->execlists);
	if (fn(rq[i - 1], i, count) && !check_context_order(engine))
		err = -EINVAL;
	execlists_active_unlock_bh(&engine->execlists);

	igt_spinner_end(&spin);
err_free:
	kfree(rq);
err_context:
	for (i = 0; i < width; i++)
		intel_context_put(ce[i]);
	kfree(ce);
err_spin:
	igt_spinner_fini(&spin);
err_heartbeat:
	scheduling_enable(engine);
	return err;
}

static int __sparse_chain(struct intel_engine_cs *engine, unsigned long width,
			  bool (*fn)(struct i915_request *rq,
				     unsigned long v, unsigned long e))
{
	struct intel_context **ce;
	struct i915_request **rq;
	struct igt_spinner spin;
	I915_RND_STATE(prng);
	unsigned long count;
	unsigned long i, j;
	int err = 0;

	if (!intel_engine_can_store_dword(engine))
		return 0;

	scheduling_disable(engine);

	if (igt_spinner_init(&spin, engine->gt)) {
		err = -ENOMEM;
		goto err_heartbeat;
	}

	ce = kmalloc_array(width, sizeof(*ce), GFP_KERNEL);
	if (!ce) {
		err = -ENOMEM;
		goto err_spin;
	}

	for (i = 0; i < width; i++) {
		ce[i] = intel_context_create(engine);
		if (IS_ERR(ce[i])) {
			err = PTR_ERR(ce[i]);
			width = i;
			goto err_context;
		}
	}

	rq = kmalloc_array(width, sizeof(*rq), GFP_KERNEL);
	if (!rq) {
		err = -ENOMEM;
		goto err_context;
	}

	rq[0] = igt_spinner_create_request(&spin, ce[0], MI_NOOP);
	if (IS_ERR(rq[0])) {
		err = PTR_ERR(rq[0]);
		goto err_free;
	}
	i915_request_add(rq[0]);

	count = 0;
	for (i = 1; i < width; i++) {
		GEM_BUG_ON(i915_request_completed(rq[0]));

		rq[i] = intel_context_create_request(ce[i]);
		if (IS_ERR(rq[i])) {
			err = PTR_ERR(rq[i]);
			break;
		}

		if (err == 0 && i > 1) {
			j = i915_prandom_u32_max_state(i - 1, &prng);
			err = i915_request_await_dma_fence(rq[i],
							   &rq[j]->fence);
			count++;
		}

		if (err == 0) {
			err = i915_request_await_dma_fence(rq[i],
							   &rq[i - 1]->fence);
			count++;
		}

		if (err == 0 && i > 2) {
			j = i915_prandom_u32_max_state(i - 2, &prng);
			err = i915_request_await_dma_fence(rq[i],
							   &rq[j]->fence);
			count++;
		}

		i915_request_add(rq[i]);
		if (err)
			break;
	}
	intel_engine_flush_submission(engine);

	execlists_active_lock_bh(&engine->execlists);
	if (fn(rq[i - 1], i, count) && !check_context_order(engine))
		err = -EINVAL;
	execlists_active_unlock_bh(&engine->execlists);

	igt_spinner_end(&spin);
err_free:
	kfree(rq);
err_context:
	for (i = 0; i < width; i++)
		intel_context_put(ce[i]);
	kfree(ce);
err_spin:
	igt_spinner_fini(&spin);
err_heartbeat:
	scheduling_enable(engine);
	return err;
}

static int igt_schedule_chains(struct drm_i915_private *i915,
			       bool (*fn)(struct i915_request *rq,
					  unsigned long v, unsigned long e))
{
	static int (* const chains[])(struct intel_engine_cs *engine,
				      unsigned long length,
				      bool (*fn)(struct i915_request *rq,
						 unsigned long v, unsigned long e)) = {
		__single_chain,
		__wide_chain,
		__inv_chain,
		__sparse_chain,
	};
	int n, err;

	for (n = 0; n < ARRAY_SIZE(chains); n++) {
		err = all_engines(i915, chains[n], 17, fn);
		if (err)
			return err;
	}

	return 0;
}

static bool igt_priority(struct i915_request *rq,
			 unsigned long v, unsigned long e)
{
	i915_request_set_priority(rq, I915_PRIORITY_BARRIER);
	GEM_BUG_ON(rq_prio(rq) != I915_PRIORITY_BARRIER);
	return true;
}

static int igt_priority_chains(void *arg)
{
	return igt_schedule_chains(arg, igt_priority);
}

int i915_scheduler_live_selftests(struct drm_i915_private *i915)
{
	static const struct i915_subtest tests[] = {
		SUBTEST(igt_priority_chains),
	};

	return i915_subtests(tests, i915);
}

static int chains(struct drm_i915_private *i915,
		  int (*chain)(struct drm_i915_private *i915,
			       unsigned long length,
			       bool (*fn)(struct i915_request *rq,
					  unsigned long v, unsigned long e)),
		  bool (*fn)(struct i915_request *rq,
			     unsigned long v, unsigned long e))
{
	unsigned long x[] = { 1, 4, 16, 64, 128, 256, 512, 1024, 4096 };
	int i, err;

	for (i = 0; i < ARRAY_SIZE(x); i++) {
		IGT_TIMEOUT(end_time);

		err = chain(i915, x[i], fn);
		if (err)
			return err;

		if (__igt_timeout(end_time, NULL))
			break;
	}

	return 0;
}

static int single_chain(struct drm_i915_private *i915,
			unsigned long length,
			bool (*fn)(struct i915_request *rq,
				   unsigned long v, unsigned long e))
{
	return first_engine(i915, __single_chain, length, fn);
}

static int single(struct drm_i915_private *i915,
		  bool (*fn)(struct i915_request *rq,
			     unsigned long v, unsigned long e))
{
	return chains(i915, single_chain, fn);
}

static int wide_chain(struct drm_i915_private *i915,
		      unsigned long width,
		      bool (*fn)(struct i915_request *rq,
				 unsigned long v, unsigned long e))
{
	return first_engine(i915, __wide_chain, width, fn);
}

static int wide(struct drm_i915_private *i915,
		bool (*fn)(struct i915_request *rq,
			   unsigned long v, unsigned long e))
{
	return chains(i915, wide_chain, fn);
}

static int inv_chain(struct drm_i915_private *i915,
		     unsigned long width,
		     bool (*fn)(struct i915_request *rq,
				unsigned long v, unsigned long e))
{
	return first_engine(i915, __inv_chain, width, fn);
}

static int inv(struct drm_i915_private *i915,
	       bool (*fn)(struct i915_request *rq,
			  unsigned long v, unsigned long e))
{
	return chains(i915, inv_chain, fn);
}

static int sparse_chain(struct drm_i915_private *i915,
			unsigned long width,
			bool (*fn)(struct i915_request *rq,
				   unsigned long v, unsigned long e))
{
	return first_engine(i915, __sparse_chain, width, fn);
}

static int sparse(struct drm_i915_private *i915,
		  bool (*fn)(struct i915_request *rq,
			     unsigned long v, unsigned long e))
{
	return chains(i915, sparse_chain, fn);
}

static void report(const char *what, unsigned long v, unsigned long e, u64 dt)
{
	pr_info("(%4lu, %7lu), %s:%10lluns\n", v, e, what, dt);
}

static u64 __set_priority(struct i915_request *rq, int prio)
{
	u64 dt;

	preempt_disable();
	dt = ktime_get_raw_fast_ns();
	i915_request_set_priority(rq, prio);
	dt = ktime_get_raw_fast_ns() - dt;
	preempt_enable();

	return dt;
}

static bool set_priority(struct i915_request *rq,
			 unsigned long v, unsigned long e)
{
	report("set-priority", v, e, __set_priority(rq, I915_PRIORITY_BARRIER));
	return true;
}

static int single_priority(void *arg)
{
	return single(arg, set_priority);
}

static int wide_priority(void *arg)
{
	return wide(arg, set_priority);
}

static int inv_priority(void *arg)
{
	return inv(arg, set_priority);
}

static int sparse_priority(void *arg)
{
	return sparse(arg, set_priority);
}

int i915_scheduler_perf_selftests(struct drm_i915_private *i915)
{
	static const struct i915_subtest tests[] = {
		SUBTEST(single_priority),
		SUBTEST(wide_priority),
		SUBTEST(inv_priority),
		SUBTEST(sparse_priority),
	};
	static const struct {
		const char *name;
		size_t sz;
	} types[] = {
#define T(t) { #t, sizeof(struct t) }
		T(i915_dependency),
		T(i915_priolist),
		T(i915_sched_attr),
		T(i915_sched_node),
		T(i915_request),
#undef T
		{}
	};
	typeof(*types) *t;

	for (t = types; t->name; t++)
		pr_info("sizeof(%s): %zd\n", t->name, t->sz);

	return i915_subtests(tests, i915);
}
