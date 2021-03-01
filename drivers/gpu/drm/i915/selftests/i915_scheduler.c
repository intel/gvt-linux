// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include "i915_selftest.h"

#include "gt/intel_context.h"
#include "gt/intel_gpu_commands.h"
#include "gt/intel_ring.h"
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

static bool check_context_order(struct i915_sched *se)
{
	u64 last_seqno, last_context;
	unsigned long count;
	bool result = false;
	struct rb_node *rb;
	int last_prio;

	/* We expect the execution order to follow ascending fence-context */
	spin_lock_irq(&se->lock);

	count = 0;
	last_context = 0;
	last_seqno = 0;
	last_prio = 0;
	for (rb = rb_first_cached(&se->queue); rb; rb = rb_next(rb)) {
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
	spin_unlock_irq(&se->lock);

	return result;
}

static int __single_chain(struct intel_engine_cs *engine, unsigned long length,
			  bool (*fn)(struct i915_request *rq,
				     unsigned long v, unsigned long e))
{
	struct i915_sched *se = intel_engine_get_scheduler(engine);
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
	i915_sched_flush(se);

	i915_sched_lock_bh(se);
	if (fn(rq, count, count - 1) && !check_context_order(se))
		err = -EINVAL;
	i915_sched_unlock_bh(se);

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
	struct i915_sched *se = intel_engine_get_scheduler(engine);
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
	i915_sched_flush(se);

	i915_sched_lock_bh(se);
	if (fn(rq[i - 1], i, count) && !check_context_order(se))
		err = -EINVAL;
	i915_sched_unlock_bh(se);

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
	struct i915_sched *se = intel_engine_get_scheduler(engine);
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
	i915_sched_flush(se);

	i915_sched_lock_bh(se);
	if (fn(rq[i - 1], i, count) && !check_context_order(se))
		err = -EINVAL;
	i915_sched_unlock_bh(se);

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
	struct i915_sched *se = intel_engine_get_scheduler(engine);
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
	i915_sched_flush(se);

	i915_sched_lock_bh(se);
	if (fn(rq[i - 1], i, count) && !check_context_order(se))
		err = -EINVAL;
	i915_sched_unlock_bh(se);

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

static struct i915_request *
__write_timestamp(struct intel_engine_cs *engine,
		  struct drm_i915_gem_object *obj,
		  int slot,
		  struct i915_request *prev)
{
	struct i915_request *rq = ERR_PTR(-EINVAL);
	bool use_64b = INTEL_GEN(engine->i915) >= 8;
	struct intel_context *ce;
	struct i915_vma *vma;
	int err = 0;
	u32 *cs;

	ce = intel_context_create(engine);
	if (IS_ERR(ce))
		return ERR_CAST(ce);

	vma = i915_vma_instance(obj, ce->vm, NULL);
	if (IS_ERR(vma)) {
		err = PTR_ERR(vma);
		goto out_ce;
	}

	err = i915_vma_pin(vma, 0, 0, PIN_USER);
	if (err)
		goto out_ce;

	rq = intel_context_create_request(ce);
	if (IS_ERR(rq)) {
		err = PTR_ERR(rq);
		goto out_unpin;
	}

	i915_vma_lock(vma);
	err = i915_vma_move_to_active(vma, rq, EXEC_OBJECT_WRITE);
	i915_vma_unlock(vma);
	if (err)
		goto out_request;

	if (prev) {
		err = i915_request_await_dma_fence(rq, &prev->fence);
		if (err)
			goto out_request;
	}

	if (engine->emit_init_breadcrumb) {
		err = engine->emit_init_breadcrumb(rq);
		if (err)
			goto out_request;
	}

	cs = intel_ring_begin(rq, 4);
	if (IS_ERR(cs)) {
		err = PTR_ERR(cs);
		goto out_request;
	}

	*cs++ = MI_STORE_REGISTER_MEM + use_64b;
	*cs++ = i915_mmio_reg_offset(RING_TIMESTAMP(engine->mmio_base));
	*cs++ = lower_32_bits(vma->node.start) + sizeof(u32) * slot;
	*cs++ = upper_32_bits(vma->node.start);
	intel_ring_advance(rq, cs);

	i915_request_get(rq);
out_request:
	i915_request_add(rq);
out_unpin:
	i915_vma_unpin(vma);
out_ce:
	intel_context_put(ce);
	i915_request_put(prev);
	return err ? ERR_PTR(err) : rq;
}

static struct i915_request *create_spinner(struct drm_i915_private *i915,
					   struct igt_spinner *spin)
{
	struct intel_engine_cs *engine;

	for_each_uabi_engine(engine, i915) {
		struct intel_context *ce;
		struct i915_request *rq;

		if (igt_spinner_init(spin, engine->gt))
			return ERR_PTR(-ENOMEM);

		ce = intel_context_create(engine);
		if (IS_ERR(ce))
			return ERR_CAST(ce);

		rq = igt_spinner_create_request(spin, ce, MI_NOOP);
		intel_context_put(ce);
		if (rq == ERR_PTR(-ENODEV))
			continue;
		if (IS_ERR(rq))
			return rq;

		i915_request_get(rq);
		i915_request_add(rq);
		return rq;
	}

	return ERR_PTR(-ENODEV);
}

static bool has_timestamp(const struct drm_i915_private *i915)
{
	return INTEL_GEN(i915) >= 7;
}

static int __igt_schedule_cycle(struct drm_i915_private *i915,
				bool (*fn)(struct i915_request *rq,
					   unsigned long v, unsigned long e))
{
	struct intel_engine_cs *engine;
	struct drm_i915_gem_object *obj;
	struct igt_spinner spin;
	struct i915_request *rq;
	unsigned long count, n;
	u32 *time, last;
	int err, loop;

	/*
	 * Queue a bunch of ordered requests (each waiting on the previous)
	 * around the engines a couple of times. Each request will write
	 * the timestamp it executes at into the scratch, with the expectation
	 * that the timestamp will be in our desired execution order.
	 */

	if (!i915->caps.scheduler || !has_timestamp(i915))
		return 0;

	obj = i915_gem_object_create_internal(i915, SZ_64K);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	time = i915_gem_object_pin_map(obj, I915_MAP_WC);
	if (IS_ERR(time)) {
		err = PTR_ERR(time);
		goto out_obj;
	}

	rq = create_spinner(i915, &spin);
	if (IS_ERR(rq)) {
		err = PTR_ERR(rq);
		goto out_obj;
	}

	err = 0;
	count = 0;
	for (loop = 0; !err && loop < 3; loop++) {
		for_each_uabi_engine(engine, i915) {
			if (!intel_engine_has_scheduler(engine))
				continue;

			rq = __write_timestamp(engine, obj, count, rq);
			if (IS_ERR(rq)) {
				err = PTR_ERR(rq);
				break;
			}

			count++;
		}
	}
	GEM_BUG_ON(count * sizeof(u32) > obj->base.size);
	if (err || !count)
		goto out_spin;

	fn(rq, count + 1, count);
	igt_spinner_end(&spin);

	if (i915_request_wait(rq, 0, HZ / 2) < 0) {
		err = -ETIME;
		goto out_request;
	}

	last = time[0];
	for (n = 1; n < count; n++) {
		if (i915_seqno_passed(last, time[n])) {
			pr_err("Timestamp[%lu] %x before previous %x\n",
			       n, time[n], last);
			err = -EINVAL;
			break;
		}
		last = time[n];
	}

out_request:
	i915_request_put(rq);
out_spin:
	igt_spinner_fini(&spin);
out_obj:
	i915_gem_object_put(obj);
	return err;
}

static bool noop(struct i915_request *rq, unsigned long v, unsigned long e)
{
	return true;
}

static int igt_schedule_cycle(void *arg)
{
	return __igt_schedule_cycle(arg, noop);
}

static int igt_priority_cycle(void *arg)
{
	return __igt_schedule_cycle(arg, igt_priority);
}

int i915_scheduler_live_selftests(struct drm_i915_private *i915)
{
	static const struct i915_subtest tests[] = {
		SUBTEST(igt_priority_chains),

		SUBTEST(igt_schedule_cycle),
		SUBTEST(igt_priority_cycle),
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
		T(i915_sched),
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
