/*
 * Copyright(c) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "i915_drv.h"
#include "i915_vgpu.h"
#include "intel_gvt.h"
#include "gvt/gvt.h"
#include "gt/intel_context.h"
#include "gt/intel_ring.h"
#include "gt/shmem_utils.h"

/**
 * DOC: Intel GVT-g host support
 *
 * Intel GVT-g is a graphics virtualization technology which shares the
 * GPU among multiple virtual machines on a time-sharing basis. Each
 * virtual machine is presented a virtual GPU (vGPU), which has equivalent
 * features as the underlying physical GPU (pGPU), so i915 driver can run
 * seamlessly in a virtual machine.
 *
 * To virtualize GPU resources GVT-g driver depends on hypervisor technology
 * e.g KVM/VFIO/mdev, Xen, etc. to provide resource access trapping capability
 * and be virtualized within GVT-g device module. More architectural design
 * doc is available on https://01.org/group/2230/documentation-list.
 */

static bool is_supported_device(struct drm_i915_private *dev_priv)
{
	if (IS_BROADWELL(dev_priv))
		return true;
	if (IS_SKYLAKE(dev_priv))
		return true;
	if (IS_KABYLAKE(dev_priv))
		return true;
	if (IS_BROXTON(dev_priv))
		return true;
	if (IS_COFFEELAKE(dev_priv))
		return true;
	if (IS_COMETLAKE(dev_priv))
		return true;

	return false;
}

/**
 * intel_gvt_sanitize_options - sanitize GVT related options
 * @dev_priv: drm i915 private data
 *
 * This function is called at the i915 options sanitize stage.
 */
void intel_gvt_sanitize_options(struct drm_i915_private *dev_priv)
{
	if (!dev_priv->params.enable_gvt)
		return;

	if (intel_vgpu_active(dev_priv)) {
		drm_info(&dev_priv->drm, "GVT-g is disabled for guest\n");
		goto bail;
	}

	if (!is_supported_device(dev_priv)) {
		drm_info(&dev_priv->drm,
			 "Unsupported device. GVT-g is disabled\n");
		goto bail;
	}

	return;
bail:
	dev_priv->params.enable_gvt = 0;
}

/**
 * intel_gvt_init - initialize GVT components
 * @dev_priv: drm i915 private data
 *
 * This function is called at the initialization stage to create a GVT device.
 *
 * Returns:
 * Zero on success, negative error code if failed.
 *
 */
int intel_gvt_init(struct drm_i915_private *dev_priv)
{
	int ret;

	if (i915_inject_probe_failure(dev_priv))
		return -ENODEV;

	if (!dev_priv->params.enable_gvt) {
		drm_dbg(&dev_priv->drm,
			"GVT-g is disabled by kernel params\n");
		return 0;
	}

	if (intel_uc_wants_guc_submission(&dev_priv->gt.uc)) {
		drm_err(&dev_priv->drm,
			"i915 GVT-g loading failed due to Graphics virtualization is not yet supported with GuC submission\n");
		return -EIO;
	}

	request_module("kvmgt");
	dev_priv->vgpu.ops = symbol_get(intel_gvt_vgpu_ops);
	if (!dev_priv->vgpu.ops) {
		drm_dbg(&dev_priv->drm, "Fail to find GVT ops\n");
		goto bail;
	}

	ret = dev_priv->vgpu.ops->init_device(dev_priv);
	if (ret) {
		drm_dbg(&dev_priv->drm, "Fail to init GVT device\n");
		goto bail_put_ops;
	}

	return 0;

bail_put_ops:
	symbol_put(gvt_ops);
bail:
	dev_priv->params.enable_gvt = 0;
	return 0;
}

static inline bool intel_gvt_active(struct drm_i915_private *dev_priv)
{
	return dev_priv->gvt;
}

/**
 * intel_gvt_driver_remove - cleanup GVT components when i915 driver is
 *			     unbinding
 * @dev_priv: drm i915 private *
 *
 * This function is called at the i915 driver unloading stage, to shutdown
 * GVT components and release the related resources.
 */
void intel_gvt_driver_remove(struct drm_i915_private *dev_priv)
{
	if (intel_gvt_active(dev_priv)) {
		dev_priv->vgpu.ops->clean_device(dev_priv);
		symbol_put(dev_priv->vgpu.ops);
	}
}

/**
 * intel_gvt_resume - GVT resume routine wapper
 *
 * @dev_priv: drm i915 private *
 *
 * This function is called at the i915 driver resume stage to restore required
 * HW status for GVT so that vGPU can continue running after resumed.
 */
void intel_gvt_resume(struct drm_i915_private *dev_priv)
{
	if (intel_gvt_active(dev_priv))
		dev_priv->vgpu.ops->pm_resume(dev_priv);
}

/*
 * Exported here so that the exports only get created when GVT support is
 * actually enabled.
 */
EXPORT_SYMBOL_NS_GPL(i915_gem_object_alloc, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_object_create_shmem, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_object_init, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_object_ggtt_pin_ww, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_object_pin_map, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_object_set_to_cpu_domain, I915_GVT);
EXPORT_SYMBOL_NS_GPL(__i915_gem_object_flush_map, I915_GVT);
EXPORT_SYMBOL_NS_GPL(__i915_gem_object_set_pages, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_gtt_insert, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_prime_export, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_ww_ctx_init, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_ww_ctx_backoff, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_gem_ww_ctx_fini, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_ppgtt_create, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_request_add, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_request_create, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_request_wait, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_reserve_fence, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_unreserve_fence, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_vm_release, I915_GVT);
EXPORT_SYMBOL_NS_GPL(i915_vma_move_to_active, I915_GVT);
EXPORT_SYMBOL_NS_GPL(intel_context_create, I915_GVT);
EXPORT_SYMBOL_NS_GPL(intel_context_unpin, I915_GVT);
EXPORT_SYMBOL_NS_GPL(__intel_context_do_pin, I915_GVT);
EXPORT_SYMBOL_NS_GPL(intel_ring_begin, I915_GVT);
EXPORT_SYMBOL_NS_GPL(intel_runtime_pm_get, I915_GVT);
EXPORT_SYMBOL_NS_GPL(intel_runtime_pm_put_unchecked, I915_GVT);
EXPORT_SYMBOL_NS_GPL(intel_uncore_forcewake_for_reg, I915_GVT);
EXPORT_SYMBOL_NS_GPL(intel_uncore_forcewake_get, I915_GVT);
EXPORT_SYMBOL_NS_GPL(intel_uncore_forcewake_put, I915_GVT);
EXPORT_SYMBOL_NS_GPL(shmem_pin_map, I915_GVT);
EXPORT_SYMBOL_NS_GPL(shmem_unpin_map, I915_GVT);
EXPORT_SYMBOL_NS_GPL(__px_dma, I915_GVT);
