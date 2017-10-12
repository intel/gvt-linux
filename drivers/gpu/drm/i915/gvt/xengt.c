/*
 * Interfaces coupled to Xen
 *
 * Copyright(c) 2011-2013 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.
 */

/*
 * NOTE:
 * This file contains hypervisor specific interactions to
 * implement the concept of mediated pass-through framework.
 * What this file provides is actually a general abstraction
 * of in-kernel device model, which is not vgt specific.
 *
 * Now temporarily in vgt code. long-term this should be
 * in hypervisor (xen/kvm) specific directory
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <linux/freezer.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>
#include <xen/xen-ops.h>
#include <xen/events.h>
#include <xen/interface/hvm/params.h>
#include <xen/interface/hvm/ioreq.h>
#include <xen/interface/hvm/hvm_op.h>
#include <xen/interface/hvm/dm_op.h>
#include <xen/interface/memory.h>
#include <xen/interface/platform.h>
#include <xen/interface/vcpu.h>

#include <i915_drv.h>
#include <i915_pvinfo.h>
#include <gvt/gvt.h>
#include "xengt.h"

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("XenGT mediated passthrough driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

struct kobject *gvt_ctrl_kobj;
static struct kset *gvt_kset;
static DEFINE_MUTEX(gvt_sysfs_lock);

struct xengt_struct xengt_priv;
const struct intel_gvt_ops *intel_gvt_ops;

static ssize_t kobj_attr_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, buf);
	return ret;
}

static ssize_t kobj_attr_store(struct kobject *kobj,
	struct attribute *attr,	const char *buf, size_t count)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->store)
		ret = kattr->store(kobj, kattr, buf, count);
	return ret;
}

/*
 * TODO
 * keep the sysfs name of create_vgt_instance no change to reuse current
 * test tool-kit. Better name should be: create_xengt_instance +
 * destroy_xengt_instance.
 */
static struct kobj_attribute xengt_instance_attr =
__ATTR(create_vgt_instance, 0220, NULL, xengt_sysfs_instance_manage);

static struct kobj_attribute xengt_vm_attr =
__ATTR(vgpu_id, 0440, xengt_sysfs_vgpu_id, NULL);

static struct kobj_attribute xengt_sch_attr =
__ATTR(schedule, 0220, NULL, xengt_sysfs_vgpu_schedule);

static struct attribute *xengt_ctrl_attrs[] = {
	&xengt_instance_attr.attr,
	NULL,   /* need to NULL terminate the list of attributes */
};

static struct attribute *xengt_vm_attrs[] = {
	&xengt_vm_attr.attr,
	&xengt_sch_attr.attr,
	NULL,   /* need to NULL terminate the list of attributes */
};

const struct sysfs_ops xengt_kobj_sysfs_ops = {
	.show   = kobj_attr_show,
	.store  = kobj_attr_store,
};

static struct kobj_type xengt_instance_ktype = {
	.sysfs_ops  = &xengt_kobj_sysfs_ops,
	.default_attrs = xengt_vm_attrs,
};

static struct kobj_type xengt_ctrl_ktype = {
	.sysfs_ops  = &xengt_kobj_sysfs_ops,
	.default_attrs = xengt_ctrl_attrs,
};

static ssize_t
device_state_read(struct file *filp, struct kobject *kobj,
		struct bin_attribute *bin_attr,
		char *buf, loff_t off, size_t count)
{
	struct xengt_hvm_dev *info = container_of((kobj), struct xengt_hvm_dev, kobj);
	struct intel_vgpu *vgpu = info->vgpu;
	void *base = info->dev_state;

	if (!count || off < 0 || (off + count > bin_attr->size) || (off & 0x3))
		return -EINVAL;

	if (info->dev_state == NULL)
		return -EINVAL;

	if (intel_gvt_ops->vgpu_save_restore(vgpu,
			buf, count, base, 0, false) != 0)
		return -EINVAL;

	memcpy(buf, base + off, count);

	return count;
}

static ssize_t
device_state_write(struct file *filp, struct kobject *kobj,
		struct bin_attribute *bin_attr,
		char *buf, loff_t off, size_t count)
{
	struct xengt_hvm_dev *info = container_of((kobj), struct xengt_hvm_dev, kobj);
	struct intel_vgpu *vgpu = info->vgpu;
	void *base = info->dev_state;

	if (!count || off < 0 || (off + count > bin_attr->size) || (off & 0x3))
		return -EINVAL;

	if (info->dev_state == NULL)
		return -EINVAL;

	memcpy(base + off, buf, count);

	if ((off + count) == bin_attr->size) {
		if (intel_gvt_ops->vgpu_save_restore(vgpu,
				buf, count, base, 0, true) != 0)
			return -EINVAL;
	}

	return count;
}

static struct bin_attribute vgpu_state_attr = {
	.attr =	{
		.name = "device_state",
		.mode = 0660
	},
	.size = MIGRATION_IMG_MAX_SIZE,
	.read = device_state_read,
	.write = device_state_write,
};

static struct intel_vgpu_type *xengt_choose_vgpu_type(
		struct xengt_hvm_params *vp)
{
	struct intel_vgpu_type *vgpu_type;
	unsigned int  i;

	for (i = 0;  i < xengt_priv.gvt->num_types; i++) {
		vgpu_type = &xengt_priv.gvt->types[i];
		if ((vgpu_type->low_gm_size >> 20) == vp->aperture_sz) {
			gvt_dbg_core("choose vgpu type:%d\n", i);
			return vgpu_type;
		}
	}

	gvt_err("specify a wrong low_gm_sz in hvm.cfg: %d\n", vp->aperture_sz);
		return NULL;
}

static int xengt_sysfs_add_instance(struct xengt_hvm_params *vp)
{
	int ret = 0;
	struct intel_vgpu *vgpu;
	struct xengt_hvm_dev *info;
	struct intel_vgpu_type *type;

	type = xengt_choose_vgpu_type(vp);
	if (type == NULL) {
		gvt_err("choose vgpu type failed");
		return -EINVAL;
	}
	mutex_lock(&gvt_sysfs_lock);
	vgpu = xengt_instance_create(vp->vm_id, type);
	mutex_unlock(&gvt_sysfs_lock);
	if (vgpu == NULL) {
		gvt_err("xengt_sysfs_add_instance failed.\n");
		ret = -EINVAL;
	} else {
		info = (struct xengt_hvm_dev *) vgpu->handle;
		xengt_priv.vgpus[vgpu->id - 1] = vgpu;
		gvt_dbg_core("add xengt instance for vm-%d with vgpu-%d.\n",
			vp->vm_id, vgpu->id);

		kobject_init(&info->kobj, &xengt_instance_ktype);
		info->kobj.kset = gvt_kset;
		/* add kobject, NULL parent indicates using kset as parent */
		ret = kobject_add(&info->kobj, NULL, "vm%u", info->vm_id);
		if (ret) {
			gvt_err("%s: kobject add error: %d\n", __func__, ret);
			kobject_put(&info->kobj);
		}

		ret = sysfs_create_bin_file(&info->kobj, &vgpu_state_attr);
		if (ret) {
			gvt_err("%s: kobject add error: %d\n", __func__, ret);
			kobject_put(&info->kobj);
		}
	}

	return ret;
}

static struct intel_vgpu *vgpu_from_vm_id(int vm_id)
{
	int i;

	/* vm_id is negtive in del_instance call */
	if (vm_id < 0)
		vm_id = -vm_id;
	for (i = 0; i < GVT_MAX_VGPU_INSTANCE; i++) {
		if (xengt_priv.vgpus[i]) {
			struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)
				(xengt_priv.vgpus[i]->handle);
			if (info->vm_id == vm_id)
				return xengt_priv.vgpus[i];
		}
	}
	return NULL;
}

static int xengt_sysfs_del_instance(struct xengt_hvm_params *vp)
{
	int ret = 0;
	struct intel_vgpu *vgpu = vgpu_from_vm_id(vp->vm_id);
	struct xengt_hvm_dev *info;

	if (vgpu) {
		gvt_dbg_core("xengt: remove vm-%d sysfs node.\n", vp->vm_id);

		info = (struct xengt_hvm_dev *) vgpu->handle;
		kobject_put(&info->kobj);

		mutex_lock(&gvt_sysfs_lock);
		xengt_priv.vgpus[vgpu->id - 1] = NULL;
		xengt_instance_destroy(vgpu);
		mutex_unlock(&gvt_sysfs_lock);
	}

	return ret;
}

static ssize_t xengt_sysfs_vgpu_id(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int i;

	for (i = 0; i < GVT_MAX_VGPU_INSTANCE; i++) {
		if (xengt_priv.vgpus[i] &&
			(kobj == &((struct xengt_hvm_dev *)
				(xengt_priv.vgpus[i]->handle))->kobj)) {
			return sprintf(buf, "%d\n", xengt_priv.vgpus[i]->id);
		}
	}
	return 0;
}

static ssize_t xengt_sysfs_instance_manage(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct xengt_hvm_params vp;
	int param_cnt;
	char param_str[64];
	int rc;
	int high_gm_sz;
	int low_gm_sz;

	/* We expect the param_str should be vmid,a,b,c (where the guest
	 * wants a MB aperture and b MB gm, and c fence registers) or -vmid
	 * (where we want to release the vgt instance).
	 */
	(void)sscanf(buf, "%63s", param_str);
	param_cnt = sscanf(param_str, "%d,%d,%d,%d,%d,%d", &vp.vm_id,
			&low_gm_sz, &high_gm_sz, &vp.fence_sz, &vp.gvt_primary,
			&vp.cap);
	vp.aperture_sz = low_gm_sz;
	vp.gm_sz = high_gm_sz + low_gm_sz;
	if (param_cnt == 1) {
		if (vp.vm_id >= 0)
			return -EINVAL;
	} else if (param_cnt == 4 || param_cnt == 5 || param_cnt == 6) {
		if (!(vp.vm_id > 0 && vp.aperture_sz > 0 &&
			vp.aperture_sz <= vp.gm_sz && vp.fence_sz > 0))
			return -EINVAL;

		if (param_cnt == 5 || param_cnt == 6) {
			/* -1/0/1 means: not-specified, non-primary, primary */
			if (vp.gvt_primary < -1 || vp.gvt_primary > 1)
				return -EINVAL;
			if (vp.cap < 0 || vp.cap > 100)
				return -EINVAL;
		} else {
			vp.cap = 0; /* default 0 means no upper cap. */
			vp.gvt_primary = -1; /* no valid value specified. */
		}
	} else
		return -EINVAL;

	rc = (vp.vm_id > 0) ? xengt_sysfs_add_instance(&vp) :
		xengt_sysfs_del_instance(&vp);

	return rc < 0 ? rc : count;
}

static int xengt_hvm_modified_memory(struct xengt_hvm_dev *info, uint64_t start_pfn)
{
	xen_dm_op_buf_t dm_buf[2];
	struct xen_dm_op op;
	struct xen_dm_op_modified_memory *header;
	struct xen_dm_op_modified_memory_extent data;
	int rc;

	memset(&op, 0, sizeof(op));
	memset(&data, 0, sizeof(data));

	op.op = XEN_DMOP_modified_memory;
	header = &op.u.modified_memory;
	header->nr_extents = 1;

	data.nr = 1;
	data.first_pfn = start_pfn;

	dm_buf[0].h = &op;
	dm_buf[0].size = sizeof(op);

	dm_buf[1].h = &data;
	dm_buf[1].size = sizeof(data);

	rc = HYPERVISOR_dm_op(info->vm_id, 2, &dm_buf);

	if (rc < 0)
		gvt_err("Cannot modified memory: %d!\n", rc);

	return rc;
}

static void xengt_logd_sync(struct xengt_hvm_dev *info)
{
	struct gvt_logd_pfn *logd, *next;

	mutex_lock(&info->logd_lock);
	rbtree_postorder_for_each_entry_safe(logd, next,
					     &info->logd_list, node)
		xengt_hvm_modified_memory(info, logd->gfn);
	mutex_unlock(&info->logd_lock);
}

static ssize_t xengt_sysfs_vgpu_schedule(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct xengt_hvm_dev *info =
		container_of((kobj), struct xengt_hvm_dev, kobj);
	struct intel_vgpu *vgpu = info->vgpu;
	int running;

	mutex_lock(&gvt_sysfs_lock);
	if (sscanf(buf, "%d", &running) != 1) {
		mutex_unlock(&gvt_sysfs_lock);
		return -EINVAL;
	}

	if (running) {
		if (info->iosrv_enabled == 0) {
			hvm_claim_ioreq_server_type(info, 1);
			xen_hvm_toggle_iorequest_server(info, true);
		}
		intel_gvt_ops->vgpu_activate(vgpu);
	} else {
		intel_gvt_ops->vgpu_deactivate(vgpu);
		if (info->iosrv_enabled != 0) {
			hvm_claim_ioreq_server_type(info, 0);
			xen_hvm_toggle_iorequest_server(info, false);
		}
		xengt_logd_sync(info);
	}

	mutex_unlock(&gvt_sysfs_lock);

	return count;
}

int xengt_sysfs_init(struct intel_gvt *gvt)
{
	int ret;

	/*
	 * TODO.
	 * keep the name of 'vgt', not 'gvt', so that current tool kit
	 * still could be used.
	 */
	gvt_kset = kset_create_and_add("vgt", NULL, kernel_kobj);
	if (!gvt_kset) {
		ret = -ENOMEM;
		goto kset_fail;
	}

	gvt_ctrl_kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
	if (!gvt_ctrl_kobj) {
		ret = -ENOMEM;
		goto ctrl_fail;
	}

	gvt_ctrl_kobj->kset = gvt_kset;
	ret = kobject_init_and_add(gvt_ctrl_kobj, &xengt_ctrl_ktype,
			NULL, "control");
	if (ret) {
		ret = -EINVAL;
		goto kobj_fail;
	}

	return 0;

kobj_fail:
	kobject_put(gvt_ctrl_kobj);
ctrl_fail:
	kset_unregister(gvt_kset);
kset_fail:
	return ret;
}

void xengt_sysfs_del(void)
{
	kobject_put(gvt_ctrl_kobj);
	kset_unregister(gvt_kset);
}

/* Translate from VM's guest pfn to machine pfn */
static unsigned long xen_g2m_pfn(domid_t vm_id, unsigned long g_pfn)
{
	struct xen_get_mfn_from_pfn pfn_arg;
	int rc;
	unsigned long pfn_list[1];

	pfn_list[0] = g_pfn;

	set_xen_guest_handle(pfn_arg.pfn_list, pfn_list);
	pfn_arg.nr_pfns = 1;
	pfn_arg.domid = vm_id;

	rc = HYPERVISOR_memory_op(XENMEM_get_mfn_from_pfn, &pfn_arg);
	if (rc < 0) {
		gvt_err("failed to get mfn for gpfn 0x%lx: %d\n", g_pfn, rc);
		return INTEL_GVT_INVALID_ADDR;
	}

	return pfn_list[0];
}

static int xen_get_max_gpfn(domid_t vm_id)
{
	domid_t dom_id = vm_id;
	int max_gpfn = HYPERVISOR_memory_op(XENMEM_maximum_gpfn, &dom_id);

	if (max_gpfn < 0)
		max_gpfn = 0;
	return max_gpfn;
}

static int xen_pause_domain(domid_t vm_id)
{
	int rc;
	struct xen_domctl domctl;

	domctl.domain = vm_id;
	domctl.cmd = XEN_DOMCTL_pausedomain;
	domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	rc = HYPERVISOR_domctl(&domctl);
	if (rc != 0)
		gvt_dbg_core("xen_pause_domain fail: %d!\n", rc);

	return rc;
}

static int xen_shutdown_domain(domid_t  vm_id)
{
	int rc;
	struct sched_remote_shutdown r;

	r.reason = SHUTDOWN_crash;
	r.domain_id = vm_id;
	rc = HYPERVISOR_sched_op(SCHEDOP_remote_shutdown, &r);
	if (rc != 0)
		gvt_dbg_core("xen_shutdown_domain failed: %d\n", rc);
	return rc;
}

static int xen_domain_iomem_perm(domid_t domain_id, uint64_t first_mfn,
							uint64_t nr_mfns, uint8_t allow_access)
{
	struct xen_domctl arg;
	int rc;

	arg.domain = domain_id;
	arg.cmd = XEN_DOMCTL_iomem_permission;
	arg.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
	arg.u.iomem_perm.first_mfn = first_mfn;
	arg.u.iomem_perm.nr_mfns = nr_mfns;
	arg.u.iomem_perm.allow_access = allow_access;
	rc = HYPERVISOR_domctl(&arg);

	return rc;
}

static int xen_get_nr_vcpu(domid_t vm_id)
{
	struct xen_domctl arg;
	int rc;

	arg.domain = vm_id;
	arg.cmd = XEN_DOMCTL_getdomaininfo;
	arg.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	rc = HYPERVISOR_domctl(&arg);
	if (rc < 0) {
		gvt_err("HYPERVISOR_domctl fail ret=%d\n", rc);
		/* assume it is UP */
		return 1;
	}

	return arg.u.getdomaininfo.max_vcpu_id + 1;
}

static int xen_hvm_memory_mapping(domid_t vm_id, uint64_t first_gfn,
		uint64_t first_mfn, uint32_t nr_mfns, uint32_t add_mapping)
{
	struct xen_domctl arg;
	int rc = 0, err = 0;
	unsigned long done = 0, mapping_sz = 64;

	if (add_mapping) {
		rc = xen_domain_iomem_perm(vm_id, first_mfn, nr_mfns, 1);
		if (rc < 0) {
			gvt_err("xen_domain_iomem_perm failed: %d\n",	rc);
			return rc;
		}
	}

	arg.domain = vm_id;
	arg.cmd = XEN_DOMCTL_memory_mapping;
	arg.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
	arg.u.memory_mapping.add_mapping = add_mapping;

retry:
	if (nr_mfns > 0 && mapping_sz > 0) {
		while (done < nr_mfns) {
			mapping_sz = min(nr_mfns - done, mapping_sz);
			arg.u.memory_mapping.nr_mfns = mapping_sz;
			arg.u.memory_mapping.first_gfn = first_gfn + done;
			arg.u.memory_mapping.first_mfn = first_mfn + done;
			err = HYPERVISOR_domctl(&arg);
			if (err == -E2BIG) {
				mapping_sz /= 2;
				goto retry;
			}
			//Save first error status.
			if (!rc)
				rc = err;

			if (err && add_mapping != DPCI_REMOVE_MAPPING)
				break;
			done += mapping_sz;
		}

		//Undo operation, if some error to mapping.
		if (rc && add_mapping != DPCI_REMOVE_MAPPING) {
			xen_hvm_memory_mapping(vm_id, first_gfn, first_mfn,
						nr_mfns, DPCI_REMOVE_MAPPING);
		}
	}

	if (rc < 0) {
		gvt_err("map fail: %d gfn:0x%llx mfn:0x%llx nr:%d\n",
				rc, first_gfn, first_mfn, nr_mfns);
		return rc;
	}

	if (!add_mapping) {
		rc = xen_domain_iomem_perm(vm_id, first_mfn, nr_mfns, 0);
		if (rc < 0) {
			gvt_err("xen_domain_iomem_perm failed: %d\n", rc);
			return rc;
		}
	}

	return rc;
}

static int xen_hvm_create_iorequest_server(struct xengt_hvm_dev *info)
{
	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_create_ioreq_server *data;
	int r;

	memset(&op, 0, sizeof(op));

	op.op = XEN_DMOP_create_ioreq_server;
	data = &op.u.create_ioreq_server;
	data->handle_bufioreq = 0;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	r = HYPERVISOR_dm_op(info->vm_id, 1, &dm_buf);
	if (r < 0) {
		gvt_err("Cannot create io-requset server: %d!\n", r);
		return r;
	}
	info->iosrv_id = data->id;

	return r;
}

static int xen_hvm_toggle_iorequest_server(struct xengt_hvm_dev *info, bool enable)
{
	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_set_ioreq_server_state *data;
	int r;

	if (info->iosrv_enabled == !!enable)
		return 0;

	info->iosrv_enabled = !!enable;

	memset(&op, 0, sizeof(op));

	op.op = XEN_DMOP_set_ioreq_server_state;
	data = &op.u.set_ioreq_server_state;
	data->id = info->iosrv_id;
	data->enabled = !!enable;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	r = HYPERVISOR_dm_op(info->vm_id, 1, &dm_buf);
	if (r < 0) {
		gvt_err("Cannot %s io-request server: %d!\n",
			enable ? "enable" : "disbale",  r);
		return r;
	}

	return r;
}

static int xen_hvm_get_ioreq_pfn(struct xengt_hvm_dev *info, uint64_t *value)
{
	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_get_ioreq_server_info *data;
	int r;

	memset(&op, 0, sizeof(op));

	op.op = XEN_DMOP_get_ioreq_server_info;
	data = &op.u.get_ioreq_server_info;
	data->id = info->iosrv_id;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	r = HYPERVISOR_dm_op(info->vm_id, 1, &dm_buf);
	if (r < 0) {
		gvt_err("Cannot get ioreq pfn: %d!\n", r);
		return r;
	}
	*value = data->ioreq_pfn;
	return r;
}

static int xen_hvm_destroy_iorequest_server(struct xengt_hvm_dev *info)
{
	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_destroy_ioreq_server *data;
	int r;

	memset(&op, 0, sizeof(op));

	op.op = XEN_DMOP_destroy_ioreq_server;
	data = &op.u.destroy_ioreq_server;
	data->id = info->iosrv_id;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	r = HYPERVISOR_dm_op(info->vm_id, 1, &dm_buf);
	if (r < 0) {
		gvt_err("Cannot destroy io-request server(%d): %d!\n",
			info->iosrv_id, r);
		return r;
	}
	info->iosrv_id = 0;

	return r;
}

static struct vm_struct *xen_hvm_map_iopage(struct xengt_hvm_dev *info)
{
	uint64_t ioreq_pfn;
	int rc;

	rc = xen_hvm_create_iorequest_server(info);
	if (rc < 0)
		return NULL;
	rc = xen_hvm_get_ioreq_pfn(info, &ioreq_pfn);
	if (rc < 0) {
		xen_hvm_destroy_iorequest_server(info);
		return NULL;
	}

	return xen_remap_domain_mfn_range_in_kernel(ioreq_pfn, 1, info->vm_id);
}

static int xen_hvm_map_io_range_to_ioreq_server(struct xengt_hvm_dev *info,
		int is_mmio, uint64_t start, uint64_t end, int map)
{
	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_ioreq_server_range *data;
	int r;

	memset(&op, 0, sizeof(op));

	op.op = map ? XEN_DMOP_map_io_range_to_ioreq_server :
		XEN_DMOP_unmap_io_range_from_ioreq_server;
	data = map ? &op.u.map_io_range_to_ioreq_server :
		&op.u.unmap_io_range_from_ioreq_server;
	data->id = info->iosrv_id;
	data->type = is_mmio ? XEN_DMOP_IO_RANGE_MEMORY :
		XEN_DMOP_IO_RANGE_PORT;
	data->start = start;
	data->end = end;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	r = HYPERVISOR_dm_op(info->vm_id, 1, &dm_buf);
	if (r < 0) {
		gvt_err("Couldn't %s io_range 0x%llx ~ 0x%llx, vm_id:%d:%d\n",
			map ? "map" : "unmap",
			start, end, info->vm_id, r);
	}
	return r;
}

static int xen_hvm_map_pcidev_to_ioreq_server(struct xengt_hvm_dev *info,
					uint64_t sbdf)
{
	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_ioreq_server_range *data;
	int r;

	memset(&op, 0, sizeof(op));

	op.op = XEN_DMOP_map_io_range_to_ioreq_server;
	data = &op.u.map_io_range_to_ioreq_server;
	data->id = info->iosrv_id;
	data->type = XEN_DMOP_IO_RANGE_PCI;
	data->start = data->end = sbdf;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	r = HYPERVISOR_dm_op(info->vm_id, 1, &dm_buf);
	if (r < 0)
		gvt_err("Cannot map pci_dev to ioreq_server: %d!\n", r);

	return r;
}

static int hvm_claim_ioreq_server_type(struct xengt_hvm_dev *info,
		uint32_t set)
{

	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_map_mem_type_to_ioreq_server *data;
	int r;

	memset(&op, 0, sizeof(op));

	op.op = XEN_DMOP_map_mem_type_to_ioreq_server;
	data = &op.u.map_mem_type_to_ioreq_server;
	data->id = info->iosrv_id;
	data->type = HVMMEM_ioreq_server;
	data->flags = (set == 1) ? XEN_DMOP_IOREQ_MEM_ACCESS_WRITE : 0;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	r = HYPERVISOR_dm_op(info->vm_id, 1, &dm_buf);
	if (r < 0)
		gvt_err("Cannot map mem type to ioreq_server\n");

	return r;
}

static int xen_hvm_set_mem_type(domid_t vm_id, uint16_t mem_type,
		uint64_t first_pfn, uint64_t nr)
{
	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_set_mem_type *data;
	int r;

	memset(&op, 0, sizeof(op));

	op.op = XEN_DMOP_set_mem_type;
	data = &op.u.set_mem_type;

	data->mem_type = mem_type;
	data->first_pfn = first_pfn;
	data->nr = nr;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	r = HYPERVISOR_dm_op(vm_id, 1, &dm_buf);
	if (r < 0) {
		gvt_err("Cannot set mem type for 0x%llx ~ 0x%llx, memtype: %x\n",
			first_pfn, first_pfn+nr, mem_type);
	}
	return r;
}

static int xen_hvm_wp_page_to_ioreq_server(struct xengt_hvm_dev *info,
		unsigned long page, bool set)
{
	int rc = 0;
	uint16_t mem_type;

	mem_type = set ? HVMMEM_ioreq_server : HVMMEM_ram_rw;
	rc = xen_hvm_set_mem_type(info->vm_id, mem_type, page, 1);
	if (rc < 0) {
		gvt_err("set mem type of page 0x%lx to %s fail - %d!\n", page,
				set ? "HVMMEM_ioreq_server" : "HVMMEM_ram_rw", rc);
	}

	return rc;
}

static int xengt_map_gfn_to_mfn(unsigned long handle, unsigned long gfn,
	unsigned long mfn, unsigned int nr, bool map)
{
	int rc;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)handle;

	if (!info)
		return -EINVAL;

	if (info->on_destroy)
		return 0;

	rc = xen_hvm_memory_mapping(info->vm_id, gfn, mfn, nr,
			map ? DPCI_ADD_MAPPING : DPCI_REMOVE_MAPPING);
	if (rc != 0)
		gvt_err("xen_hvm_memory_mapping failed: %d\n", rc);
	return rc;
}

static int xengt_set_trap_area(unsigned long handle, u64 start,
							u64 end, bool map)
{
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)handle;

	if (!info)
		return -EINVAL;

	return xen_hvm_map_io_range_to_ioreq_server(info, 1, start, end, map);
}

static int xengt_set_wp_page(unsigned long handle, u64 gfn)
{
	int r;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)handle;

	if (!info)
		return -EINVAL;

	if (info->on_destroy)
		return 0;

	r = xen_hvm_wp_page_to_ioreq_server(info, gfn, true);
	if (r) {
		gvt_err("fail to set write protection.\n");
		return -EFAULT;
	}

	return 0;
}

static int xengt_unset_wp_page(unsigned long handle, u64 gfn)
{
	int r;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)handle;

	if (!info)
		return -EINVAL;

	if (info->on_destroy)
		return 0;

	r = xen_hvm_wp_page_to_ioreq_server(info, gfn, false);
	if (r) {
		gvt_err("fail to clear write protection.\n");
		return -EFAULT;
	}

	return 0;
}

static int xengt_hvm_vmem_init(struct intel_vgpu *vgpu)
{
	unsigned long i, j, gpfn, count;
	unsigned long nr_low_1mb_bkt, nr_high_bkt, nr_high_4k_bkt;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)vgpu->handle;

	if (!info->vm_id)
		return 0;

	info->vmem_sz = xen_get_max_gpfn(info->vm_id);
	info->vmem_sz <<= PAGE_SHIFT;

	nr_low_1mb_bkt = VMEM_1MB >> PAGE_SHIFT;
	nr_high_bkt = (info->vmem_sz >> VMEM_BUCK_SHIFT);
	nr_high_4k_bkt = (info->vmem_sz >> PAGE_SHIFT);

	info->vmem_vma_low_1mb =
		vzalloc(sizeof(*info->vmem_vma) * nr_low_1mb_bkt);
	info->vmem_vma =
		vzalloc(sizeof(*info->vmem_vma) * nr_high_bkt);
	info->vmem_vma_4k = /* TODO: really needs so big array for every page? */
		vzalloc(sizeof(*info->vmem_vma) * nr_high_4k_bkt);

	if (info->vmem_vma_low_1mb == NULL || info->vmem_vma == NULL ||
		info->vmem_vma_4k == NULL) {
		gvt_err("Insufficient memory for vmem_vma, vmem_sz=0x%llx\n",
				info->vmem_sz);
		goto err;
	}

	/* map the low 1MB memory */
	for (i = 0; i < nr_low_1mb_bkt; i++) {
		info->vmem_vma_low_1mb[i] =
			xen_remap_domain_mfn_range_in_kernel(i, 1, info->vm_id);

		if (info->vmem_vma_low_1mb[i] != NULL)
			continue;

		/* Don't warn on [0xa0000, 0x100000): a known non-RAM hole */
		if (i < (0xa0000 >> PAGE_SHIFT))
			gvt_err("VM%d: can't map GPFN %ld!\n", info->vm_id, i);
	}

	count = 0;
	/* map the >1MB memory */
	for (i = 1; i < nr_high_bkt; i++) {
		gpfn = i << (VMEM_BUCK_SHIFT - PAGE_SHIFT);
		info->vmem_vma[i] = xen_remap_domain_mfn_range_in_kernel(
				gpfn, VMEM_BUCK_SIZE >> PAGE_SHIFT, info->vm_id);

		if (info->vmem_vma[i] != NULL)
			continue;

		/* for <4G GPFNs: skip the hole after low_mem_max_gpfn */
		if (gpfn < (1 << (32 - PAGE_SHIFT)) &&
			vgpu->low_mem_max_gpfn != 0 &&
			gpfn > vgpu->low_mem_max_gpfn)
			continue;

		for (j = gpfn;
		     j < ((i + 1) << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
		     j++) {
			info->vmem_vma_4k[j] =
				xen_remap_domain_mfn_range_in_kernel(j, 1,
						info->vm_id);

			if (info->vmem_vma_4k[j]) {
				count++;
				gvt_dbg_mm("map 4k gpa (%lx)\n", j << PAGE_SHIFT);
			}
		}

		/* To reduce the number of err messages(some of them, due to
		 * the MMIO hole, are spurious and harmless) we only print a
		 * message if it's at every 64MB boundary or >4GB memory.
		 */
		if (!info->vmem_vma_4k[gpfn] &&
			((i % 64 == 0) || (i >= (1ULL << (32 - VMEM_BUCK_SHIFT)))))
			gvt_dbg_mm("VM%d: can't map gpfn 0x%lx\n", info->vm_id, gpfn);
	}

	return 0;
err:
	vfree(info->vmem_vma);
	vfree(info->vmem_vma_low_1mb);
	vfree(info->vmem_vma_4k);
	info->vmem_vma = info->vmem_vma_low_1mb = info->vmem_vma_4k = NULL;
	return -ENOMEM;
}

static void xengt_vmem_destroy(struct intel_vgpu *vgpu)
{
	int i, j;
	unsigned long nr_low_1mb_bkt, nr_high_bkt, nr_high_bkt_4k;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)vgpu->handle;

	if (!info || info->vm_id == 0)
		return;

	/*
	 * Maybe the VM hasn't accessed GEN MMIO(e.g., still in the legacy VGA
	 * mode), so no mapping is created yet.
	 */
	if (info->vmem_vma == NULL && info->vmem_vma_low_1mb == NULL)
		return;

	nr_low_1mb_bkt = VMEM_1MB >> PAGE_SHIFT;
	nr_high_bkt = (info->vmem_sz >> VMEM_BUCK_SHIFT);
	nr_high_bkt_4k = (info->vmem_sz >> PAGE_SHIFT);

	for (i = 0; i < nr_low_1mb_bkt; i++) {
		if (info->vmem_vma_low_1mb[i] == NULL)
			continue;
		xen_unmap_domain_mfn_range_in_kernel(info->vmem_vma_low_1mb[i],
				1, info->vm_id);
	}

	for (i = 1; i < nr_high_bkt; i++) {
		if (info->vmem_vma[i] == NULL) {
			for (j = (i << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
			     j < ((i + 1) << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
			     j++) {
				if (info->vmem_vma_4k[j] == NULL)
					continue;
				xen_unmap_domain_mfn_range_in_kernel(
					info->vmem_vma_4k[j], 1, info->vm_id);
			}
			continue;
		}
		xen_unmap_domain_mfn_range_in_kernel(
			info->vmem_vma[i], VMEM_BUCK_SIZE >> PAGE_SHIFT,
			info->vm_id);
	}

	vfree(info->vmem_vma);
	vfree(info->vmem_vma_low_1mb);
	vfree(info->vmem_vma_4k);
}

static uint64_t intel_vgpu_get_bar0_addr(struct intel_vgpu *vgpu)
{
	u32 start_lo, start_hi;
	u32 mem_type;
	int pos = PCI_BASE_ADDRESS_0;

	start_lo = (*(u32 *)(vgpu->cfg_space.virtual_cfg_space + pos)) &
				PCI_BASE_ADDRESS_MEM_MASK;
	mem_type = (*(u32 *)(vgpu->cfg_space.virtual_cfg_space + pos)) &
				PCI_BASE_ADDRESS_MEM_TYPE_MASK;

	switch (mem_type) {
	case PCI_BASE_ADDRESS_MEM_TYPE_64:
		start_hi = (*(u32 *)(vgpu->cfg_space.virtual_cfg_space
					+ pos + 4));
		break;
	case PCI_BASE_ADDRESS_MEM_TYPE_32:
	case PCI_BASE_ADDRESS_MEM_TYPE_1M:
		/* 1M mem BAR treated as 32-bit BAR */
	default:
		/* mem unknown type treated as 32-bit BAR */
		start_hi = 0;
		break;
	}

	return ((u64)start_hi << 32) | start_lo;
}

static int xengt_hvm_mmio_emulation(struct intel_vgpu *vgpu,
		struct ioreq *req)
{
	int i, sign;
	void *gva;
	unsigned long gpa;
	uint64_t base = intel_vgpu_get_bar0_addr(vgpu);
	uint64_t tmp;
	int pvinfo_page;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)vgpu->handle;

	if (info->vmem_vma == NULL) {
		tmp = req->addr - base;
		pvinfo_page = (tmp >= VGT_PVINFO_PAGE
				&& tmp < (VGT_PVINFO_PAGE + VGT_PVINFO_SIZE));
		/*
		 * hvmloader will read PVINFO to identify if HVM is in VGT
		 * or VTD. So we don't trigger HVM mapping logic here.
		 */
		if (!pvinfo_page && xengt_hvm_vmem_init(vgpu) < 0) {
			gvt_err("can not map the memory of VM%d!!!\n",
					info->vm_id);
			return -EINVAL;
		}
	}

	sign = req->df ? -1 : 1;

	if (req->dir == IOREQ_READ) {
		/* MMIO READ */
		if (!req->data_is_ptr) {
			if (req->count != 1)
				goto err_ioreq_count;

			if (intel_gvt_ops->emulate_mmio_read(vgpu, req->addr,
						&req->data, req->size))
				return -EINVAL;
		} else {
			for (i = 0; i < req->count; i++) {
				if (intel_gvt_ops->emulate_mmio_read(vgpu,
					req->addr + sign * i * req->size,
					&tmp, req->size))
					return -EINVAL;

				gpa = req->data + sign * i * req->size;
				gva = xengt_gpa_to_va((unsigned long)info, gpa);
				if (!gva) {
					gvt_err("vGT: can not read gpa = 0x%lx!!!\n", gpa);
					return -EFAULT;
				}
				memcpy(gva, &tmp, req->size);
			}
		}
	} else { /* MMIO Write */
		if (!req->data_is_ptr) {
			if (req->count != 1)
				goto err_ioreq_count;
			if (intel_gvt_ops->emulate_mmio_write(vgpu,
						req->addr,
						&req->data, req->size))
				return -EINVAL;
		} else {
			for (i = 0; i < req->count; i++) {
				gpa = req->data + sign * i * req->size;
				gva = xengt_gpa_to_va((unsigned long)info, gpa);
				if (!gva) {
					gvt_err("VM %d mmio access invalid gpa: 0x%lx.\n",
						info->vm_id, gpa);
					return -EFAULT;
				}

				memcpy(&tmp, gva, req->size);
				if (intel_gvt_ops->emulate_mmio_write(vgpu,
						req->addr +	sign * i * req->size,
						&tmp, req->size))
					return -EINVAL;
			}
		}
	}

	return 0;

err_ioreq_count:
	gvt_err("VM(%d): Unexpected %s request count(%d)\n",
		info->vm_id, req->dir == IOREQ_READ ? "read" : "write",
		req->count);
	return -EINVAL;
}

static bool xengt_write_cfg_space(struct intel_vgpu *vgpu,
	uint64_t addr, unsigned int bytes, unsigned long val)
{
	/* Low 32 bit of addr is real address, high 32 bit is bdf */
	unsigned int port = addr & 0xffffffff;

	if (port == PCI_VENDOR_ID) {
		/* Low 20 bit of val are valid low mem gpfn. */
		val &= 0xfffff;
		vgpu->low_mem_max_gpfn = val;
		return true;
	}
	if (intel_gvt_ops->emulate_cfg_write(vgpu, port, &val, bytes))
		return false;
	return true;
}

static bool xengt_read_cfg_space(struct intel_vgpu *vgpu,
	uint64_t addr, unsigned int bytes, unsigned long *val)
{
	unsigned long data;
	/* Low 32 bit of addr is real address, high 32 bit is bdf */
	unsigned int port = addr & 0xffffffff;

	if (intel_gvt_ops->emulate_cfg_read(vgpu, port, &data, bytes))
		return false;
	memcpy(val, &data, bytes);
	return true;
}

static int xengt_hvm_pio_emulation(struct intel_vgpu *vgpu, struct ioreq *ioreq)
{
	int sign;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)vgpu->handle;

	sign = ioreq->df ? -1 : 1;

	if (ioreq->dir == IOREQ_READ) {
		/* PIO READ */
		if (!ioreq->data_is_ptr) {
			if (!xengt_read_cfg_space(vgpu,
				ioreq->addr,
				ioreq->size,
				(unsigned long *)&ioreq->data))
				return -EINVAL;
		} else {
			gvt_err("VGT: _hvm_pio_emulation read data_ptr %lx\n",
					(long)ioreq->data);
			goto err_data_ptr;
		}
	} else {
		/* PIO WRITE */
		if (!ioreq->data_is_ptr) {
			if (!xengt_write_cfg_space(vgpu,
				ioreq->addr,
				ioreq->size,
				(unsigned long)ioreq->data))
				return -EINVAL;
		} else {
			gvt_err("VGT: _hvm_pio_emulation write data_ptr %lx\n",
					(long)ioreq->data);
			goto err_data_ptr;
		}
	}
	return 0;
err_data_ptr:
	/* The data pointer of emulation is guest physical address
	 * so far, which goes to Qemu emulation, but hard for
	 * vGT driver which doesn't know gpn_2_mfn translation.
	 * We may ask hypervisor to use mfn for vGT driver.
	 * We mark it as unsupported in case guest really it.
	 */
	gvt_err("VM(%d): Unsupported %s data_ptr(%lx)\n",
		info->vm_id, ioreq->dir == IOREQ_READ ? "read" : "write",
		(long)ioreq->data);
	return -EINVAL;
}

static int xengt_do_ioreq(struct intel_vgpu *vgpu, struct ioreq *ioreq)
{
	int rc = 0;

	BUG_ON(ioreq->state != STATE_IOREQ_INPROCESS);

	switch (ioreq->type) {
	case IOREQ_TYPE_PCI_CONFIG:
		rc = xengt_hvm_pio_emulation(vgpu, ioreq);
		break;
	case IOREQ_TYPE_COPY:   /* MMIO */
		rc = xengt_hvm_mmio_emulation(vgpu, ioreq);
		break;
	case IOREQ_TYPE_INVALIDATE:
	case IOREQ_TYPE_TIMEOFFSET:
		break;
	default:
		gvt_err("Unknown ioreq type %x addr %llx size %u state %u\n",
			ioreq->type, ioreq->addr, ioreq->size, ioreq->state);
		rc = -EINVAL;
		break;
	}

	wmb();

	return rc;
}

static struct ioreq *xengt_get_hvm_ioreq(struct intel_vgpu *vgpu, int vcpu)
{
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)vgpu->handle;
	ioreq_t *req = &(info->iopage->vcpu_ioreq[vcpu]);

	if (req->state != STATE_IOREQ_READY)
		return NULL;

	rmb();

	req->state = STATE_IOREQ_INPROCESS;
	return req;
}

static int xengt_emulation_thread(void *priv)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *)priv;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)vgpu->handle;

	int vcpu;
	int nr_vcpus = info->nr_vcpu;

	struct ioreq *ioreq;
	int irq, ret;

	gvt_dbg_core("start kthread for VM%d\n", info->vm_id);

	set_freezable();
	while (1) {
		ret = wait_event_freezable(info->io_event_wq,
			kthread_should_stop() ||
			bitmap_weight(info->ioreq_pending, nr_vcpus));

		if (kthread_should_stop())
			return 0;

		if (ret)
			gvt_err("Emulation thread(%d) waken up"
				 "by unexpected signal!\n", info->vm_id);

		for (vcpu = 0; vcpu < nr_vcpus; vcpu++) {
			if (!test_and_clear_bit(vcpu, info->ioreq_pending))
				continue;

			ioreq = xengt_get_hvm_ioreq(vgpu, vcpu);
			if (ioreq == NULL)
				continue;

			if (xengt_do_ioreq(vgpu, ioreq)) {
				xen_pause_domain(info->vm_id);
				xen_shutdown_domain(info->vm_id);
			}

			ioreq->state = STATE_IORESP_READY;

			irq = info->evtchn_irq[vcpu];
			notify_remote_via_irq(irq);
		}
	}

	BUG(); /* It's actually impossible to reach here */
	return 0;
}

static inline void xengt_raise_emulation_request(struct intel_vgpu *vgpu,
	int vcpu)
{
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)vgpu->handle;

	set_bit(vcpu, info->ioreq_pending);
	wake_up(&info->io_event_wq);
}

static irqreturn_t xengt_io_req_handler(int irq, void *dev)
{
	struct intel_vgpu *vgpu;
	struct xengt_hvm_dev *info;
	int vcpu;

	vgpu = (struct intel_vgpu *)dev;
	info = (struct xengt_hvm_dev *)vgpu->handle;

	for (vcpu = 0; vcpu < info->nr_vcpu; vcpu++) {
		if (info->evtchn_irq[vcpu] == irq)
			break;
	}
	if (vcpu == info->nr_vcpu) {
		/*opps, irq is not the registered one*/
		gvt_dbg_core("Received a IOREQ w/o vcpu target\n");
		gvt_dbg_core("Possible a false request from event binding\n");
		return IRQ_NONE;
	}

	xengt_raise_emulation_request(vgpu, vcpu);

	return IRQ_HANDLED;
}

static void xengt_logd_destroy(struct xengt_hvm_dev *info)
{
	struct gvt_logd_pfn *logd;
	struct rb_node *node = NULL;

	mutex_lock(&info->logd_lock);
	while ((node = rb_first(&info->logd_list))) {
		logd = rb_entry(node, struct gvt_logd_pfn, node);
		rb_erase(&logd->node, &info->logd_list);
		kfree(logd);
	}
	mutex_unlock(&info->logd_lock);
}

void xengt_instance_destroy(struct intel_vgpu *vgpu)
{
	struct xengt_hvm_dev *info;
	int vcpu;

	intel_gvt_ops->vgpu_deactivate(vgpu);

	info = (struct xengt_hvm_dev *)vgpu->handle;
	if (info == NULL)
		goto free_vgpu;

	info->on_destroy = true;
	if (info->emulation_thread != NULL)
		kthread_stop(info->emulation_thread);

	if (!info->nr_vcpu || info->evtchn_irq == NULL)
		goto out1;

	if (info->iosrv_enabled != 0) {
		hvm_claim_ioreq_server_type(info, 0);
		xen_hvm_toggle_iorequest_server(info, false);
	}

	if (info->iosrv_id != 0)
		xen_hvm_destroy_iorequest_server(info);

	for (vcpu = 0; vcpu < info->nr_vcpu; vcpu++) {
		if (info->evtchn_irq[vcpu] >= 0)
			unbind_from_irqhandler(info->evtchn_irq[vcpu], vgpu);
	}

	if (info->iopage_vma != NULL) {
		xen_unmap_domain_mfn_range_in_kernel(info->iopage_vma, 1,
				info->vm_id);
		info->iopage_vma = NULL;
	}

	kfree(info->evtchn_irq);

	if (info->dev_state)
		vfree(info->dev_state);

out1:
	xengt_logd_destroy(info);
	xengt_vmem_destroy(vgpu);
	vgpu->handle = (unsigned long)NULL;
	kfree(info);

free_vgpu:
	if (vgpu)
		intel_gvt_ops->vgpu_destroy(vgpu);
}

struct intel_vgpu *xengt_instance_create(domid_t vm_id,
		struct intel_vgpu_type *vgpu_type)
{
	struct xengt_hvm_dev *info;
	struct intel_vgpu *vgpu;
	int vcpu, irq, rc = 0;
	struct task_struct *thread;

	if (!intel_gvt_ops || !xengt_priv.gvt)
		return NULL;

	vgpu = intel_gvt_ops->vgpu_create(xengt_priv.gvt, vgpu_type);
	if (IS_ERR(vgpu))
		return NULL;
	intel_gvt_ops->vgpu_activate(vgpu);
	info = kzalloc(sizeof(struct xengt_hvm_dev), GFP_KERNEL);
	if (info == NULL)
		goto err;

	info->vm_id = vm_id;
	info->vgpu = vgpu;
	vgpu->handle = (unsigned long)info;
	info->iopage_vma = xen_hvm_map_iopage(info);
	if (info->iopage_vma == NULL) {
		gvt_err("Failed to map HVM I/O page for VM%d\n", vm_id);
		rc = -EFAULT;
		goto err;
	}
	info->iopage = info->iopage_vma->addr;
	init_waitqueue_head(&info->io_event_wq);
	info->nr_vcpu = xen_get_nr_vcpu(vm_id);
	info->evtchn_irq = kmalloc(info->nr_vcpu * sizeof(int), GFP_KERNEL);
	if (info->evtchn_irq == NULL) {
		rc = -ENOMEM;
		goto err;
	}
	for (vcpu = 0; vcpu < info->nr_vcpu; vcpu++)
		info->evtchn_irq[vcpu] = -1;

	info->dev_state = vzalloc(MIGRATION_IMG_MAX_SIZE);
	if (info->dev_state == NULL) {
		rc = -ENOMEM;
		goto err;
	}

	rc = xen_hvm_map_pcidev_to_ioreq_server(info,
			PCI_BDF2(0, 0x10));//FIXME hack the dev bdf
	if (rc < 0)
		goto err;

	rc = hvm_claim_ioreq_server_type(info, 1);
	if (rc < 0)
		goto err;

	rc = xen_hvm_toggle_iorequest_server(info, 1);
	if (rc < 0)
		goto err;

	for (vcpu = 0; vcpu < info->nr_vcpu; vcpu++) {
		irq = bind_interdomain_evtchn_to_irqhandler(vm_id,
				info->iopage->vcpu_ioreq[vcpu].vp_eport,
				xengt_io_req_handler, 0,
				"xengt", vgpu);
		if (irq < 0) {
			rc = irq;
			gvt_err("Failed to bind event channle: %d\n", rc);
			goto err;
		}
		info->evtchn_irq[vcpu] = irq;
	}

	thread = kthread_run(xengt_emulation_thread, vgpu,
			"xengt_emulation:%d", vm_id);
	if (IS_ERR(thread))
		goto err;
	info->emulation_thread = thread;

	return vgpu;

err:
	xengt_instance_destroy(vgpu);
	return NULL;
}

static void *xengt_gpa_to_va(unsigned long handle, unsigned long gpa)
{
	unsigned long buck_index, buck_4k_index;
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)handle;

	if (!info->vm_id)
		return (char *)mfn_to_virt(gpa>>PAGE_SHIFT) +
				(gpa & (PAGE_SIZE-1));

	if (gpa > info->vmem_sz) {
		if (info->vmem_sz == 0)
			xengt_hvm_vmem_init(info->vgpu);
		else {
			gvt_err("vGT try to access invalid gpa=0x%lx\n", gpa);
			return NULL;
		}
	}

	/* handle the low 1MB memory */
	if (gpa < VMEM_1MB) {
		buck_index = gpa >> PAGE_SHIFT;
		if (!info->vmem_vma_low_1mb[buck_index])
			return NULL;

		return (char *)(info->vmem_vma_low_1mb[buck_index]->addr) +
			(gpa & ~PAGE_MASK);

	}

	/* handle the >1MB memory */
	buck_index = gpa >> VMEM_BUCK_SHIFT;

	if (!info->vmem_vma[buck_index]) {
		buck_4k_index = gpa >> PAGE_SHIFT;
		if (!info->vmem_vma_4k[buck_4k_index]) {
			if (buck_4k_index > info->vgpu->low_mem_max_gpfn)
				gvt_err("vGT failed to map gpa=0x%lx?\n", gpa);
			return NULL;
		}

		return (char *)(info->vmem_vma_4k[buck_4k_index]->addr) +
			(gpa & ~PAGE_MASK);
	}

	return (char *)(info->vmem_vma[buck_index]->addr) +
		(gpa & (VMEM_BUCK_SIZE - 1));
}

static int xengt_host_init(struct device *dev, void *gvt, const void *ops)
{
	int ret = -EFAULT;

	if (!gvt || !ops)
		return -EINVAL;

	xengt_priv.gvt = (struct intel_gvt *)gvt;
	intel_gvt_ops = (const struct intel_gvt_ops *)ops;

	ret = xengt_sysfs_init(xengt_priv.gvt);
	if (ret) {
		xengt_priv.gvt = NULL;
		intel_gvt_ops = NULL;
	}

	return ret;
}

static void xengt_host_exit(struct device *dev, void *gvt)
{
	xengt_sysfs_del();
	xengt_priv.gvt = NULL;
	intel_gvt_ops = NULL;
}

static int xengt_attach_vgpu(void *vgpu, unsigned long *handle)
{
	/* nothing to do here */
	return 0;
}

static void xengt_detach_vgpu(unsigned long handle)
{
	/* nothing to do here */
}

static int xengt_inject_msi(unsigned long handle, u32 addr_lo, u16 data)
{
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)handle;
	xen_dm_op_buf_t dm_buf;
	struct xen_dm_op op;
	struct xen_dm_op_inject_msi *arg;

	memset(&op, 0, sizeof(op));

	op.op = XEN_DMOP_inject_msi;
	arg = &op.u.inject_msi;

	arg->addr = (uint64_aligned_t)addr_lo;
	arg->data = (uint32_t)data;

	dm_buf.h = &op;
	dm_buf.size = sizeof(op);

	return HYPERVISOR_dm_op(info->vm_id, 1, &dm_buf);
}

static unsigned long xengt_virt_to_mfn(void *addr)
{
	return virt_to_mfn(addr);
}

static int xengt_read_gpa(unsigned long handle, unsigned long gpa,
							void *buf, unsigned long len)
{
	void *va = NULL;

	if (!handle)
		return -EINVAL;

	va = xengt_gpa_to_va(handle, gpa);
	if (!va) {
		gvt_err("GVT: can not read gpa = 0x%lx!!!\n", gpa);
		return -EFAULT;
	}
	memcpy(buf, va, len);
	return 0;
}

static int xengt_write_gpa(unsigned long handle, unsigned long gpa,
							void *buf, unsigned long len)
{
	void *va = NULL;

	if (!handle)
		return -EINVAL;

	va = xengt_gpa_to_va(handle, gpa);
	if (!va) {
		gvt_err("GVT: can not write gpa = 0x%lx!!!\n", gpa);
		return -EFAULT;
	}
	memcpy(va, buf, len);
	return 0;
}

static struct gvt_logd_pfn *xengt_find_logd(struct xengt_hvm_dev *info,
							unsigned long gfn)
{
	struct gvt_logd_pfn *logd;
	struct rb_node *node = info->logd_list.rb_node;

	while (node) {
		logd = rb_entry(node, struct gvt_logd_pfn, node);

		if (gfn < logd->gfn)
			node = node->rb_left;
		else if (gfn > logd->gfn)
			node = node->rb_right;
		else
			return logd;
	}
	return NULL;
}

static void xengt_logd_add(struct xengt_hvm_dev *info, unsigned long gfn)
{
	struct gvt_logd_pfn *logd, *itr;
	struct rb_node **node = &info->logd_list.rb_node, *parent = NULL;

	mutex_lock(&info->logd_lock);

	logd = xengt_find_logd(info, gfn);
	if (logd) {
		atomic_inc(&logd->ref_count);
		mutex_unlock(&info->logd_lock);
		return;
	}

	logd = kzalloc(sizeof(struct gvt_logd_pfn), GFP_KERNEL);
	if (!logd)
		goto exit;

	logd->gfn = gfn;
	atomic_set(&logd->ref_count, 1);

	while (*node) {
		parent = *node;
		itr = rb_entry(parent, struct gvt_logd_pfn, node);

		if (logd->gfn < itr->gfn)
			node = &parent->rb_left;
		else
			node = &parent->rb_right;
	}
	rb_link_node(&logd->node, parent, node);
	rb_insert_color(&logd->node, &info->logd_list);

exit:
	mutex_unlock(&info->logd_lock);
	return;
}

static unsigned long xengt_gfn_to_pfn(unsigned long handle, unsigned long gfn)
{
	struct xengt_hvm_dev *info = (struct xengt_hvm_dev *)handle;
	unsigned long pfn;

	if (!info)
		return -EINVAL;

	pfn = xen_g2m_pfn(info->vm_id, gfn);

	if (pfn != INTEL_GVT_INVALID_ADDR)
		xengt_logd_add(info, gfn);

	return pfn;
}

struct intel_gvt_mpt xengt_mpt = {
	//.detect_host = xengt_detect_host,
	.host_init = xengt_host_init,
	.host_exit = xengt_host_exit,
	.attach_vgpu = xengt_attach_vgpu,
	.detach_vgpu = xengt_detach_vgpu,
	.inject_msi = xengt_inject_msi,
	.from_virt_to_mfn = xengt_virt_to_mfn,
	.set_wp_page = xengt_set_wp_page,
	.unset_wp_page = xengt_unset_wp_page,
	.read_gpa = xengt_read_gpa,
	.write_gpa = xengt_write_gpa,
	.gfn_to_mfn = xengt_gfn_to_pfn,
	.map_gfn_to_mfn = xengt_map_gfn_to_mfn,
	.set_trap_area = xengt_set_trap_area,
};
EXPORT_SYMBOL_GPL(xengt_mpt);

static int __init xengt_init(void)
{
	if (!xen_initial_domain())
		return -EINVAL;
	return 0;
}

static void __exit xengt_exit(void)
{
	gvt_dbg_core("xengt: unloaded\n");
}

module_init(xengt_init);
module_exit(xengt_exit);
