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
 *
 * Authors:
 *    Yulei Zhang <yulei.zhang@intel.com>
 *    Xiao Zheng <xiao.zheng@intel.com>
 */

#include "i915_drv.h"
#include "gvt.h"
#include "i915_pvinfo.h"

#define INV (-1)
#define RULES_NUM(x) (sizeof(x)/sizeof(gvt_migration_obj_t))
#define FOR_EACH_OBJ(obj, rules) \
	for (obj = rules; obj->region.type != GVT_MIGRATION_NONE; obj++)
#define MIG_VREG_RESTORE(vgpu, off)					\
	{								\
		u32 data = vgpu_vreg(vgpu, (off));			\
		u64 pa = intel_vgpu_mmio_offset_to_gpa(vgpu, off);	\
		intel_vgpu_emulate_mmio_write(vgpu, pa, &data, 4);	\
	}

/* s - struct
 * t - type of obj
 * m - size of obj
 * ops - operation override callback func
 */
#define MIGRATION_UNIT(_s, _t, _m, _ops) {		\
.img		= NULL,					\
.region.type	= _t,					\
.region.size	= _m,					\
.ops		= &(_ops),				\
.name		= "["#_s":"#_t"]\0"			\
}

#define MIGRATION_END {		\
	NULL, NULL, 0,		\
	{GVT_MIGRATION_NONE, 0},\
	NULL,	\
	NULL	\
}

static DEFINE_MUTEX(gvt_migration);
static int image_header_load(const struct gvt_migration_obj_t *obj, u32 size);
static int image_header_save(const struct gvt_migration_obj_t *obj);
static int vreg_load(const struct gvt_migration_obj_t *obj, u32 size);
static int vreg_save(const struct gvt_migration_obj_t *obj);
static int sreg_load(const struct gvt_migration_obj_t *obj, u32 size);
static int sreg_save(const struct gvt_migration_obj_t *obj);
static int vcfg_space_load(const struct gvt_migration_obj_t *obj, u32 size);
static int vcfg_space_save(const struct gvt_migration_obj_t *obj);
static int vggtt_load(const struct gvt_migration_obj_t *obj, u32 size);
static int vggtt_save(const struct gvt_migration_obj_t *obj);
static int workload_load(const struct gvt_migration_obj_t *obj, u32 size);
static int workload_save(const struct gvt_migration_obj_t *obj);
static int ppgtt_load(const struct gvt_migration_obj_t *obj, u32 size);
static int ppgtt_save(const struct gvt_migration_obj_t *obj);
static int opregion_load(const struct gvt_migration_obj_t *obj, u32 size);
static int opregion_save(const struct gvt_migration_obj_t *obj);

/***********************************************
 * Internal Static Functions
 ***********************************************/
struct gvt_migration_operation_t vReg_ops = {
	.pre_copy = NULL,
	.pre_save = vreg_save,
	.pre_load = vreg_load,
	.post_load = NULL,
};

struct gvt_migration_operation_t sReg_ops = {
	.pre_copy = NULL,
	.pre_save = sreg_save,
	.pre_load = sreg_load,
	.post_load = NULL,
};

struct gvt_migration_operation_t vcfg_space_ops = {
	.pre_copy = NULL,
	.pre_save = vcfg_space_save,
	.pre_load = vcfg_space_load,
	.post_load = NULL,
};

struct gvt_migration_operation_t vgtt_info_ops = {
	.pre_copy = NULL,
	.pre_save = vggtt_save,
	.pre_load = vggtt_load,
	.post_load = NULL,
};

struct gvt_migration_operation_t image_header_ops = {
	.pre_copy = NULL,
	.pre_save = image_header_save,
	.pre_load = image_header_load,
	.post_load = NULL,
};

struct gvt_migration_operation_t workload_ops = {
	.pre_copy = NULL,
	.pre_save = workload_save,
	.pre_load = workload_load,
	.post_load = NULL,
};

struct gvt_migration_operation_t ppgtt_ops = {
	.pre_copy = NULL,
	.pre_save = ppgtt_save,
	.pre_load = ppgtt_load,
	.post_load = NULL,
};

struct gvt_migration_operation_t opregion_ops = {
	.pre_copy = NULL,
	.pre_save = opregion_save,
	.pre_load = opregion_load,
	.post_load = NULL,
};

/* gvt_device_objs[] are list of gvt_migration_obj_t objs
 * Each obj has its operation method to save to qemu image
 * and restore from qemu image during the migration.
 *
 * for each saved bject, it will have a region header
 * struct gvt_region_t {
 *   region_type;
 *   region_size;
 * }
 *__________________  _________________   __________________
 *|x64 (Source)    |  |image region    |  |x64 (Target)    |
 *|________________|  |________________|  |________________|
 *|    Region A    |  |   Region A     |  |   Region A     |
 *|    Header      |  |   offset=0     |  | allocate a page|
 *|    content     |  |                |  | copy data here |
 *|----------------|  |     ...        |  |----------------|
 *|    Region B    |  |     ...        |  |   Region B     |
 *|    Header      |  |----------------|  |                |
 *|    content        |   Region B     |  |                |
 *|----------------|  |   offset=4096  |  |----------------|
 *                    |                |
 *                    |----------------|
 *
 * On the target side, it will parser the incoming data copy
 * from Qemu image, and apply difference restore handlers depends
 * on the region type.
 */
static struct gvt_migration_obj_t gvt_device_objs[] = {
	MIGRATION_UNIT(struct intel_vgpu,
			GVT_MIGRATION_HEAD,
			sizeof(struct gvt_image_header_t),
			image_header_ops),
	MIGRATION_UNIT(struct intel_vgpu,
			GVT_MIGRATION_CFG_SPACE,
			PCI_CFG_SPACE_EXP_SIZE,
			vcfg_space_ops),
	MIGRATION_UNIT(struct intel_vgpu,
			GVT_MIGRATION_SREG,
			GVT_MMIO_SIZE, sReg_ops),
	MIGRATION_UNIT(struct intel_vgpu,
			GVT_MIGRATION_VREG,
			GVT_MMIO_SIZE, vReg_ops),
	MIGRATION_UNIT(struct intel_vgpu,
			GVT_MIGRATION_GTT,
			0, vgtt_info_ops),
	MIGRATION_UNIT(struct intel_vgpu,
			GVT_MIGRATION_PPGTT,
			0, ppgtt_ops),
	MIGRATION_UNIT(struct intel_vgpu,
			GVT_MIGRATION_WORKLOAD,
			0, workload_ops),
	MIGRATION_UNIT(struct intel_vgpu,
			GVT_MIGRATION_OPREGION,
			INTEL_GVT_OPREGION_SIZE, opregion_ops),
	MIGRATION_END,
};

static inline void
update_image_region_start_pos(struct gvt_migration_obj_t *obj, int pos)
{
	obj->offset = pos;
}

static inline void
update_image_region_base(struct gvt_migration_obj_t *obj, void *base)
{
	obj->img = base;
}

static inline void
update_status_region_base(struct gvt_migration_obj_t *obj, void *base)
{
	obj->vgpu = base;
}

static inline struct gvt_migration_obj_t *
find_migration_obj(enum gvt_migration_type_t type)
{
	struct gvt_migration_obj_t *obj;

	for (obj = gvt_device_objs;
		obj->region.type != GVT_MIGRATION_NONE; obj++)
		if (obj->region.type == type)
			return obj;
	return NULL;
}

static int image_header_save(const struct gvt_migration_obj_t *obj)
{
	struct gvt_region_t region;
	struct gvt_image_header_t header;
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;

	region.type = GVT_MIGRATION_HEAD;
	region.size = sizeof(struct gvt_image_header_t);
	memcpy(obj->img, &region, sizeof(struct gvt_region_t));

	header.version = GVT_MIGRATION_VERSION;
	header.data_size = obj->offset;
	header.crc_check = 0; /* CRC check skipped for now*/

	if (intel_gvt_host.hypervisor_type == INTEL_GVT_HYPERVISOR_XEN) {
		header.global_data[0] = vgpu->low_mem_max_gpfn;
	}

	memcpy(obj->img + sizeof(struct gvt_region_t), &header,
			sizeof(struct gvt_image_header_t));

	return sizeof(struct gvt_region_t) + sizeof(struct gvt_image_header_t);
}

static int image_header_load(const struct gvt_migration_obj_t *obj, u32 size)
{
	struct gvt_image_header_t header;
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;

	if (unlikely(size != sizeof(struct gvt_image_header_t))) {
		gvt_err("migration obj size isn't match between target and image!"
		" memsize=%d imgsize=%d\n",
		obj->region.size,
		size);
		return INV;
	}

	memcpy(&header, obj->img + obj->offset,
		sizeof(struct gvt_image_header_t));

	if (intel_gvt_host.hypervisor_type == INTEL_GVT_HYPERVISOR_XEN) {
		vgpu->low_mem_max_gpfn = header.global_data[0];
	}

	return header.data_size;
}

static int vcfg_space_save(const struct gvt_migration_obj_t *obj)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	int n_transfer = INV;
	void *src = vgpu->cfg_space.virtual_cfg_space;
	void *des = obj->img + obj->offset;

	memcpy(des, &obj->region, sizeof(struct gvt_region_t));

	des += sizeof(struct gvt_region_t);
	n_transfer = obj->region.size;

	memcpy(des, src, n_transfer);
	return sizeof(struct gvt_region_t) + n_transfer;
}

static int vcfg_space_load(const struct gvt_migration_obj_t *obj, u32 size)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	char *dest = vgpu->cfg_space.virtual_cfg_space;
	int n_transfer = INV;

	if (unlikely(size != obj->region.size)) {
		gvt_err("migration obj size isn't match between target and image!"
		" memsize=%d imgsize=%d\n",
		obj->region.size,
		size);
		return n_transfer;
	} else {
		n_transfer = obj->region.size;
		memcpy(dest, obj->img + obj->offset, n_transfer);
	}

	if (intel_gvt_host.hypervisor_type == INTEL_GVT_HYPERVISOR_XEN) {
#define MIG_CFG_SPACE_WRITE(off) {					\
	u32 data;							\
	data = *((u32 *)(dest + (off)));				\
	intel_vgpu_emulate_cfg_write(vgpu, (off), &data, sizeof(data));	\
	}

#define MIG_CFG_SPACE_WRITE_BAR(bar) {					\
	u32 data = 0x500;						\
	vgpu_cfg_space(vgpu)[PCI_COMMAND] = 0;				\
	intel_vgpu_emulate_cfg_write(vgpu, PCI_COMMAND, &data, 2);	\
	data = *((u32 *)(dest + (bar)));				\
	intel_vgpu_emulate_cfg_write(vgpu, (bar), &data, sizeof(data));	\
	data = *((u32 *)(dest + (bar)+4));				\
	intel_vgpu_emulate_cfg_write(vgpu, (bar)+4, &data, sizeof(data));\
	data = 0x503;							\
	intel_vgpu_emulate_cfg_write(vgpu, PCI_COMMAND, &data, 2);	\
	}

		/* reconfig bar0,1,2 with source VM's base address.
		 * TargetVM and SourceVM must have same bar base.
		 */
		MIG_CFG_SPACE_WRITE_BAR(PCI_BASE_ADDRESS_0);
		MIG_CFG_SPACE_WRITE_BAR(PCI_BASE_ADDRESS_2);
		MIG_CFG_SPACE_WRITE_BAR(PCI_BASE_ADDRESS_4);

		/* restore OpRegion */
		MIG_CFG_SPACE_WRITE(INTEL_GVT_PCI_OPREGION);
		MIG_CFG_SPACE_WRITE(INTEL_GVT_PCI_SWSCI);
	}
	return n_transfer;
}

static int sreg_save(const struct gvt_migration_obj_t *obj)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	int n_transfer = INV;
	void *src = vgpu->mmio.sreg;
	void *des = obj->img + obj->offset;

	memcpy(des, &obj->region, sizeof(struct gvt_region_t));

	des += sizeof(struct gvt_region_t);
	n_transfer = obj->region.size;

	memcpy(des, src, n_transfer);
	return sizeof(struct gvt_region_t) + n_transfer;
}

static int sreg_load(const struct gvt_migration_obj_t *obj, u32 size)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	void *dest = vgpu->mmio.sreg;
	int n_transfer = INV;

	if (unlikely(size != obj->region.size)) {
		gvt_err("migration obj size isn't match between target and image!"
		" memsize=%d imgsize=%d\n",
		obj->region.size,
		size);
		return n_transfer;
	} else {
		n_transfer = obj->region.size;
		memcpy(dest, obj->img + obj->offset, n_transfer);
	}

	return n_transfer;
}

static int opregion_save(const struct gvt_migration_obj_t *obj)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	int n_transfer = INV;
	void *src = vgpu->opregion.va;
	void *des = obj->img + obj->offset;

	memcpy(des, &obj->region, sizeof(struct gvt_region_t));

	des += sizeof(struct gvt_region_t);
	n_transfer = obj->region.size;

	memcpy(des, src, n_transfer);
	return sizeof(struct gvt_region_t) + n_transfer;
}

static int opregion_load(const struct gvt_migration_obj_t *obj, u32 size)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	int n_transfer = INV;

	if (unlikely(size != obj->region.size)) {
		gvt_err("migration object size is not match between target \
				and image!!! memsize=%d imgsize=%d\n",
		obj->region.size,
		size);
		return n_transfer;
	} else {
		vgpu_opregion(vgpu)->va = (void *)__get_free_pages(GFP_KERNEL |
			__GFP_ZERO,
			get_order(INTEL_GVT_OPREGION_SIZE));
		n_transfer = obj->region.size;
		memcpy(vgpu_opregion(vgpu)->va, obj->img + obj->offset, n_transfer);
	}

	return n_transfer;
}

static int ppgtt_save(const struct gvt_migration_obj_t *obj)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	struct list_head *pos;
	struct intel_vgpu_mm *mm;
	struct gvt_ppgtt_entry_t entry;
	struct gvt_region_t region;
	int num = 0;
	u32 sz = sizeof(struct gvt_ppgtt_entry_t);
	void *des = obj->img + obj->offset;

	list_for_each(pos, &vgpu->gtt.ppgtt_mm_list_head) {
		mm = container_of(pos, struct intel_vgpu_mm, ppgtt_mm.list);
		if (mm->type != INTEL_GVT_MM_PPGTT)
			continue;

		entry.page_table_level = mm->ppgtt_mm.root_entry_type;
		memcpy(entry.pdp, mm->ppgtt_mm.shadow_pdps, 32);

		memcpy(des + sizeof(struct gvt_region_t) + (num * sz),
			&entry, sz);
		num++;
	}

	region.type = GVT_MIGRATION_PPGTT;
	region.size = num * sz;
	memcpy(des, &region, sizeof(struct gvt_region_t));

	return sizeof(struct gvt_region_t) + region.size;
}

static int ppgtt_load(const struct gvt_migration_obj_t *obj, u32 size)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	int n_transfer = INV;
	struct gvt_ppgtt_entry_t entry;
	struct intel_vgpu_mm *mm;
	void *src = obj->img + obj->offset;
	int i;
	u32 sz = sizeof(struct gvt_ppgtt_entry_t);

	if (size == 0)
		return size;

	if (unlikely(size % sz) != 0) {
		gvt_err("migration obj size isn't match between target and image!"
		" memsize=%d imgsize=%d\n",
		obj->region.size,
		size);
		return n_transfer;
	}

	for (i = 0; i < size / sz; i++) {
		memcpy(&entry, src + (i * sz), sz);
		mm = intel_vgpu_create_ppgtt_mm(vgpu, entry.page_table_level,
						entry.pdp);
		if (IS_ERR(mm)) {
			gvt_vgpu_err("fail to create mm object.\n");
			return n_transfer;
		}
	}

	n_transfer = size;

	return n_transfer;
}

static int vreg_save(const struct gvt_migration_obj_t *obj)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	int n_transfer = INV;
	void *src = vgpu->mmio.vreg;
	void *des = obj->img + obj->offset;

	memcpy(des, &obj->region, sizeof(struct gvt_region_t));

	des += sizeof(struct gvt_region_t);
	n_transfer = obj->region.size;

	memcpy(des, src, n_transfer);
	return sizeof(struct gvt_region_t) + n_transfer;
}

static int vreg_load(const struct gvt_migration_obj_t *obj, u32 size)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	void *dest = vgpu->mmio.vreg;
	int n_transfer = INV;
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;
	enum pipe pipe;

	if (unlikely(size != obj->region.size)) {
		gvt_err("migration obj size isn't match between target and image!"
		" memsize=%d imgsize=%d\n",
		obj->region.size,
		size);
		return n_transfer;
	} else {
		n_transfer = obj->region.size;
		memcpy(dest, obj->img + obj->offset, n_transfer);
	}

	//restore vblank emulation
	for (pipe = PIPE_A; pipe < I915_MAX_PIPES; ++pipe)
		MIG_VREG_RESTORE(vgpu, i915_mmio_reg_offset(PIPECONF(pipe)));

	return n_transfer;
}

static int workload_save(const struct gvt_migration_obj_t *obj)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;
	struct gvt_region_t region;
	struct intel_engine_cs *engine;
	struct intel_vgpu_workload *pos, *n;
	unsigned int i;
	struct gvt_pending_workload_t workload;
	void *des = obj->img + obj->offset;
	unsigned int num = 0;
	u32 sz = sizeof(struct gvt_pending_workload_t);

	for_each_engine(engine, dev_priv, i) {
		list_for_each_entry_safe(pos, n,
			&vgpu->submission.workload_q_head[engine->id], list) {
			workload.ring_id = pos->ring_id;
			memcpy(&workload.elsp_dwords, &pos->elsp_dwords,
				sizeof(struct intel_vgpu_elsp_dwords));
			memcpy(des + sizeof(struct gvt_region_t) + (num * sz),
				&workload, sz);
			num++;
		}
	}

	region.type = GVT_MIGRATION_WORKLOAD;
	region.size = num * sz;
	memcpy(des, &region, sizeof(struct gvt_region_t));

	return sizeof(struct gvt_region_t) + region.size;
}

static int workload_load(const struct gvt_migration_obj_t *obj, u32 size)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	struct drm_i915_private *dev_priv = vgpu->gvt->dev_priv;
	int n_transfer = INV;
	struct gvt_pending_workload_t workload;
	struct intel_engine_cs *engine;
	void *src = obj->img + obj->offset;
	u64 pa, off;
	u32 sz = sizeof(struct gvt_pending_workload_t);
	int i, j;

	if (size == 0)
		return size;

	if (unlikely(size % sz) != 0) {
		gvt_err("migration obj size isn't match between target and image!"
		" memsize=%d imgsize=%d\n",
		obj->region.size,
		size);
		return n_transfer;
	}

	for (i = 0; i < size / sz; i++) {
		memcpy(&workload, src + (i * sz), sz);
		engine = dev_priv->engine[workload.ring_id];
		off = i915_mmio_reg_offset(RING_ELSP(engine));
		pa = intel_vgpu_mmio_offset_to_gpa(vgpu, off);
		for (j = 0; j < 4; j++) {
			intel_vgpu_emulate_mmio_write(vgpu, pa,
					&workload.elsp_dwords.data[j], 4);
		}
	}

	n_transfer = size;

	return n_transfer;
}

static int
mig_ggtt_save_restore(struct intel_vgpu_mm *ggtt_mm,
		void *data, u64 gm_offset,
		u64 gm_sz,
		bool save_to_image)
{
	struct intel_vgpu *vgpu = ggtt_mm->vgpu;
	struct intel_gvt_gtt_gma_ops *gma_ops = vgpu->gvt->gtt.gma_ops;

	void *ptable;
	int sz;
	int shift = vgpu->gvt->device_info.gtt_entry_size_shift;

	ptable = ggtt_mm->ggtt_mm.virtual_ggtt +
	    (gma_ops->gma_to_ggtt_pte_index(gm_offset) << shift);
	sz = (gm_sz >> I915_GTT_PAGE_SHIFT) << shift;

	if (save_to_image)
		memcpy(data, ptable, sz);
	else
		memcpy(ptable, data, sz);

	return sz;
}

static int vggtt_save(const struct gvt_migration_obj_t *obj)
{
	int ret = INV;
	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	struct intel_vgpu_mm *ggtt_mm = vgpu->gtt.ggtt_mm;
	void *des = obj->img + obj->offset;
	struct gvt_region_t region;
	int sz;

	u64 aperture_offset = vgpu_guest_aperture_offset(vgpu);
	u64 aperture_sz = vgpu_aperture_sz(vgpu);
	u64 hidden_gm_offset = vgpu_guest_hidden_offset(vgpu);
	u64 hidden_gm_sz = vgpu_hidden_sz(vgpu);

	des += sizeof(struct gvt_region_t);

	/*TODO:512MB GTT takes total 1024KB page table size, optimization here*/

	gvt_dbg_core("Guest aperture=0x%llx (HW: 0x%llx),"
		"Guest Hidden=0x%llx (HW:0x%llx)\n",
		aperture_offset, vgpu_aperture_offset(vgpu),
		hidden_gm_offset, vgpu_hidden_offset(vgpu));

	/*TODO:to be fixed after removal of address ballooning */
	ret = 0;

	/* aperture */
	sz = mig_ggtt_save_restore(ggtt_mm, des,
		aperture_offset, aperture_sz, true);
	des += sz;
	ret += sz;

	/* hidden gm */
	sz = mig_ggtt_save_restore(ggtt_mm, des,
		hidden_gm_offset, hidden_gm_sz, true);
	des += sz;
	ret += sz;

	/* Save the total size of this session */
	region.type = GVT_MIGRATION_GTT;
	region.size = ret;
	memcpy(obj->img + obj->offset, &region, sizeof(struct gvt_region_t));

	ret += sizeof(struct gvt_region_t);

	return ret;
}

static int vggtt_load(const struct gvt_migration_obj_t *obj, u32 size)
{
	int ret;
	u32 ggtt_index;
	void *src;
	int sz;

	struct intel_vgpu *vgpu = (struct intel_vgpu *) obj->vgpu;
	struct intel_vgpu_mm *ggtt_mm = vgpu->gtt.ggtt_mm;

	int shift = vgpu->gvt->device_info.gtt_entry_size_shift;

	/* offset to bar1 beginning */
	u64 dest_aperture_offset = vgpu_guest_aperture_offset(vgpu);
	u64 aperture_sz = vgpu_aperture_sz(vgpu);
	u64 dest_hidden_gm_offset = vgpu_guest_hidden_offset(vgpu);
	u64 hidden_gm_sz = vgpu_hidden_sz(vgpu);

	gvt_dbg_core("Guest aperture=0x%llx (HW: 0x%llx),"
		"Guest Hidden=0x%llx (HW:0x%llx)\n",
		dest_aperture_offset, vgpu_aperture_offset(vgpu),
		dest_hidden_gm_offset, vgpu_hidden_offset(vgpu));

	if ((size>>shift) !=
			((aperture_sz + hidden_gm_sz) >> I915_GTT_PAGE_SHIFT)) {
		gvt_err("ggtt restore failed due to page table size not match\n");
		return INV;
	}

	ret = 0;
	src = obj->img + obj->offset;

	/* aperture */
	sz = mig_ggtt_save_restore(ggtt_mm,
		src, dest_aperture_offset, aperture_sz, false);
	src += sz;
	ret += sz;

	/* hidden GM */
	sz = mig_ggtt_save_restore(ggtt_mm, src,
			dest_hidden_gm_offset, hidden_gm_sz, false);
	ret += sz;

	/* aperture/hidden GTT emulation from Source to Target */
	for (ggtt_index = 0; 
	     ggtt_index < (gvt_ggtt_gm_sz(vgpu->gvt) >> I915_GTT_PAGE_SHIFT);
	     ggtt_index++) {

		if (vgpu_gmadr_is_valid(vgpu, ggtt_index << I915_GTT_PAGE_SHIFT)) {
			struct intel_gvt_gtt_pte_ops *ops =
					vgpu->gvt->gtt.pte_ops;
			struct intel_gvt_gtt_entry e;
			u64 offset;
			u64 pa;

			/* TODO: hardcode to 64bit right now */
			offset = vgpu->gvt->device_info.gtt_start_offset
				+ (ggtt_index<<shift);

			pa = intel_vgpu_mmio_offset_to_gpa(vgpu, offset);

			/* read out virtual GTT entity and
			 * trigger emulate write
			 */
			ggtt_get_guest_entry(ggtt_mm, &e, ggtt_index);
			if (ops->test_present(&e)) {
			/* same as gtt_emulate
			 * _write(vgt, offset, &e.val64, 1<<shift);
			 * Using vgt_emulate_write as to align with vReg load
			 */
				intel_vgpu_emulate_mmio_write(vgpu, pa,
							&e.val64, 1<<shift);
			}
		}
	}

	return ret;
}

static int vgpu_save(const void *img)
{
	struct gvt_migration_obj_t *node;
	int n_img_actual_saved = 0;

	/* go by obj rules one by one */
	FOR_EACH_OBJ(node, gvt_device_objs) {
		int n_img = INV;

		if ((node->region.type == GVT_MIGRATION_OPREGION) &&
			(intel_gvt_host.hypervisor_type == INTEL_GVT_HYPERVISOR_KVM))
			continue;

		/* obj will copy data to image file img.offset */
		update_image_region_start_pos(node, n_img_actual_saved);
		if (node->ops->pre_save == NULL) {
			n_img = 0;
		} else {
			n_img = node->ops->pre_save(node);
			if (n_img == INV) {
				gvt_err("Save obj %s failed\n",
						node->name);
				n_img_actual_saved = INV;
				break;
			}
		}
		/* show GREEN on screen with colorred term */
		gvt_dbg_core("Save obj %s success with %d bytes\n",
			       node->name, n_img);
		n_img_actual_saved += n_img;

		if (n_img_actual_saved >= MIGRATION_IMG_MAX_SIZE) {
			gvt_err("Image size overflow!!! data=%d MAX=%ld\n",
				n_img_actual_saved,
				MIGRATION_IMG_MAX_SIZE);
			/* Mark as invalid */
			n_img_actual_saved = INV;
			break;
		}
	}
	/* update the header with real image size */
	node = find_migration_obj(GVT_MIGRATION_HEAD);
	update_image_region_start_pos(node, n_img_actual_saved);
	node->ops->pre_save(node);
	return n_img_actual_saved;
}

static int vgpu_restore(void *img)
{
	struct gvt_migration_obj_t *node;
	struct gvt_region_t region;
	int n_img_actual_recv = 0;
	u32 n_img_actual_size;

	/* load image header at first to get real size */
	memcpy(&region, img, sizeof(struct gvt_region_t));
	if (region.type != GVT_MIGRATION_HEAD) {
		gvt_err("Invalid image. Doesn't start with image_head\n");
		return INV;
	}

	n_img_actual_recv += sizeof(struct gvt_region_t);
	node = find_migration_obj(region.type);
	update_image_region_start_pos(node, n_img_actual_recv);
	n_img_actual_size = node->ops->pre_load(node, region.size);
	if (n_img_actual_size == INV) {
		gvt_err("Load img %s failed\n", node->name);
		return INV;
	}

	if (n_img_actual_size >= MIGRATION_IMG_MAX_SIZE) {
		gvt_err("Invalid image. magic_id offset = 0x%x\n",
				n_img_actual_size);
		return INV;
	}

	n_img_actual_recv += sizeof(struct gvt_image_header_t);

	do {
		int n_img = INV;
		/* parse each region head to get type and size */
		memcpy(&region, img + n_img_actual_recv,
				sizeof(struct gvt_region_t));
		node = find_migration_obj(region.type);
		if (node == NULL)
			break;
		n_img_actual_recv += sizeof(struct gvt_region_t);
		update_image_region_start_pos(node, n_img_actual_recv);

		if (node->ops->pre_load == NULL) {
			n_img = 0;
		} else {
			n_img = node->ops->pre_load(node, region.size);
			if (n_img == INV) {
				/* Error occurred. colored as RED */
				gvt_err("Load obj %s failed\n",
						node->name);
				n_img_actual_recv = INV;
				break;
			}
		}
		/* show GREEN on screen with colorred term */
		gvt_dbg_core("Load obj %s success with %d bytes.\n",
			       node->name, n_img);
		n_img_actual_recv += n_img;
	} while (n_img_actual_recv < MIGRATION_IMG_MAX_SIZE);

	return n_img_actual_recv;
}

int intel_gvt_save_restore(struct intel_vgpu *vgpu, char *buf, size_t count,
			   void *base, uint64_t off, bool restore)
{
	struct gvt_migration_obj_t *node;
	int ret = 0;

	mutex_lock(&gvt_migration);

	FOR_EACH_OBJ(node, gvt_device_objs) {
		update_image_region_base(node, base + off);
		update_image_region_start_pos(node, INV);
		update_status_region_base(node, vgpu);
	}

	if (restore) {
		vgpu->pv_notified = true;
		if (vgpu_restore(base + off) == INV) {
			ret = -EFAULT;
			goto exit;
		}
	} else {
		if (vgpu_save(base + off) == INV) {
			ret = -EFAULT;
			goto exit;
		}

	}

exit:
	mutex_unlock(&gvt_migration);

	return ret;
}
