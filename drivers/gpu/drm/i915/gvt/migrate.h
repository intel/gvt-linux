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

#ifndef __GVT_MIGRATE_H__
#define __GVT_MIGRATE_H__

/* Assume 9MB is eough to descript VM kernel state */
#define MIGRATION_IMG_MAX_SIZE (9*1024UL*1024UL)
#define GVT_MMIO_SIZE (2*1024UL*1024UL)
#define GVT_MIGRATION_VERSION	0

enum gvt_migration_type_t {
	GVT_MIGRATION_NONE,
	GVT_MIGRATION_HEAD,
	GVT_MIGRATION_CFG_SPACE,
	GVT_MIGRATION_VREG,
	GVT_MIGRATION_SREG,
	GVT_MIGRATION_GTT,
	GVT_MIGRATION_PPGTT,
	GVT_MIGRATION_WORKLOAD,
	GVT_MIGRATION_OPREGION,
};

struct gvt_ppgtt_entry_t {
	int page_table_level;
	u64 pdp[4];
};

struct gvt_pending_workload_t {
	int ring_id;
	struct intel_vgpu_elsp_dwords elsp_dwords;
};

struct gvt_region_t {
	enum gvt_migration_type_t type;
	u32 size;		/* obj size of bytes to read/write */
};

struct gvt_migration_obj_t {
	void *img;
	void *vgpu;
	u32 offset;
	struct gvt_region_t region;
	/* operation func defines how data save-restore */
	struct gvt_migration_operation_t *ops;
	char *name;
};

struct gvt_migration_operation_t {
	/* called during pre-copy stage, VM is still alive */
	int (*pre_copy)(const struct gvt_migration_obj_t *obj);
	/* called before when VM was paused,
	 * return bytes transferred
	 */
	int (*pre_save)(const struct gvt_migration_obj_t *obj);
	/* called before load the state of device */
	int (*pre_load)(const struct gvt_migration_obj_t *obj, u32 size);
	/* called after load the state of device, VM already alive */
	int (*post_load)(const struct gvt_migration_obj_t *obj, u32 size);
};

struct gvt_image_header_t {
	int version;
	int data_size;
	u64 crc_check;
	u64 global_data[64];
};

struct gvt_logd_pfn {
	struct rb_node	node;
	unsigned long	gfn;
	atomic_t	ref_count;
};

#endif
