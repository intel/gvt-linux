/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2020 Intel Corporation
 */

#ifndef __I915_DRM_CLIENT_H__
#define __I915_DRM_CLIENT_H__

#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/kref.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/xarray.h>

struct drm_i915_private;

struct i915_drm_clients {
	struct drm_i915_private *i915;

	struct xarray xarray;
	u32 next_id;

	struct kobject *root;
};

struct i915_drm_client {
	struct kref kref;

	struct rcu_work rcu;

	unsigned int id;
	struct pid *pid;
	char *name;
	bool closed;

	struct i915_drm_clients *clients;

	struct kobject *root;
	struct {
		struct device_attribute pid;
		struct device_attribute name;
	} attr;
};

void i915_drm_clients_init(struct i915_drm_clients *clients,
			   struct drm_i915_private *i915);

static inline struct i915_drm_client *
i915_drm_client_get(struct i915_drm_client *client)
{
	kref_get(&client->kref);
	return client;
}

void __i915_drm_client_free(struct kref *kref);

static inline void i915_drm_client_put(struct i915_drm_client *client)
{
	kref_put(&client->kref, __i915_drm_client_free);
}

void i915_drm_client_close(struct i915_drm_client *client);

struct i915_drm_client *i915_drm_client_add(struct i915_drm_clients *clients,
					    struct task_struct *task);

void i915_drm_clients_fini(struct i915_drm_clients *clients);

#endif /* !__I915_DRM_CLIENT_H__ */
