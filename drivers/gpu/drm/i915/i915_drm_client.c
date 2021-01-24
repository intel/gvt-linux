// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <drm/drm_print.h>

#include "i915_drm_client.h"
#include "i915_drv.h"
#include "i915_gem.h"
#include "i915_utils.h"

void i915_drm_clients_init(struct i915_drm_clients *clients,
			   struct drm_i915_private *i915)
{
	clients->i915 = i915;

	clients->next_id = 0;
	xa_init_flags(&clients->xarray, XA_FLAGS_ALLOC);
}

static ssize_t
show_client_name(struct device *kdev, struct device_attribute *attr, char *buf)
{
	struct i915_drm_client *client =
		container_of(attr, typeof(*client), attr.name);
	int ret;

	rcu_read_lock();
	ret = sysfs_emit(buf,
			 READ_ONCE(client->closed) ? "<%s>\n" : "%s\n",
			 i915_drm_client_name(client));
	rcu_read_unlock();

	return ret;
}

static ssize_t
show_client_pid(struct device *kdev, struct device_attribute *attr, char *buf)
{
	struct i915_drm_client *client =
		container_of(attr, typeof(*client), attr.pid);
	int ret;

	rcu_read_lock();
	ret = sysfs_emit(buf,
			 READ_ONCE(client->closed) ? "<%u>\n" : "%u\n",
			 pid_nr(i915_drm_client_pid(client)));
	rcu_read_unlock();

	return ret;
}

static int __client_register_sysfs(struct i915_drm_client *client)
{
	const struct {
		const char *name;
		struct device_attribute *attr;
		ssize_t (*show)(struct device *dev,
				struct device_attribute *attr,
				char *buf);
	} files[] = {
		{ "name", &client->attr.name, show_client_name },
		{ "pid", &client->attr.pid, show_client_pid },
	};
	unsigned int i;
	char buf[16];
	int ret;

	ret = scnprintf(buf, sizeof(buf), "%u", client->id);
	if (ret == sizeof(buf))
		return -EINVAL;

	client->root = kobject_create_and_add(buf, client->clients->root);
	if (!client->root)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		struct device_attribute *attr = files[i].attr;

		sysfs_attr_init(&attr->attr);

		attr->attr.name = files[i].name;
		attr->attr.mode = 0444;
		attr->show = files[i].show;

		ret = sysfs_create_file(client->root, &attr->attr);
		if (ret)
			break;
	}

	if (ret)
		kobject_put(client->root);

	return ret;
}

static void __client_unregister_sysfs(struct i915_drm_client *client)
{
	kobject_put(fetch_and_zero(&client->root));
}

static struct i915_drm_client_name *get_name(struct i915_drm_client *client,
					     struct task_struct *task)
{
	struct i915_drm_client_name *name;
	int len = strlen(task->comm);

	name = kmalloc(struct_size(name, name, len + 1), GFP_KERNEL);
	if (!name)
		return NULL;

	init_rcu_head(&name->rcu);
	name->client = client;
	name->pid = get_task_pid(task, PIDTYPE_PID);
	memcpy(name->name, task->comm, len + 1);

	return name;
}

static void free_name(struct rcu_head *rcu)
{
	struct i915_drm_client_name *name =
		container_of(rcu, typeof(*name), rcu);

	put_pid(name->pid);
	kfree(name);
}

static int
__i915_drm_client_register(struct i915_drm_client *client,
			   struct task_struct *task)
{
	struct i915_drm_clients *clients = client->clients;
	struct i915_drm_client_name *name;
	int ret;

	name = get_name(client, task);
	if (!name)
		return -ENOMEM;

	RCU_INIT_POINTER(client->name, name);

	if (!clients->root)
		return 0; /* intel_fbdev_init registers a client before sysfs */

	ret = __client_register_sysfs(client);
	if (ret)
		goto err_sysfs;

	return 0;

err_sysfs:
	RCU_INIT_POINTER(client->name, NULL);
	call_rcu(&name->rcu, free_name);
	return ret;
}

static void __i915_drm_client_unregister(struct i915_drm_client *client)
{
	struct i915_drm_client_name *name;

	__client_unregister_sysfs(client);

	mutex_lock(&client->update_lock);
	name = rcu_replace_pointer(client->name, NULL, true);
	mutex_unlock(&client->update_lock);

	call_rcu(&name->rcu, free_name);
}

static void __rcu_i915_drm_client_free(struct work_struct *wrk)
{
	struct i915_drm_client *client =
		container_of(wrk, typeof(*client), rcu.work);

	__i915_drm_client_unregister(client);

	xa_erase(&client->clients->xarray, client->id);
	kfree(client);
}

struct i915_drm_client *
i915_drm_client_add(struct i915_drm_clients *clients, struct task_struct *task)
{
	struct i915_drm_client *client;
	int ret;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	kref_init(&client->kref);
	mutex_init(&client->update_lock);
	spin_lock_init(&client->ctx_lock);
	INIT_LIST_HEAD(&client->ctx_list);

	client->clients = clients;
	INIT_RCU_WORK(&client->rcu, __rcu_i915_drm_client_free);

	ret = xa_alloc_cyclic(&clients->xarray, &client->id, client,
			      xa_limit_32b, &clients->next_id, GFP_KERNEL);
	if (ret < 0)
		goto err_id;

	ret = __i915_drm_client_register(client, task);
	if (ret)
		goto err_register;

	return client;

err_register:
	xa_erase(&clients->xarray, client->id);
err_id:
	kfree(client);

	return ERR_PTR(ret);
}

void __i915_drm_client_free(struct kref *kref)
{
	struct i915_drm_client *client =
		container_of(kref, typeof(*client), kref);

	queue_rcu_work(system_wq, &client->rcu);
}

void i915_drm_client_close(struct i915_drm_client *client)
{
	GEM_BUG_ON(READ_ONCE(client->closed));
	WRITE_ONCE(client->closed, true);
	i915_drm_client_put(client);
}

int
i915_drm_client_update(struct i915_drm_client *client,
		       struct task_struct *task)
{
	struct i915_drm_client_name *name;

	name = get_name(client, task);
	if (!name)
		return -ENOMEM;

	mutex_lock(&client->update_lock);
	if (name->pid != rcu_dereference_protected(client->name, true)->pid)
		name = rcu_replace_pointer(client->name, name, true);
	mutex_unlock(&client->update_lock);

	call_rcu(&name->rcu, free_name);
	return 0;
}

void i915_drm_clients_fini(struct i915_drm_clients *clients)
{
	while (!xa_empty(&clients->xarray)) {
		rcu_barrier();
		flush_workqueue(system_wq);
	}

	xa_destroy(&clients->xarray);
}
