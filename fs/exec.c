/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/ptrace.h>
#include <lego/kernel.h>
#include <lego/binfmts.h>
#include <lego/spinlock.h>
#include <lego/syscalls.h>
#include <lego/uaccess.h>
#include <lego/comp_common.h>
#include <lego/comp_processor.h>

static LIST_HEAD(formats);
static DEFINE_SPINLOCK(binfmt_lock);

void __register_binfmt(struct lego_binfmt *fmt, int insert)
{
	BUG_ON(!fmt);
	if (WARN_ON(!fmt->load_binary))
		return;
	spin_lock(&binfmt_lock);
	insert ? list_add(&fmt->lh, &formats) :
		 list_add_tail(&fmt->lh, &formats);
	spin_unlock(&binfmt_lock);
}

void unregister_binfmt(struct lego_binfmt *fmt)
{
	spin_lock(&binfmt_lock);
	list_del(&fmt->lh);
	spin_unlock(&binfmt_lock);
}

static int exec_mmap(void)
{
	struct mm_struct *new_mm;
	struct mm_struct *old_mm;
	struct task_struct *tsk;

	new_mm = mm_alloc();
	if (!new_mm)
		return -ENOMEM;

	tsk = current;
	old_mm = current->mm;
	mm_release(tsk, old_mm);

	task_lock(tsk);
	tsk->mm = new_mm;
	tsk->active_mm = new_mm;
	activate_mm(old_mm, new_mm);
	task_unlock(tsk);

	if (old_mm)
		mmput(old_mm);
	return 0;
}

static __u32 count_param(const char * const *argv, int max, __u32 *size)
{
	int i = 0;

	if (!argv || !size)
		return 0;

	for (;;) {
		const char *p;
		__u32 len;

		if (get_user(p, argv + i))
			return -EFAULT;

		if (!p)
			break;

		if (i >= max)
			return -E2BIG;

		/*
		 * Vulnerable to read-after-check attack?
		 */
		len = strnlen_user(p, MAX_ARG_STRLEN);
		if (unlikely(!len))
			return -EINVAL;

		*size += len;
		i++;
	}
	return i;
}

/* Copy strings from userspace to core-kernel paylaod */
static int copy_strings(__u32 argc, const char * const *argv,
			struct p2m_execve_struct *payload, __u32 *array_oft)
{
	int i;
	long copied;
	char *dst;
	const char *src;

	BUG_ON(!argc || !argv || !payload || !array_oft);

	dst = (char *)&(payload->array) + *array_oft;
	for (i = 0; i < argc; i++) {
		if (get_user(src, argv + i))
			return -EFAULT;

		copied = strncpy_from_user(dst, src, MAX_ARG_STRLEN);
		if (unlikely(copied < 0))
			return -EFAULT;

		copied++; /* including terminal NULL */
		*array_oft += copied;
		dst += copied;
	}

	return 0;
}

/*
 * Processor-Component
 * Prepare the payload being sent to memory-component
 */
static void *prepare_exec_payload(const char *filename,
				  const char * const *argv,
				  const char * const *envp,
				  __u32 *payload_size)
{
	__u32 argc, envc, size = 0, array_oft = 0;
	long copied;
	struct p2m_execve_struct *payload;

	/* Count the total payload size first */
	argc = count_param(argv, MAX_ARG_STRINGS, &size);
	if (argc < 0)
		return ERR_PTR(argc);

	envc = count_param(envp, MAX_ARG_STRINGS, &size);
	if (envc < 0)
		return ERR_PTR(envc);

	/* then allocate payload */
	*payload_size = sizeof(*payload) + size - sizeof(char *);
	payload = kzalloc(*payload_size, GFP_KERNEL);
	if (!payload)
		return ERR_PTR(-ENOMEM);

	/* then copy strings and fill payload */
	payload->pid = current->pid;
	payload->payload_size = *payload_size;
	payload->argc = argc;
	payload->envc = envc;

	copied = strncpy_from_user(payload->filename, filename, MAX_FILENAME_LENGTH);
	if (unlikely(copied < 0))
		goto out;

	array_oft = 0;
	if (copy_strings(argc, argv, payload, &array_oft))
		goto out;

	if (copy_strings(envc, envp, payload, &array_oft))
		goto out;

	return payload;

out:
	kfree(payload);
	return ERR_PTR(-EFAULT);
}

static void *prepare_exec_reply(__u32 *reply_size)
{
	*reply_size = sizeof(struct m2p_execve_struct);
	return kmalloc(sizeof(struct m2p_execve_struct), GFP_KERNEL);
}

static int p2m_execve(struct p2m_execve_struct *payload,
		      struct m2p_execve_struct *reply,
		      __u32 payload_size, __u32 reply_size,
		      unsigned long *new_ip, unsigned long *new_sp)
{
	int ret;

	ret = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_EXECVE, payload,
			payload_size, reply, reply_size, false, DEF_NET_TIMEOUT);

	if (ret > 0) {
		if (reply->status == RET_OKAY) {
			*new_ip = reply->new_ip;
			*new_sp = reply->new_sp;
			return 0;
		} else {
			WARN(1, ret_to_string(reply->status));
			return -(reply->status);
		}
	}

	*new_ip = 0xc0001000;
	*new_sp = 0xc0003000;
	return 0;
}

int do_execve(const char *filename,
	      const char * const *argv,
	      const char * const *envp)
{
	int ret;
	__u32 payload_size, reply_size;
	unsigned long new_ip, new_sp;
	struct pt_regs *regs = current_pt_regs();
	void *payload, *reply;

	payload = prepare_exec_payload(filename, argv, envp, &payload_size);
	if (IS_ERR(payload))
		return PTR_ERR(payload);

	reply = prepare_exec_reply(&reply_size);
	if (!reply) {
		kfree(payload);
		return -ENOMEM;
	}

	ret = p2m_execve(payload, reply, payload_size, reply_size,
			 &new_ip, &new_sp);
	if (ret)
		goto out;

	/* core-kernel: switch the emulated page-table */
	ret = exec_mmap();
	if (ret)
		goto out;

	/* core-kernel: change the task iret frame */
	start_thread(regs, new_ip, new_sp);
	ret = 0;

out:
	kfree(payload);
	kfree(reply);

	/*
	 * This return will return to the point where do_execve()
	 * is invoked. The final return to user-space will happen
	 * when this kernel thread finishes and merges into
	 * the end of ret_from_fork().
	 *
	 * Check ret_from_fork() for more detail.
	 */
	return ret;
}

SYSCALL_DEFINE3(execve,
		const char __user*, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	return do_execve(filename, argv, envp);
}

void __init exec_init(void)
{
	register_binfmt(&elf_format);
}
