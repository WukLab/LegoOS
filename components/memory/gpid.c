/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/hashtable.h>
#include <lego/spinlock.h>
#include <lego/comp_memory.h>
#include <lego/comp_common.h>

DEFINE_HASHTABLE(node_pid_hash, HASH_BITS);
DEFINE_SPINLOCK(hastable_lock);

static int getKey (unsigned int node, unsigned int pid)
{
        return node*10000+pid*10;
}

struct lego_task_struct *
alloc_lego_task(unsigned long node, unsigned long pid) 
{
        struct lego_task_struct *proc;
        
        pr_info("Reached alloc_lego_task. \n");
        if (!node || !pid) {
                return NULL;
        }

        proc = kmalloc(sizeof(*proc), GFP_KERNEL);
        
        if (!proc) 
                return NULL;

        proc->node = node;
        proc->pid = pid;
        
        pr_info("Allocated alloc_lego_task. \n");
        
        spin_lock(&hastable_lock);
        hash_add(node_pid_hash, &proc->link, getKey(node, pid));  
        spin_unlock(&hastable_lock);
        
        pr_info("Exiting alloc_lego_task [%p]. \n", proc);
        return proc;
}

void free_lego_task(struct lego_task_struct *proc) 
{
        if (!proc)
                return;
        
        spin_lock(&hastable_lock);
        hash_remove(&proc->link);
        spin_unlock(&hastable_lock);

        kfree(proc);
}

struct lego_task_struct *
find_lego_task_by_pid(unsigned long node, unsigned long pid)
{
        struct lego_task_struct *proc;

        spin_lock(&hastable_lock);
        hash_for_each_possible(node_pid_hash, proc, link, getKey(node, pid)) {
                if (proc->pid == pid && proc->node == node) {
                        pr_info("Found matching task_struct.\n");
                        spin_unlock(&hastable_lock);
                        return proc;        
                }
        }
        spin_unlock(&hastable_lock);

        return NULL;
}
