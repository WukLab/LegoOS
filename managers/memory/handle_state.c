/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <lego/comp_common.h>
#include <lego/printk.h>
#include <lego/hashtable.h>

#include <memory/thread_pool.h>


struct p2m_state_reply {
    ssize_t		retval;
};

//TODO: handle_p2m_state_dummy_get, add comment later
/*
 * simple explanation of the function
 */
void handle_p2m_state_dummy_get(struct p2m_state_struct *payload, struct thpool_buffer *tb)
{
    // Print number from payload
    printk("HEYYY! Handling message for state management: %ld\n", payload->number);
//    pr_info("handling message: %ld\n", payload->number);

    ssize_t retval;
    void *buf;
    struct p2m_state_reply *retbuf;
    retbuf = thpool_buffer_tx(tb);
    buf = (char *)retbuf;
    tb_set_tx_size(tb, sizeof(retval));

    retbuf->retval = 6666;
}


unsigned long hash_func(const char * key, const unsigned int table_size)
{
    unsigned int h = 0;
    unsigned int o = 31415;
    const unsigned int t = 27183;
    while (*key)
    {
        h = (o * h + *key++) % table_size;
        o = o * t % (table_size - 1);
    }
    return h;
}


/*
 *  state_save
 */
struct hlist_head * state_md; /* Create state_metadata as a hash table */
#define STATE_MD_BITS 8
#define STATE_MD_SIZE (1 << STATE_MD_BITS)


struct md_entry {
    char * name;
    struct {
        void * addr;
        size_t size;
    } data;
    struct hlist_node node;
};

void handle_p2m_state_save(struct p2m_state_save_payload * payload, struct thpool_buffer *tb)
{
    printk("[Function] state_save\n");
    struct p2m_state_save_reply *retbuf;
    ssize_t retval;
    retval = 0;

    if (!state_md) {
        printk("[Warning] state_md doesn't exist. Attempt to initialize.\n");
        state_md = kmalloc(STATE_MD_SIZE * sizeof(struct hlist_head), GFP_KERNEL);
        if (!state_md){
            printk("[Error] Failed to create state metadata!\n");
            retval = -ENOMEM;
            goto out;
        }
        int i;
        for (i =0; i < STATE_MD_SIZE; i++)
            INIT_HLIST_HEAD(&state_md[i]);
    }
    printk("[Success] state_md initialized.\n");

    struct md_entry * entry = kmalloc(sizeof(struct md_entry), GFP_KERNEL);
    if (!entry){
        printk("[Error] Failed to create data entry!\n");
        retval = -ENOMEM;
        goto out;
    }
    printk("[Success] entry initialized.\n");


    // kmalloc saved state
    char * state = kmalloc(payload->state_size, GFP_KERNEL);
    if (!state){
        printk("[Error] Failed to allocate memory for state data!\n");
        retval = -ENOMEM;
        goto free_entry;
    }

    memcpy(state, payload->state, payload->state_size);
    printk("[Success] state initialized.\n");

    char * name = kmalloc(payload->name_size, GFP_KERNEL);
    if (!name){
        printk("[Error] Failed to allocate memory for state name!\n");
        retval = -ENOMEM;
        goto free_state;
    }
    memcpy(name, payload->name, payload->name_size);

    printk("[Success] name initialized.\n");

    entry->name = name;
    entry->data.addr = state;
    entry->data.size = payload->state_size;

//    hash_add(state_md, &(state_md->node), state_md->name);
    hlist_add_head(&(entry->node), &state_md[hash_func(entry->name, STATE_MD_SIZE)]);
    goto out;

free_state:
    kfree(state);
free_entry:
    kfree(entry);
out:
    // construct reply
    retbuf = thpool_buffer_tx(tb);
    tb_set_tx_size(tb, sizeof(*retbuf));
    retbuf->retval = retval;
}

/*
 *  state_load
 */

void handle_p2m_state_load(struct p2m_state_load_payload * payload, struct thpool_buffer *tb)
{
    printk("[Function] state_load\n");
    // construct reply
    ssize_t retval;
    struct p2m_state_load_reply *retbuf;
    retval = 0;
    retbuf = thpool_buffer_tx(tb);
    tb_set_tx_size(tb, sizeof(*retbuf));

    retbuf->retval = retval;
    strcpy(retbuf->state, "Reply Placeholder");

    if (!state_md) {
        printk("[Error] state_md doesn't exist. Nothing to load.\n");
        retval = -EINVAL;
        return;
    }

    char * name = kmalloc(payload->name_size, GFP_KERNEL);
    if (!name){
        printk("[Error] Failed to allocate memory for state name!\n");
        retval = -ENOMEM;
        return;
    }
    memcpy(name, payload->name, payload->name_size);

    // loop over state_md
    struct md_entry * curr;
//    struct md_entry * tmp;

    hlist_for_each_entry(curr, &state_md[hash_func(name, STATE_MD_SIZE)], node) {
        printk("[Log] data=%s\n", curr->name);
        if (!strcmp(curr->name, name)){
            printk("[Log] Found a matching state\n");
            memcpy(retbuf->state, curr->data.addr, curr->data.size);
            break;
        }
    }

}