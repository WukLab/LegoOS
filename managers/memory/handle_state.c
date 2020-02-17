//
// Created by Yuxuan Liu on 2/16/20.
//
#include <lego/kernel.h>
#include <lego/comp_common.h>
#include <lego/printk.h>

//TODO: handle_p2m_state_dummy_get

void handle_p2m_state_dummy_get(struct p2m_state_struct *payload)
{
    // Print number from payload
    printk("handling message: %ld", payload->number);
    pr_info("handling message: %ld\n", payload->number);
}