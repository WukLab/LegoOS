//
// Created by Yuxuan Liu on 2/16/20.
//
#include <lego/kernel.h>
#include <lego/comp_common.h>
#include <lego/printk.h>

#include <memory/thread_pool.h>

//TODO: handle_p2m_state_dummy_get
struct p2m_state_reply {
    /* nb of bytes read, or error */
    ssize_t		retval;
};

void handle_p2m_state_dummy_get(struct p2m_state_struct *payload, struct thpool_buffer *tb)
{
    // Print number from payload
    printk("HEYYY! Handling message for state management: %ld", payload->number);
//    pr_info("handling message: %ld\n", payload->number);

    ssize_t retval = 6666;
    struct p2m_read_reply *retbuf;
    retbuf = thpool_buffer_tx(tb);
    buf = (char *)retbuf;
    tb_set_tx_size(tb, sizeof(retval));

    retbuf->retval = retval;
}