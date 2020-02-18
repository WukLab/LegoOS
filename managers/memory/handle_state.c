#include <lego/kernel.h>
#include <lego/comp_common.h>
#include <lego/printk.h>

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
    printk("HEYYY! Handling message for state management: %ld", payload->number);
//    pr_info("handling message: %ld\n", payload->number);

    ssize_t retval = 6666;
    void *buf;
    struct p2m_state_reply *retbuf;
    retbuf = thpool_buffer_tx(tb);
    buf = (char *)retbuf;
    tb_set_tx_size(tb, sizeof(retval));

    retbuf->retval = retval;
}

void handle_p2m_state_save(struct p2m_state_save_payload * payload, struct thpool_buffer *tb)
{
    printk("Hello, you wanna SAVE state?\n");
    ssize_t retval = 0;
//    void *buf;
    struct p2m_state_save_reply *retbuf;
    retbuf = thpool_buffer_tx(tb);
//    buf = (char *)retbuf;
    tb_set_tx_size(tb, sizeof(*retbuf));

    retbuf->retval = retval;
}
void handle_p2m_state_load(struct p2m_state_load_payload * payload, struct thpool_buffer *tb)
{
    printk("Hello, you wanna LOAD state?\n");
    ssize_t retval = 0;
//    void *buf;
    struct p2m_state_load_reply *retbuf;
    retbuf = thpool_buffer_tx(tb);
//    buf = (char *)retbuf;
    tb_set_tx_size(tb, sizeof(*retbuf));

    retbuf->retval = retval;
    strcpy(retbuf->state, "This is not your state but OK");

}

