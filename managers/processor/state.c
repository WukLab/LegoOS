#include <lego/syscalls.h>
#include <lego/comp_common.h>
#include <lego/fit_ibapi.h>

#include <processor/processor.h>

SYSCALL_DEFINE1(dummy_get, long, number)
{
    pr_info("\n\n\nDummy State Management says:", number, "\n\n\n");

//    TODO: send message to mComponent
    ssize_t retval, retlen;
    u32 len_msg;
    void *msg;
    struct common_header* hdr;
    struct p2m_state_struct* payload;

    len_msg = sizeof(*hdr)+sizeof(*payload);
    msg = kmalloc(len_msg, GFP_KERNEL);
    if(!msg)
        return -ENOMEM;

    hdr = (struct common_header *)msg;
    hdr->opcode = P2M_STATE_DUMMY_GET;
    hdr->src_nid = LEGO_LOCAL_NID;
    payload = to_payload(msg);

    payload->number = number;

    retlen = ibapi_send_reply_imm(current_pgcache_home_node(), msg, len_msg, &retval, sizeof(retval),false);

    /* check return value */
    if(retlen == -ETIMEDOUT){
        kfree(msg);
        return -1;
    }

//    /* free allocated memory */
//    kfree(msg);

    return retval;
}