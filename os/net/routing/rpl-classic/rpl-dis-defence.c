#include "net/ipv6/uip.h"
#include "contiki.h"
#include "os/lib/memb.h"
#include "os/lib/list.h"
#include "rpl-private.h"

#ifndef RPL_DIS_DEFENSE_TABLE_SIZE
#define RPL_DIS_DEFENSE_TABLE_SIZE 20
#endif

#ifndef RPL_DIS_DEFENSE_MIN_INTERVAL
#define RPL_DIS_DEFENSE_MIN_INTERVAL 10
#endif

#ifndef RPL_DIS_DEFENSE_ENTRY_TIMEOUT
// TODO: we will use this to cleanup the table 
#define RPL_DIS_DEFENSE_ENTRY_TIMEOUT 60
#endif

typedef struct {
    uip_ipaddr_t src_addr;
    clock_time_t ts;
} dis_source;

// allocate memory block for structs 
MEMB(dis_source_memb, dis_source, RPL_DIS_DEFENSE_TABLE_SIZE);
// allocate resources for a linked list
LIST(dis_source_list);

void rpl_dis_defense_init(void)
{
    memb_init(&dis_source_memb);
    list_init(dis_source_list);
}

int
rpl_dis_defense_check(const uip_ipaddr_t *src_addr)
{
    dis_source *s;
    clock_time_t current_time = clock_time();

    // see if the source is already in the list
    for (s = list_head(dis_source_list); s != NULL; s = list_item_next(s))
    {
        if (uip_ipaddr_cmp(&s->src_addr, src_addr))
        {
            // check if the time interval is less than the minimum interval
            if (current_time - s->ts < (RPL_DIS_DEFENSE_MIN_INTERVAL * CLOCK_SECOND))
            {
                // drop it
                return 0;
            }
            else
            {
                s->ts = current_time;
                return 1;
            }
        }
    }

    // if here, the source was not in the list, so add it and let it through
    s = memb_alloc(&dis_source_memb);
    if (s != NULL)
    {
        uip_ipaddr_copy(&s->src_addr, src_addr);
        s->ts = current_time;
        list_add(dis_source_list, s);
    }
    else
    {

        // table full
        dis_source *oldest = NULL;
        clock_time_t oldest_time = current_time;

        for (s = list_head(dis_source_list); s != NULL; s = list_item_next(s))
        {
            if (s->ts < oldest_time)
            {
                oldest = s;
                oldest_time = s->ts;
            }

            // TODO: also the time to do cleanup; lazy now ele u can doit
            // dont forget to free the memory with memb_free when u remove an item
        }

        // if we cleanup in the prev loop, then no need to remove anything from the list
        // otherwise this logic stays. - keep it for now
        if (oldest != NULL)
        {
            uip_ipaddr_copy(&oldest->src_addr, src_addr);
            oldest->ts = current_time;
        }
    }

    /* Allow processing the first DIS from this source */
    return 1;
}


/*
TODO: create a header file for this
TODO: import the header file from rpl-icmp6.c
TODO: use it is dis_input(). If the result is 0, drop the packet and use uipbuf_clear() to free the buffer.

Dont know where to use the init function yet.
*/
