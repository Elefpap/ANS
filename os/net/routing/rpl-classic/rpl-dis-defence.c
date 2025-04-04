#include "net/ipv6/uip.h"
#include "contiki.h"
#include "os/lib/memb.h"
#include "os/lib/list.h"
#include "rpl-private.h"
#include "sys/log.h"
#include "net/routing/rpl-classic/rpl-dis-defence.h"

#define LOG_MODULE "RPL-DIS-DEF"
#define LOG_LEVEL LOG_LEVEL_INFO


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
    LOG_INFO("DIS defense initialized (table size: %u, min interval: %u seconds)\n", 
             RPL_DIS_DEFENSE_TABLE_SIZE, RPL_DIS_DEFENSE_MIN_INTERVAL);
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
            LOG_INFO("DIS defense: checking time interval for ");
            LOG_INFO_6ADDR(src_addr);
            LOG_INFO_(" (current time: %lu, stored time: %lu)\n", (unsigned long)current_time, (unsigned long)s->ts);
            LOG_INFO("DIS defense: time interval: %lu\n", (unsigned long)(current_time - s->ts));
            LOG_INFO("DIS defense: min interval: %lu\n", (unsigned long)(RPL_DIS_DEFENSE_MIN_INTERVAL * CLOCK_SECOND));
            if (current_time - s->ts < (RPL_DIS_DEFENSE_MIN_INTERVAL * CLOCK_SECOND))
            {
                // drop it
                LOG_INFO("DIS defense: dropping message from ");
                LOG_INFO_6ADDR(src_addr);
                LOG_INFO_(" (too frequent)\n");
                return 0;
            }
            else
            {
                s->ts = current_time;
                LOG_INFO("DIS defense: message from ");
                LOG_INFO_6ADDR(src_addr);
                LOG_INFO_(" (allowed)\n");
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
        LOG_INFO("DIS defense: added new source ");
        LOG_INFO_6ADDR(src_addr);
        LOG_INFO_("\n");
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
            LOG_INFO("DIS defense: table full, replacing oldest entry ");
            LOG_INFO_6ADDR(&oldest->src_addr);
            LOG_INFO_(" with ");
            LOG_INFO_6ADDR(src_addr);
            LOG_INFO_("\n");
            
            uip_ipaddr_copy(&oldest->src_addr, src_addr);
            oldest->ts = current_time;
        }
    }

    /* Allow processing the first DIS from this source */
    return 1;
}

/**
 * Cleanup old entries from the DIS defense table
 * This should be called periodically to free memory
 */
void rpl_dis_defense_cleanup(void)
{
    dis_source *s;
    dis_source *next;
    clock_time_t current_time = clock_time();
    
    for(s = list_head(dis_source_list); s != NULL; s = next)
    {
        // Store next pointer before removing the current entry
        next = list_item_next(s);
        
        // Check if this entry has expired
        if(current_time - s->ts > (RPL_DIS_DEFENSE_ENTRY_TIMEOUT * CLOCK_SECOND))
        {
            LOG_INFO("DIS defense: removing expired entry for ");
            LOG_INFO_6ADDR(&s->src_addr);
            LOG_INFO_("\n");
            
            // Remove from list and free memory
            list_remove(dis_source_list, s);
            memb_free(&dis_source_memb, s);
        }
    }
}

/*
TODO: create a header file for this
TODO: import the header file from rpl-icmp6.c
TODO: use it is dis_input(). If the result is 0, drop the packet and use uipbuf_clear() to free the buffer.

Dont know where to use the init function yet.
*/
