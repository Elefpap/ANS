#ifndef RPL_DIS_DEFENCE_H_
#define RPL_DIS_DEFENCE_H_

#include "contiki.h"
#include "net/ipv6/uip.h"

#ifndef RPL_DIS_DEFENSE_TABLE_SIZE
#define RPL_DIS_DEFENSE_TABLE_SIZE 20
#endif

#ifndef RPL_DIS_DEFENSE_MIN_INTERVAL
#define RPL_DIS_DEFENSE_MIN_INTERVAL 20
#endif

#ifndef RPL_DIS_DEFENSE_ENTRY_TIMEOUT
#define RPL_DIS_DEFENSE_ENTRY_TIMEOUT 60
#endif

void rpl_dis_defense_init(void);

int rpl_dis_defense_check(const uip_ipaddr_t *src_addr);

void rpl_dis_defense_cleanup(void);

#endif 