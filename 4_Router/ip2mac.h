/**
 * @file ip2mac.h
 * @brief IPアドレスとMACアドレスを紐づける関数群のヘッダファイル
 */

#ifndef IP2MAC_H_
#define IP2MAC_H_

#include <netinet/in.h>

#include "base.h"

IP2MAC *Ip2MacSearch(int deviceNo, in_addr_t addr, unsigned char *hwaddr);
IP2MAC *GetIp2Mac(int deviceNo, in_addr_t addr, unsigned char *hwaddr);
int BufferSendOne(int deviceNo, IP2MAC *ip2mac);
int AppendSendReqData(int deviceNo, int ip2macNo);
int GetSendReqData(int *deviceNo, int *ip2macNo);
int BufferSend();

#endif