/**
 * @file send_buf.h
 * @brief 送信待ちバッファのデータを管理する関数群のヘッダファイル
 */

#ifndef SEND_BUF_H_
#define SEND_BUF_H_

int AppendSendData(IP2MAC *ip2mac, int deviceNo, in_addr_t addr, unsigned char *data, int size);
int GetSendData(IP2MAC *ip2mac, int *size, unsigned char **data);
int FreeSendData(IP2MAC *ip2mac);
int BufferSend();

#endif