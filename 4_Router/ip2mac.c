/**
 * @file ip2mac.c
 * @brief IPアドレスとMACアドレスを紐づける関数群の実装ファイル
 */

#include "ip2mac.h"

#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "base.h"
#include "netutil.h"
#include "send_buf.h"

extern int DebugPrintf(char *fmt, ...);

#define IP2MAC_TIMEOUT_SEC 60
#define IP2MAC_NG_TIMEOUT_SEC 1

/**
 * @brief ARPテーブルで2つのインターフェイスを分けて管理するための構造体
 */
struct ArpTable {
    IP2MAC *data;
    int size;
    int num;
} arp_table[2];

extern InterfaceInfo interface_info[2];

extern int end_flag;

/**
 * @brief ARPテーブルから探索する
 * @param device_number : デバイス番号
 * @param ip_addr : IPアドレス
 * @param hw_addr : MACアドレス
 */
IP2MAC *Ip2MacSearch(int device_number, in_addr_t ip_addr, u_char *hw_addr)
{
    IP2MAC *ip2mac = NULL;
    int free_number = -1;
    time_t now = time(NULL);
    char buf[80] = {'\0'};

    // ARPテーブルから検索する
    for (int i = 0; i < arp_table[device_number].num; i++) {
        ip2mac = &arp_table[device_number].data[i];
        // 空きテーブルがあるなら記録する
        if (ip2mac->flag == FLAG_FREE) {
            if (free_number == -1) {
                free_number = i;
            }
            continue;
        }

        // IPアドレスが一致したらIP2MACを返す
        if (ip2mac->ip_addr == ip_addr) {
            if (ip2mac->flag == FLAG_OK) {
                // 最終更新時刻を更新
                ip2mac->lastTime = now;
            }

            if (hw_addr != NULL) {
                memcpy(ip2mac->hw_addr, hw_addr, 6);
                ip2mac->flag = FLAG_OK;
                if (ip2mac->send_data.top != NULL) {
                    AppendSendReqData(device_number, i);
                }
                DebugPrintf("Ip2Mac EXIST [%d] %s = %d\n",
                            device_number, in_addr_t2str(ip_addr, buf, sizeof(buf)), i);
                return ip2mac;
            }
            else {
                // 有効期限チェック・タイムアウトチェックで該当すれば、空き状態にする
                if ((ip2mac->flag == FLAG_OK && now - ip2mac->lastTime > IP2MAC_TIMEOUT_SEC) ||
                    (ip2mac->flag == FLAG_NG && now - ip2mac->lastTime > IP2MAC_NG_TIMEOUT_SEC)) {
                    FreeSendData(ip2mac);
                    ip2mac->flag = FLAG_FREE;
                    DebugPrintf("Ip2Mac FREE [%d] %s = %d\n",
                                device_number, in_addr_t2str(ip2mac->ip_addr, buf, sizeof(buf)), i);
                    if (free_number == -1) {
                        free_number = i;
                    }
                }
                else {
                    DebugPrintf("Ip2Mac EXIST [%d] %s = %d\n",
                                device_number, in_addr_t2str(ip_addr, buf, sizeof(buf)), i);
                    return ip2mac;
                }
            }
        }
        else {
            // 有効期限チェック・タイムアウトチェックで該当すれば、空き状態にする
            if ((ip2mac->flag == FLAG_OK && now - ip2mac->lastTime > IP2MAC_TIMEOUT_SEC) ||
                (ip2mac->flag == FLAG_NG && now - ip2mac->lastTime > IP2MAC_NG_TIMEOUT_SEC)) {
                FreeSendData(ip2mac);
                ip2mac->flag = FLAG_FREE;
                DebugPrintf("Ip2Mac FREE [%d] %s = %d\n",
                            device_number, in_addr_t2str(ip2mac->ip_addr, buf, sizeof(buf)), i);
                if (free_number == -1) {
                    free_number = i;
                }
            }
        }
    }

    int idx = 0;
    // ARPテーブルから見つからなければ新しく作成
    if (free_number == -1) {
        idx = arp_table[device_number].num;
        // 最大サイズを1024Byte分拡張する
        if (idx >= arp_table[device_number].size) {
            if (arp_table[device_number].size == 0) {
                arp_table[device_number].size = 1024;
                arp_table[device_number].data = (IP2MAC *)malloc(arp_table[device_number].size * sizeof(IP2MAC));
            }
            else {
                arp_table[device_number].size += 1024;
                arp_table[device_number].data =
                    (IP2MAC *)realloc(arp_table[device_number].data, arp_table[device_number].size * sizeof(IP2MAC));
            }
        }
        arp_table[device_number].num++;
    }
    else {
        idx = free_number;
    }

    ip2mac = &arp_table[device_number].data[idx];

    // ip2macにデータを詰める
    ip2mac->device_number = device_number;
    ip2mac->ip_addr = ip_addr;
    if (hw_addr == NULL) {
        ip2mac->flag = FLAG_NG;
        memset(ip2mac->hw_addr, 0, 6);
    }
    else {
        ip2mac->flag = FLAG_OK;
        memcpy(ip2mac->hw_addr, hw_addr, 6);
    }
    ip2mac->lastTime = now;
    memset(&ip2mac->send_data, 0, sizeof(SendData));
    pthread_mutex_init(&ip2mac->send_data.mutex, NULL);

    DebugPrintf("Ip2Mac ADD [%d] %s = %d\n", device_number, in_addr_t2str(ip2mac->ip_addr, buf, sizeof(buf)), idx);

    return ip2mac;
}

/**
 * @brief ARPテーブルから探索・または新しく格納する
 * @param device_number : デバイス番号
 * @param ip_addr : IPアドレス
 * @param hw_addr : MACアドレス
 */
IP2MAC *GetIp2Mac(int device_number, in_addr_t ip_addr, u_char *hw_addr)
{
    static u_char broad_cast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    char buf[80] = {'\0'};
    IP2MAC *ip2mac = Ip2MacSearch(device_number, ip_addr, hw_addr);

    if (ip2mac->flag == FLAG_OK) {
        DebugPrintf("Ip2Mac(%s):OK\n", in_addr_t2str(ip_addr, buf, sizeof(buf)));
        return ip2mac;
    }
    else {
        DebugPrintf("Ip2Mac(%s):NG\n", in_addr_t2str(ip_addr, buf, sizeof(buf)));
        DebugPrintf("Ip2Mac(%s):Send Arp Request\n", in_addr_t2str(ip_addr, buf, sizeof(buf)));
        SendArpRequestB(interface_info[device_number].socket_descriptor, ip_addr,
                        broad_cast, interface_info[device_number].ip_addr.s_addr,
                        interface_info[device_number].hw_addr);
        return ip2mac;
    }
}

/**
 * @brief 送信待ちバッファに溜まっているデータを送信する
 * @param device_number : デバイス番号
 * @param ip2mac : IPアドレスとMACアドレスが紐づいたデータ
 */
int BufferSendOne(int device_number, IP2MAC *ip2mac)
{
    struct ether_header eth_hdr;
    struct iphdr ip_hdr;
    u_char option[1500] = {'\0'};
    int option_len = 0;
    int size = 0;
    u_char *data = NULL;
    u_char *ptr = NULL;

    while (1) {
        if (GetSendData(ip2mac, &size, &data) == -1) {
            break;
        }

        ptr = data;

        memcpy(&eth_hdr, ptr, sizeof(struct ether_header));
        ptr += sizeof(struct ether_header);

        memcpy(&ip_hdr, ptr, sizeof(struct iphdr));
        ptr += sizeof(struct iphdr);

        option_len = ip_hdr.ihl * 4 - sizeof(struct iphdr);
        if (option_len > 0) {
            memcpy(option, ptr, option_len);
            ptr += option_len;
        }

        memcpy(eth_hdr.ether_dhost, ip2mac->hw_addr, 6);
        memcpy(data, &eth_hdr, sizeof(struct ether_header));

        DebugPrintf("ip_hdr.ttl %d->%d\n", ip_hdr.ttl, ip_hdr.ttl - 1);
        ip_hdr.ttl--;

        ip_hdr.check = 0;
        ip_hdr.check = checksum2((u_char *)&ip_hdr, sizeof(struct iphdr), option, option_len);
        memcpy(data + sizeof(struct ether_header), &ip_hdr, sizeof(struct iphdr));

        DebugPrintf("write:BufferSendOne:[%d] %dbytes\n", device_number, size);
        write(interface_info[device_number].socket_descriptor, data, size);  // 送信

        // DebugPrintf("*************************************[%d]\n", device_number);
        // print_ether_header(&eth_hdr);
        // print_ip(&ip_hdr);
        // DebugPrintf("*************************************[%d]\n", device_number);
    }

    return 0;
}

/**
 * @brief 送信待ちデータを保持するための構造体
 */
typedef struct _send_req_data_ {
    struct _send_req_data_ *next;
    struct _send_req_data_ *before;
    int device_number;
    int ip2mac_number;
} SendRequestData;

/**
 * @brief 送信リクエストを行うための構造体
 */
struct
{
    SendRequestData *top;
    SendRequestData *bottom;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} send_request = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

/**
 * @brief 送信待ちバッファに溜まっているデータを送信する
 * @param device_number : デバイス番号
 * @param ip2mac_number : IPアドレスとMACアドレスが紐づいたデータの番号
 */
int AppendSendReqData(int device_number, int ip2mac_number)
{
    SendRequestData *send_request_data = NULL;
    int status = 0;

    if ((status = pthread_mutex_lock(&send_request.mutex)) != 0) {
        DebugPrintf("AppendSendReqData:pthread_mutex_lock:%s\n", strerror(status));
        return -1;
    }

    for (send_request_data = send_request.top;
         send_request_data != NULL;
         send_request_data = send_request_data->next) {
        // 同じ宛先のものがあれば終了
        if (send_request_data->device_number == device_number &&
            send_request_data->ip2mac_number == ip2mac_number) {
            pthread_mutex_unlock(&send_request.mutex);
            return 1;
        }
    }

    send_request_data = (SendRequestData *)malloc(sizeof(SendRequestData));
    if (send_request_data == NULL) {
        DebugPrintf("AppendSendReqData:malloc error");
        pthread_mutex_unlock(&send_request.mutex);
        return -1;
    }
    send_request_data->next = send_request_data->before = NULL;
    send_request_data->device_number = device_number;
    send_request_data->ip2mac_number = ip2mac_number;

    if (send_request.bottom == NULL) {
        send_request.top = send_request.bottom = send_request_data;
    }
    else {
        // 双方向リストを作る
        send_request.bottom->next = send_request_data;
        send_request_data->before = send_request.bottom;
        send_request.bottom = send_request_data;
    }
    pthread_cond_signal(&send_request.cond);
    pthread_mutex_unlock(&send_request.mutex);

    DebugPrintf("AppendSendReqData:[%d] %d\n", device_number, ip2mac_number);

    return 0;
}

/**
 * @brief 先頭のデータ（デバイス番号とIPアドレスとMACアドレスが紐づいたデータの番号のペア）を一つ得る
 * @param device_number : デバイス番号
 * @param ip2mac_number : IPアドレスとMACアドレスが紐づいたデータの番号
 */
int GetSendReqData(int *device_number, int *ip2mac_number)
{
    if (send_request.top == NULL) {
        return -1;
    }

    int status = 0;
    if ((status = pthread_mutex_lock(&send_request.mutex)) != 0) {
        DebugPrintf("pthread_mutex_lock:%s\n", strerror(status));
        return -1;
    }

    SendRequestData *send_request_data = send_request.top;
    send_request.top = send_request_data->next;
    if (send_request.top == NULL) {
        send_request.bottom = NULL;
    }
    else {
        send_request.top->before = NULL;
    }
    pthread_mutex_unlock(&send_request.mutex);

    *device_number = send_request_data->device_number;
    *ip2mac_number = send_request_data->ip2mac_number;

    DebugPrintf("GetSendReqData:[%d] %d\n", *device_number, *ip2mac_number);

    return 0;
}

/**
 * @brief 送信待ちバッファを処理する
 */
int BufferSend()
{
    struct timeval now;
    struct timespec timeout;
    int device_number = 0;
    int ip2mac_number = 0;
    int status = 0;

    while (end_flag == 0) {
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + 1;
        timeout.tv_nsec = now.tv_usec * 1000;

        pthread_mutex_lock(&send_request.mutex);
        // 通知を受けるか、1秒でタイムアウトするまで待つ
        if ((status = pthread_cond_timedwait(&send_request.cond, &send_request.mutex, &timeout)) != 0) {
            DebugPrintf("pthread_cond_timedwait:%s\n", strerror(status));
        }
        pthread_mutex_unlock(&send_request.mutex);

        while (1) {
            if (GetSendReqData(&device_number, &ip2mac_number) == -1) {
                break;
            }
            // 溜まったデータを送信する
            BufferSendOne(device_number, &arp_table[device_number].data[ip2mac_number]);
        }
    }

    DebugPrintf("BufferSend:end\n");

    return 0;
}
