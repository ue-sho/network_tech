/**
 * @file send_buf.c
 * @brief 送信待ちバッファのデータを管理する関数群の実装ファイル
 */

#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "base.h"
#include "ip2mac.h"
#include "netutil.h"

extern int DebugPrintf(char *fmt, ...);
extern int DebugPerror(char *msg);

#define MAX_BUCKET_SIZE (1024 * 1024)

/**
 * @brief 送信待ちデータに追加する
 * @param ip2mac : IPアドレスとMACアドレスが紐づいたデータ
 * @param device_number : デバイス番号
 * @param ip_addr : IPアドレス
 * @param data : データ
 * @param size : データサイズ
 */
int AppendSendData(IP2MAC *ip2mac, int device_number, in_addr_t ip_addr, u_char *data, int size)
{
    SendData *send_data = &ip2mac->send_data;

    if (send_data->in_bucket_size > MAX_BUCKET_SIZE) {
        DebugPrintf("AppendSendData:Bucket overflow\n");
        return -1;
    }

    DataBuf *data_buf = (DataBuf *)malloc(sizeof(DataBuf));
    if (data_buf == NULL) {
        DebugPerror("malloc");
        return -1;
    }

    data_buf->data = (u_char *)malloc(size);
    if (data_buf->data == NULL) {
        DebugPerror("malloc");
        free(data_buf);
        return -1;
    }

    data_buf->next = data_buf->before = NULL;
    data_buf->time = time(NULL);
    data_buf->size = size;
    memcpy(data_buf->data, data, size);

    int status = 0;
    if ((status = pthread_mutex_lock(&send_data->mutex)) != 0) {
        DebugPrintf("AppendSendData:pthread_mutex_lock:%s\n", strerror(status));
        free(data_buf->data);
        free(data_buf);
        return -1;
    }

    if (send_data->bottom == NULL) {
        send_data->top = send_data->bottom = data_buf;
    }
    else {
        send_data->bottom->next = data_buf;
        data_buf->before = send_data->bottom;
        send_data->bottom = data_buf;
    }
    send_data->data_num++;
    send_data->in_bucket_size += size;
    pthread_mutex_unlock(&send_data->mutex);

    char buf[80] = {'\0'};
    DebugPrintf("AppendSendData:[%d] %s %dbytes(Total=%lu:%lubytes)\n",
                device_number, in_addr_t2str(ip_addr, buf, sizeof(buf)), size,
                send_data->data_num, send_data->in_bucket_size);

    return 0;
}

/**
 * @brief 送信待ちデータの先頭を得る
 * @param ip2mac : IPアドレスとMACアドレスが紐づいたデータ
 * @param size : データサイズ
 * @param data : データ
 */
int GetSendData(IP2MAC *ip2mac, int *size, u_char **data)
{
    SendData *send_data = &ip2mac->send_data;

    if (send_data->top == NULL) {
        return -1;
    }

    int status = 0;
    if ((status = pthread_mutex_lock(&send_data->mutex)) != 0) {
        DebugPrintf("pthread_mutex_lock:%s\n", strerror(status));
        return -1;
    }

    DataBuf *data_buf = send_data->top;
    send_data->top = data_buf->next;
    if (send_data->top == NULL) {
        send_data->bottom = NULL;
    }
    else {
        send_data->top->before = NULL;
    }
    send_data->data_num--;
    send_data->in_bucket_size -= data_buf->size;

    pthread_mutex_unlock(&send_data->mutex);

    *size = data_buf->size;
    *data = data_buf->data;

    free(data_buf);

    char buf[80] = {'\0'};
    DebugPrintf("GetSendData:[%d] %s %dbytes\n", ip2mac->device_number, in_addr_t2str(ip2mac->ip_addr, buf, sizeof(buf)), *size);

    return 0;
}

/**
 * @brief 送信待ちデータを削除する
 * @param ip2mac : IPアドレスとMACアドレスが紐づいたデータ
 */
int FreeSendData(IP2MAC *ip2mac)
{
    SendData *send_data = &ip2mac->send_data;

    if (send_data->top == NULL) {
        return 0;
    }

    int status = 0;
    if ((status = pthread_mutex_lock(&send_data->mutex)) != 0) {
        DebugPrintf("pthread_mutex_lock:%s\n", strerror(status));
        return -1;
    }

    char buf[80] = {'\0'};
    for (DataBuf *ptr = send_data->top; ptr != NULL; ptr = ptr->next) {
        DebugPrintf("FreeSendData:%s %lu\n", in_addr_t2str(ip2mac->ip_addr, buf, sizeof(buf)), send_data->in_bucket_size);
        free(ptr->data);
    }

    send_data->top = send_data->bottom = NULL;

    pthread_mutex_unlock(&send_data->mutex);

    DebugPrintf("FreeSendData:[%d]\n", ip2mac->device_number);

    return 0;
}
