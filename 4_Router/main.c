/**
 * @file main.c
 * @brief メイン（ルーター）の処理に関連する関数群の実装ファイル
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "base.h"
#include "ip2mac.h"
#include "netutil.h"
#include "send_buf.h"

/**
 * @brief ルーターの設定するための構造体
 */
typedef struct {
    char *receiving_interface;  //!< 受信元インターフェイス名
    char *sending_interface;    //!< 送信先インターフェイス名
    int debug_out;              //!< デバッグ出力をするかどうか
    char *next_router;          //!< 上位ルーターのIPアドレスを保持する
} RouterConfig;

//! ルーターの設定
RouterConfig router_config = {"enp0s8", "enp0s9", 1, "169.254.238.208"};

//! 上位ルーターのIPアドレスを保持する(16進数)
struct in_addr next_router;

//! 2つのネットワークインターフェイスのソケットディスクリプタ
InterfaceInfo interface_info[2];

//! プログラム終了フラグ
int end_flag = 0;

/**
 * @brief 標準エラー出力する
 * @param fmt : 可変長引数
 */
int DebugPrintf(char *fmt, ...)
{
    if (router_config.debug_out) {
        va_list args;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return 0;
}

/**
 * @brief エラー番号に対応するエラーメッセージを標準エラー出力に出力する
 * @param msg : 出力メッセージ
 */
int DebugPerror(char *msg)
{
    if (router_config.debug_out) {
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }

    return 0;
}

/**
 * @brief ICMPの時間超過を送る（知らせる）
 * @param device_number : デバイス番号
 * @param eth_hdr : Etherヘッダ
 * @param ip_hdr : IPヘッダ
 * @param data : データ
 * @param size : データサイズ
 */
int SendIcmpTimeExceeded(int device_number, struct ether_header *eth_hdr,
                         struct iphdr *ip_hdr, u_char *data, int size)
{
    struct ether_header recieve_eth_hdr;
    memcpy(recieve_eth_hdr.ether_dhost, eth_hdr->ether_shost, 6);
    memcpy(recieve_eth_hdr.ether_shost, interface_info[device_number].hw_addr, 6);
    recieve_eth_hdr.ether_type = htons(ETHERTYPE_IP);

    struct iphdr recieve_ip_hdr;
    recieve_ip_hdr.version = 4;
    recieve_ip_hdr.ihl = 20 / 4;
    recieve_ip_hdr.tos = 0;
    recieve_ip_hdr.tot_len = htons(sizeof(struct icmp) + 64);
    recieve_ip_hdr.id = 0;
    recieve_ip_hdr.frag_off = 0;
    recieve_ip_hdr.ttl = 64;
    recieve_ip_hdr.protocol = IPPROTO_ICMP;
    recieve_ip_hdr.check = 0;
    recieve_ip_hdr.saddr = interface_info[device_number].ip_addr.s_addr;
    recieve_ip_hdr.daddr = ip_hdr->saddr;

    recieve_ip_hdr.check = checksum((u_char *)&recieve_ip_hdr, sizeof(struct iphdr));

    struct icmp icmp_hdr;
    icmp_hdr.icmp_type = ICMP_TIME_EXCEEDED;
    icmp_hdr.icmp_code = ICMP_TIMXCEED_INTRANS;
    icmp_hdr.icmp_cksum = 0;
    icmp_hdr.icmp_void = 0;

    u_char *ip_ptr = data + sizeof(struct ether_header);

    icmp_hdr.icmp_cksum = checksum2((u_char *)&icmp_hdr, 8, ip_ptr, 64);

    u_char buf[1500] = {'\0'};
    u_char *tmp_ptr = buf;
    memcpy(tmp_ptr, &recieve_eth_hdr, sizeof(struct ether_header));
    tmp_ptr += sizeof(struct ether_header);
    memcpy(tmp_ptr, &recieve_ip_hdr, sizeof(struct iphdr));
    tmp_ptr += sizeof(struct iphdr);
    memcpy(tmp_ptr, &icmp_hdr, 8);
    tmp_ptr += 8;
    memcpy(tmp_ptr, ip_ptr, 64);
    tmp_ptr += 64;
    int len = tmp_ptr - buf;  // ptrのずれ=大きさ

    DebugPrintf("write:SendIcmpTimeExceeded:[%d] %dbytes\n", device_number, len);
    write(interface_info[device_number].socket_descriptor, buf, len);

    return 0;
}

/**
 * @brief パケット情報を解析する
 * @param device_number : デバイス番号
 * @param data : データ
 * @param size : 可変長引数
 */
int AnalyzePacket(int device_number, u_char *data, int size)
{
    char buf[80] = {'\0'};

    u_char *tmp_ptr = data;
    int tmp_len = size;

    // Etherヘッダ
    if (tmp_len < sizeof(struct ether_header)) {
        DebugPrintf("[%d]:tmp_len(%d) < sizeof(struct ether_header)\n", device_number, tmp_len);
        return -1;
    }
    struct ether_header *eth_hdr = (struct ether_header *)tmp_ptr;
    tmp_ptr += sizeof(struct ether_header);
    tmp_len -= sizeof(struct ether_header);

    // 送り先MACアドレスとデバイス番号のMACアドレスが一致してるか
    if (memcmp(&eth_hdr->ether_dhost, interface_info[device_number].hw_addr, 6) != 0) {
        DebugPrintf("[%d]:dhost not match %s\n", device_number,
                    my_ether_ntoa_r((u_char *)&eth_hdr->ether_dhost, buf, sizeof(buf)));
        return -1;
    }

    // ARPヘッダ
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        if (tmp_len < sizeof(struct ether_arp)) {
            DebugPrintf("[%d]:tmp_len(%d) < sizeof(struct ether_arp)\n", device_number, tmp_len);
            return -1;
        }
        struct ether_arp *arp_hdr = (struct ether_arp *)tmp_ptr;
        tmp_ptr += sizeof(struct ether_arp);
        tmp_len -= sizeof(struct ether_arp);

        if (arp_hdr->arp_op == htons(ARPOP_REQUEST)) {
            DebugPrintf("[%d]recv:ARP REQUEST:%dbytes\n", device_number, size);
            GetIp2Mac(device_number, *(in_addr_t *)arp_hdr->arp_spa, arp_hdr->arp_sha);
        }
        if (arp_hdr->arp_op == htons(ARPOP_REPLY)) {
            DebugPrintf("[%d]recv:ARP REPLY:%dbytes\n", device_number, size);
            GetIp2Mac(device_number, *(in_addr_t *)arp_hdr->arp_spa, arp_hdr->arp_sha);
        }
    }
    // IPヘッダ
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        if (tmp_len < sizeof(struct iphdr)) {
            DebugPrintf("[%d]:tmp_len(%d) < sizeof(struct iphdr)\n", device_number, tmp_len);
            return -1;
        }
        struct iphdr *ip_hdr = (struct iphdr *)tmp_ptr;
        tmp_ptr += sizeof(struct iphdr);
        tmp_len -= sizeof(struct iphdr);

        u_char option[1500] = {'\0'};
        int option_len = ip_hdr->ihl * 4 - sizeof(struct iphdr);
        if (option_len > 0) {
            if (option_len >= 1500) {
                DebugPrintf("[%d]:IP option_len(%d):too big\n", device_number, option_len);
                return -1;
            }
            memcpy(option, tmp_ptr, option_len);
            tmp_ptr += option_len;
            tmp_len -= option_len;
        }

        if (checkIPchecksum(ip_hdr, option, option_len) == 0) {
            DebugPrintf("[%d]:bad ip checksum\n", device_number);
            fprintf(stderr, "IP checksum error\n");
            return -1;
        }

        if (ip_hdr->ttl - 1 == 0) {
            DebugPrintf("[%d]:ip_hdr->ttl==0 error\n", device_number);
            SendIcmpTimeExceeded(device_number, eth_hdr, ip_hdr, data, size);
            return -1;
        }

        u_char hw_addr[6] = {'\0'};
        int another_device_number = (!device_number);

        if ((ip_hdr->daddr & interface_info[another_device_number].netmask.s_addr) ==
            interface_info[another_device_number].subnet.s_addr) {
            DebugPrintf("[%d]:%s to TargetSegment\n", device_number, in_addr_t2str(ip_hdr->daddr, buf, sizeof(buf)));

            if (ip_hdr->daddr == interface_info[another_device_number].ip_addr.s_addr) {
                DebugPrintf("[%d]:recv:myaddr\n", device_number);
                return (1);
            }
            IP2MAC *ip2mac = GetIp2Mac(another_device_number, ip_hdr->daddr, NULL);
            if (ip2mac->flag == FLAG_NG || ip2mac->send_data.data_num != 0) {
                DebugPrintf("[%d]:Ip2Mac:error or sending\n", device_number);
                AppendSendData(ip2mac, 1, ip_hdr->daddr, data, size);
                return -1;
            }
            else {
                memcpy(hw_addr, ip2mac->hw_addr, 6);
            }
        }
        else {
            DebugPrintf("[%d]:%s to next_router\n", device_number,
                        in_addr_t2str(ip_hdr->daddr, buf, sizeof(buf)));

            IP2MAC *ip2mac = GetIp2Mac(another_device_number, next_router.s_addr, NULL);
            if (ip2mac->flag == FLAG_NG || ip2mac->send_data.data_num != 0) {
                DebugPrintf("[%d]:Ip2Mac:error or sending\n", device_number);
                AppendSendData(ip2mac, 1, next_router.s_addr, data, size);
                return -1;
            }
            else {
                memcpy(hw_addr, ip2mac->hw_addr, 6);
            }
        }
        memcpy(eth_hdr->ether_dhost, hw_addr, 6);
        memcpy(eth_hdr->ether_shost, interface_info[another_device_number].hw_addr, 6);

        ip_hdr->ttl--;
        ip_hdr->check = 0;
        ip_hdr->check = checksum2((u_char *)ip_hdr, sizeof(struct iphdr), option, option_len);

        write(interface_info[another_device_number].socket_descriptor, data, size);
    }

    return 0;
}

/**
 * @brief ルータ処理を行う
 */
int Router()
{
    struct pollfd targets[2];
    targets[0].fd = interface_info[0].socket_descriptor;
    targets[0].events = POLLIN | POLLERR;
    targets[1].fd = interface_info[1].socket_descriptor;
    targets[1].events = POLLIN | POLLERR;

    u_char buf[2048] = {'\0'};
    int nready = 0;
    int size = 0;
    while (end_flag == 0) {
        switch (nready = poll(targets, 2, 100)) {
        case -1:
            if (errno != EINTR) {
                DebugPerror("poll");
            }
            break;
        case 0:
            break;
        default:
            for (int i = 0; i < 2; i++) {
                if (targets[i].revents & (POLLIN | POLLERR)) {
                    if ((size = read(interface_info[i].socket_descriptor, buf, sizeof(buf))) <= 0) {
                        DebugPerror("read");
                    }
                    else {
                        AnalyzePacket(i, buf, size);
                    }
                }
            }
            break;
        }
    }

    return 0;
}

/**
 * @brief カーネルのIPフォワードを止める
 */
int DisableIpForward()
{
    FILE *fp;

    if ((fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL) {
        DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
        return -1;
    }
    fputs("0", fp);
    fclose(fp);

    return 0;
}

/**
 * @brief 送信待ちバッファの処理をする（並列処理させる）
 */
void *BufThread(void *arg)
{
    BufferSend();

    return (NULL);
}

/**
 * @brief 終了関連のシグナルハンドラ
 */
void EndSignal(int sig)
{
    end_flag = 1;
}

//! バッファ処理のスレッドID
pthread_t buf_proc_thread_id;

int main(int argc, char *argv[], char *envp[])
{
    char buf[80];
    pthread_attr_t attr;
    int status;

    inet_aton(router_config.next_router, &next_router);  // 文字列からアドレス型に変更
    DebugPrintf("next_router=%s\n", my_inet_ntoa_r(&next_router, buf, sizeof(buf)));

    if (GetDeviceInfo(router_config.receiving_interface,
                      interface_info[0].hw_addr,
                      &interface_info[0].ip_addr,
                      &interface_info[0].subnet,
                      &interface_info[0].netmask) == -1) {
        DebugPrintf("GetDeviceInfo:error:%s\n", router_config.receiving_interface);
        return -1;
    }
    if ((interface_info[0].socket_descriptor =
             InitRawSocket(router_config.receiving_interface, 0, 0)) == -1) {
        DebugPrintf("InitRawSocket:error:%s\n", router_config.receiving_interface);
        return -1;
    }
    DebugPrintf("%s OK\n", router_config.receiving_interface);
    DebugPrintf("addr=%s\n", my_inet_ntoa_r(&interface_info[0].ip_addr, buf, sizeof(buf)));
    DebugPrintf("subnet=%s\n", my_inet_ntoa_r(&interface_info[0].subnet, buf, sizeof(buf)));
    DebugPrintf("netmask=%s\n", my_inet_ntoa_r(&interface_info[0].netmask, buf, sizeof(buf)));

    if (GetDeviceInfo(router_config.sending_interface,
                      interface_info[1].hw_addr,
                      &interface_info[1].ip_addr,
                      &interface_info[1].subnet,
                      &interface_info[1].netmask) == -1) {
        DebugPrintf("GetDeviceInfo:error:%s\n", router_config.sending_interface);
        return -1;
    }
    if ((interface_info[1].socket_descriptor =
             InitRawSocket(router_config.sending_interface, 0, 0)) == -1) {
        DebugPrintf("InitRawSocket:error:%s\n", router_config.receiving_interface);
        return -1;
    }
    DebugPrintf("%s OK\n", router_config.sending_interface);
    DebugPrintf("addr=%s\n", my_inet_ntoa_r(&interface_info[1].ip_addr, buf, sizeof(buf)));
    DebugPrintf("subnet=%s\n", my_inet_ntoa_r(&interface_info[1].subnet, buf, sizeof(buf)));
    DebugPrintf("netmask=%s\n", my_inet_ntoa_r(&interface_info[1].netmask, buf, sizeof(buf)));

    DisableIpForward();

    pthread_attr_init(&attr);
    if ((status = pthread_create(&buf_proc_thread_id, &attr, BufThread, NULL)) != 0) {
        DebugPrintf("pthread_create:%s\n", strerror(status));
    }

    signal(SIGINT, EndSignal);
    signal(SIGTERM, EndSignal);
    signal(SIGQUIT, EndSignal);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    DebugPrintf("router start\n");
    Router();
    DebugPrintf("router end\n");

    pthread_join(buf_proc_thread_id, NULL);

    close(interface_info[0].socket_descriptor);
    close(interface_info[1].socket_descriptor);

    return 0;
}
