/**
 * @file netutil.c
 * @brief ネットワークに関連する関数群の実装ファイル
 */

#include <arpa/inet.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

extern int DebugPrintf(char *fmt, ...);
extern int DebugPerror(char *msg);

/**
 * @brief Rawソケットの準備
 * @param device : ネットワークインターフェース名
 * @param promisc_flag : プロミスキャスとモードにするかどうかのフラグ
 * @param ip_only : IPパケットのみを対象とするかどうかのフラグ
 * @return socketのディスクリプタ
 *         ERRORの場合 -1
 */
int InitRawSocket(char *device, int promisc_flag, int ip_only)
{
    int socket_discriptor = -1;

    // socket(PF_PACKET, SOCK_RAW, プロトコル) でデータリンク層を扱う
    if (ip_only) {
        // IPパケットのみ
        if ((socket_discriptor = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
            DebugPerror("socket");
            return -1;
        }
    }
    else {
        // 全パケット
        if ((socket_discriptor = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
            DebugPerror("socket");
            return -1;
        }
    }

    struct ifreq interface_request;
    memset(&interface_request, 0, sizeof(struct ifreq));
    strncpy(interface_request.ifr_name, device, sizeof(interface_request.ifr_name) - 1);

    if (ioctl(socket_discriptor, SIOCGIFINDEX, &interface_request) < 0) {
        DebugPerror("ioctl");
        close(socket_discriptor);
        return -1;
    }

    struct sockaddr_ll socket_addr;
    memset(&socket_addr, 0, sizeof(struct sockaddr_ll));
    socket_addr.sll_family = PF_PACKET;
    if (ip_only) {
        socket_addr.sll_protocol = htons(ETH_P_IP);
    }
    else {
        socket_addr.sll_protocol = htons(ETH_P_ALL);
    }
    socket_addr.sll_ifindex = interface_request.ifr_ifindex;
    if (bind(socket_discriptor,
             (struct sockaddr *)&socket_addr,
             sizeof(socket_addr)) < 0) {
        DebugPerror("bind");
        close(socket_discriptor);
        return -1;
    }

    // IFF_PROMISCを付加する
    if (promisc_flag) {
        if (ioctl(socket_discriptor, SIOCGIFFLAGS, &interface_request) < 0) {
            DebugPerror("ioctl");
            close(socket_discriptor);
            return -1;
        }
        interface_request.ifr_flags = interface_request.ifr_flags | IFF_PROMISC;
        if (ioctl(socket_discriptor, SIOCSIFFLAGS, &interface_request) < 0) {
            DebugPerror("ioctl");
            close(socket_discriptor);
            return -1;
        }
    }

    return socket_discriptor;
}

/**
 * @brief デバイス（インターフェイス）名からインターフェイス情報を取得する
 * @param device : デバイス名
 * @param hw_addr : MACアドレス
 * @param uaddr : IPアドレス
 * @param subnet : サブネットマスク
 * @param mask : ネットマスク
 */
int GetDeviceInfo(char *device, u_char hw_addr[6],
                  struct in_addr *ip_addr,
                  struct in_addr *subnet,
                  struct in_addr *mask)
{
    int socket_discriptor = 0;
    if ((socket_discriptor = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        DebugPerror("socket");
        return -1;
    }

    struct ifreq interface_request;
    memset(&interface_request, 0, sizeof(struct ifreq));
    strncpy(interface_request.ifr_name, device, sizeof(interface_request.ifr_name) - 1);

    // MACアドレスを取得
    if (ioctl(socket_discriptor, SIOCGIFHWADDR, &interface_request) == -1) {
        DebugPerror("ioctl");
        close(socket_discriptor);
        return -1;
    }
    else {
        u_char *tmp_ptr = (u_char *)interface_request.ifr_hwaddr.sa_data;
        memcpy(hw_addr, tmp_ptr, 6);
    }

    struct sockaddr_in addr;
    // IPアドレスを取得
    if (ioctl(socket_discriptor, SIOCGIFADDR, &interface_request) == -1) {
        DebugPerror("ioctl");
        close(socket_discriptor);
        return -1;
    }
    else if (interface_request.ifr_addr.sa_family != PF_INET) {
        DebugPrintf("%s not PF_INET\n", device);
        close(socket_discriptor);
        return -1;
    }
    else {
        memcpy(&addr, &interface_request.ifr_addr, sizeof(struct sockaddr_in));
        *ip_addr = addr.sin_addr;
    }

    // ネットマスクを取得
    if (ioctl(socket_discriptor, SIOCGIFNETMASK, &interface_request) == -1) {
        DebugPerror("ioctl");
        close(socket_discriptor);
        return -1;
    }
    else {
        memcpy(&addr, &interface_request.ifr_addr, sizeof(struct sockaddr_in));
        *mask = addr.sin_addr;
    }

    // サブネットマスクを取得
    subnet->s_addr = ((ip_addr->s_addr) & (mask->s_addr));

    close(socket_discriptor);

    return 0;
}

/**
 * @brief MACアドレスを文字列にする
 * @param hw_addr : MACアドレス
 * @param buf : MACアドレスの文字列格納用のバッファ
 * @param size : ソケットのサイズ
 * @return MACアドレスの文字列
 */
char *my_ether_ntoa_r(u_char *hw_addr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             hw_addr[0], hw_addr[1], hw_addr[2], hw_addr[3], hw_addr[4], hw_addr[5]);

    return buf;
}

/**
 * @brief IPアドレス(in_addr構造体)を文字列にする
 * @param ip_addr : IPアドレス
 * @param buf : IPアドレスの文字列格納用のバッファ
 * @param size : ソケットのサイズ
 * @return IPアドレスの文字列
 */
char *my_inet_ntoa_r(struct in_addr *ip_addr, char *buf, socklen_t size)
{
    inet_ntop(PF_INET, ip_addr, buf, size);

    return buf;
}

/**
 * @brief IPアドレス(in_addr_t構造体)を文字列にする
 * @param ip_addr : IPアドレス
 * @param buf : IPアドレスの文字列格納用のバッファ
 * @param size : ソケットのサイズ
 * @return IPアドレスの文字列
 */
char *in_addr_t2str(in_addr_t ip_addr, char *buf, socklen_t size)
{
    struct in_addr tmp_addr;

    tmp_addr.s_addr = ip_addr;
    inet_ntop(PF_INET, &tmp_addr, buf, size);

    return buf;
}

/**
 * @brief イーサーヘッダーの情報をデバッグ出力する
 * @param eth_hdr : イーサーヘッダー
 * @param fp : メッセージ出力先ファイルポインタ
 */
int PrintEtherHeader(struct ether_header *eth_hdr, FILE *fp)
{
    char buf[80] = {'\0'};

    fprintf(fp, "ether_header----------------------------\n");
    fprintf(fp, "ether_dhost=%s\n", my_ether_ntoa_r(eth_hdr->ether_dhost, buf, sizeof(buf)));
    fprintf(fp, "ether_shost=%s\n", my_ether_ntoa_r(eth_hdr->ether_shost, buf, sizeof(buf)));
    fprintf(fp, "ether_type=%02X", ntohs(eth_hdr->ether_type));
    switch (ntohs(eth_hdr->ether_type)) {
    case ETH_P_IP:
        fprintf(fp, "(IP)\n");
        break;
    case ETH_P_IPV6:
        fprintf(fp, "(IPv6)\n");
        break;
    case ETH_P_ARP:
        fprintf(fp, "(ARP)\n");
        break;
    default:
        fprintf(fp, "(unknown)\n");
        break;
    }

    return 0;
}

/**
 * @brief チェックサムを計算する
 * @param data : データ
 * @param len : データの長さ
 * @return チェックサム
 */
u_int16_t checksum(u_char *data, int len)
{
    register u_int32_t sum = 0;
    register u_int16_t *ptr = (u_int16_t *)data;

    register int c = 0;
    for (c = len; c > 1; c -= 2) {
        sum += (*ptr);
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1) {
        u_int16_t val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

/**
 * @brief 2つのデータのチェックサムを計算する
 * @param data1 : データ1
 * @param len1 : データ1の長さ
 * @param data2 : データ2
 * @param len2 : データ2の長さ
 * @return チェックサム
 */
u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2)
{
    register u_int32_t sum = 0;
    register u_int16_t *ptr = (u_int16_t *)data1;

    register int c = 0;
    for (c = len1; c > 1; c -= 2) {
        sum += (*ptr);
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1) {
        u_int16_t val;
        val = ((*ptr) << 8) + (*data2);
        sum += val;
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr = (u_int16_t *)(data2 + 1);
        len2--;
    }
    else {
        ptr = (u_int16_t *)data2;
    }
    for (c = len2; c > 1; c -= 2) {
        sum += (*ptr);
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1) {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

/**
 * @brief IPヘッダのチェックサムを確認する
 * @param ip_hdr : IPヘッダ
 * @param option : オプション
 * @param optionLen : オプションの長さ
 * @return 1 : チェックサムが 0 or 65535
 */
int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen)
{
    struct iphdr iptmp;
    memcpy(&iptmp, iphdr, sizeof(struct iphdr));

    unsigned short sum = 0;
    if (optionLen == 0) {
        sum = checksum((u_char *)&iptmp, sizeof(struct iphdr));
        if (sum == 0 || sum == 0xFFFF) {
            return (1);
        }
        else {
            return 0;
        }
    }
    else {
        sum = checksum2((u_char *)&iptmp, sizeof(struct iphdr), option, optionLen);
        if (sum == 0 || sum == 0xFFFF) {
            return (1);
        }
        else {
            return 0;
        }
    }
}

typedef struct {
    struct ether_header eth_hdr;
    struct ether_arp arp_hdr;
} PacketArp;

/**
 * @brief ARPリクエストを送信する
 * @param socket_discriptor : ソケットディスクリプタ
 * @param target_ip : 送り先のIPアドレス
 * @param target_mac : 送り先のMACアドレス
 * @param my_ip : 自分のIPアドレス
 * @param my_mac : 自分のMACアドレス
 */
int SendArpRequestB(
    int socket_discriptor,
    in_addr_t target_ip,
    u_char target_mac[6],
    in_addr_t my_ip,
    u_char my_mac[6])
{
    PacketArp packet_arp;

    packet_arp.arp_hdr.arp_hrd = htons(ARPHRD_ETHER);
    packet_arp.arp_hdr.arp_pro = htons(ETHERTYPE_IP);
    packet_arp.arp_hdr.arp_hln = 6;
    packet_arp.arp_hdr.arp_pln = 4;
    packet_arp.arp_hdr.arp_op = htons(ARPOP_REQUEST);

    for (int i = 0; i < 6; i++) {
        packet_arp.arp_hdr.arp_sha[i] = my_mac[i];
    }

    for (int i = 0; i < 6; i++) {
        packet_arp.arp_hdr.arp_tha[i] = 0;
    }

    union {
        unsigned long l;
        u_char c[4];
    } lc;
    lc.l = my_ip;
    for (int i = 0; i < 4; i++) {
        packet_arp.arp_hdr.arp_spa[i] = lc.c[i];
    }

    lc.l = target_ip;
    for (int i = 0; i < 4; i++) {
        packet_arp.arp_hdr.arp_tpa[i] = lc.c[i];
    }

    packet_arp.eth_hdr.ether_dhost[0] = target_mac[0];
    packet_arp.eth_hdr.ether_dhost[1] = target_mac[1];
    packet_arp.eth_hdr.ether_dhost[2] = target_mac[2];
    packet_arp.eth_hdr.ether_dhost[3] = target_mac[3];
    packet_arp.eth_hdr.ether_dhost[4] = target_mac[4];
    packet_arp.eth_hdr.ether_dhost[5] = target_mac[5];

    packet_arp.eth_hdr.ether_shost[0] = my_mac[0];
    packet_arp.eth_hdr.ether_shost[1] = my_mac[1];
    packet_arp.eth_hdr.ether_shost[2] = my_mac[2];
    packet_arp.eth_hdr.ether_shost[3] = my_mac[3];
    packet_arp.eth_hdr.ether_shost[4] = my_mac[4];
    packet_arp.eth_hdr.ether_shost[5] = my_mac[5];

    packet_arp.eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    u_char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)] = {'\0'};

    u_char *tmp_ptr = buf;
    memcpy(tmp_ptr, &packet_arp.eth_hdr, sizeof(struct ether_header));
    tmp_ptr += sizeof(struct ether_header);
    memcpy(tmp_ptr, &packet_arp.arp_hdr, sizeof(struct ether_arp));
    tmp_ptr += sizeof(struct ether_arp);
    int total = tmp_ptr - buf;

    write(socket_discriptor, buf, total);

    return 0;
}