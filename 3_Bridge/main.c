/**
 * @file main.c
 * @brief ブリッジの処理に関係する関数群
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "netutil.h"

typedef struct {
    char *Device1;
    char *Device2;
    int DebugOut;  // デバッグ出力をするかどうか
} PARAM;

PARAM Param = {"enp0s8", "enp0s9", 1};

typedef struct {
    int soc;  // ソケットディスクリプタ
} DEVICE;
DEVICE Device[2];

int EndFlag = 0;  // 終了シグナル

/**
 * @brief 標準エラー出力する
 * @param fmt : 可変長引数
 */
int DebugPrintf(char *fmt, ...)
{
    if (Param.DebugOut) {
        va_list args;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return 0;
}

/**
 * @brief エラー番号に対応するエラーメッセージを標準エラー出力に出力する
 * @param fmt : 可変長引数
 */
int DebugPerror(char *msg)
{
    if (Param.DebugOut) {
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }

    return 0;
}

/**
 * @brief イーサーヘッダーの情報を解析する
 * @param deviceNo : デバイスの
 * @param data : データ
 * @param size : 可変長引数
 */
int AnalyzePacket(int deviceNo, u_char *data, int size)
{
    u_char *ptr = NULL;
    int lest = 0;
    struct ether_header *eth_hdr = NULL;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct ether_header)) {
        DebugPrintf("[%d]:lest(%d) < sizeof(struct ether_header)\n", deviceNo, lest);
        return -1;
    }

    eth_hdr = (struct ether_header *)ptr;
    ptr += sizeof(struct ether_header);
    lest -= sizeof(struct ether_header);

    DebugPrintf("[%d]", deviceNo);
    if (Param.DebugOut) {
        PrintEtherHeader(eth_hdr, stderr);
    }

    return 0;
}

/**
 * @brief ブリッジ処理を行う
 */
int Bridge()
{
    struct pollfd targets[2];
    int nready = 0;
    int i = 0;
    int size = 0;
    u_char buf[2048] = {'\0'};

    // POLLIN : 読み出し可能なデータがある
    // POLLERR :エラー状態 (出力の場合のみ)
    targets[0].fd = Device[0].soc;
    targets[0].events = POLLIN | POLLERR;
    targets[1].fd = Device[1].soc;
    targets[1].events = POLLIN | POLLERR;

    while (EndFlag == 0) {
        // poll : ファイルディスクリプタ集合のいずれか一つが I/O を実行可能な状態になるのを待つ
        switch (nready = poll(targets, 2, 100)) {
        case -1:  // エラー
            if (errno != EINTR) {
                perror("poll");
            }
            break;
        case 0:
            break;
        default:
            for (i = 0; i < 2; i++) {
                // POLLIN or POLLERR イベントが受信できていなければ次へ
                if (!(targets[i].revents & (POLLIN | POLLERR))) {
                    continue;
                }

                if ((size = read(Device[i].soc, buf, sizeof(buf))) <= 0) {
                    perror("read");
                }
                else {
                    // パケット解析に失敗したら次へ
                    if (AnalyzePacket(i, buf, size) == -1) {
                        continue;
                    }
                    // 相手のソケットディスクリプタに書き込み
                    if ((size = write(Device[(!i)].soc, buf, size)) <= 0) {
                        perror("write");
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
    FILE *fp = NULL;

    if ((fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL) {
        DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
        return -1;
    }
    fputs("0", fp);
    fclose(fp);

    return 0;
}

/**
 * @brief 終了シグナルを出す
 * @param sig : シグナル
 */
void EndSignal(int sig)
{
    EndFlag = 1;
}

int main(int argc, char *argv[], char *envp[])
{
    if ((Device[0].soc = InitRawSocket(Param.Device1, 1, 0)) == -1) {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
        return -1;
    }
    DebugPrintf("%s OK\n", Param.Device1);

    if ((Device[1].soc = InitRawSocket(Param.Device2, 1, 0)) == -1) {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
        return -1;
    }
    DebugPrintf("%s OK\n", Param.Device2);

    DisableIpForward();

    // 終了関係のシグナルハンドラが起こった場合EndSignalを呼ぶように設定
    signal(SIGINT, EndSignal);
    signal(SIGTERM, EndSignal);
    signal(SIGQUIT, EndSignal);

    // PIPE切断、TTY読み書きのシグナルを無視するように設定
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    DebugPrintf("bridge start\n");
    Bridge();
    DebugPrintf("bridge end\n");

    close(Device[0].soc);
    close(Device[1].soc);

    return 0;
}
