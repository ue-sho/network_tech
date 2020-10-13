/**
 * @file base.h
 * @brief ネットワークに関連する関数群のヘッダファイル
 */

#ifndef BASE_H_
#define BASE_H_

/**
 * @brief ネットワークインターフェイスの情報
 */
typedef struct {
    int socket_descriptor;   //!< ソケットディスクリプタ
    u_char hw_addr[6];       //!< MACアドレス
    struct in_addr ip_addr;  //!< IPアドレス
    struct in_addr subnet;   //!< サブネットマスク
    struct in_addr netmask;  //!< ネットマスク
} InterfaceInfo;

#define FLAG_FREE 0
#define FLAG_OK 1
#define FLAG_NG -1

/**
 * @brief データ領域
 */
typedef struct _data_buf_ {
    struct _data_buf_ *next;    //!< 次のデータのポインタ
    struct _data_buf_ *before;  //!< 次のデータのポインタ
    time_t time;                //!< 作成時間
    int size;                   //!< データサイズ
    unsigned char *data;        //!< データ
} DataBuf;

typedef struct {
    DataBuf *top;                  //!< 最初のデータのポインタ
    DataBuf *bottom;               //!< 最後のデータのポインタ
    unsigned long dno;             //!<
    unsigned long in_bucket_size;  //!< 全部の合計データサイズ
    pthread_mutex_t mutex;         //!< ミューテックス
} SendData;

/**
 * @brief IPアドレスとMACアドレスを関係づける
 */
typedef struct {
    int flag;                  //!< フラグ
    int device_number;         //!< デバイス番号
    in_addr_t ip_addr;         //!< IPアドレス
    unsigned char hw_addr[6];  //!< MACアドレス
    time_t lastTime;           //!< 最後のデータの作成時間
    SendData sd;               //!< 送信データ
} IP2MAC;

#endif