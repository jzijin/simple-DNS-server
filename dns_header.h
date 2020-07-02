/*
 * @Author: your name
 * @Date: 1970-01-01 08:00:00
 * @LastEditTime: 2020-07-02 10:03:55
 * @LastEditors: your name
 * @Description: In User Settings Edit
 * @FilePath: /DNS_Server/dns_header.h
 */ 
#ifndef DNS
#define DNS

// dns 报文信息的头信息
typedef struct Dns_header {
    unsigned short id; //会话标识
    unsigned short flags; // flags
    unsigned short q_count; // 表示查询问题区域节的数量 
    unsigned short ans_count; // 表示回答区域的数量
    unsigned short auth_count; // 表示授权区域的数量
    unsigned short add_count; // 表示附加区域的数量
} __attribute__ ((packed)) DNS_HEADER;

// dns 报文信息的查询部分
typedef struct question {
    unsigned short qtype;//查询类型
    unsigned short qclass;//查询类
} QUESTION;

// dns 回复报文信息的回复信息部分
typedef struct answers {
    unsigned short offset; // 用偏移量来表示域名
    unsigned short atype;
    unsigned short aclass;
    unsigned int ttl;
    unsigned short data_length;
    unsigned int ip;
}__attribute__ ((packed)) ANSWERS;
#endif // !DNS_HEADER