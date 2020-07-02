#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/select.h>
#include "dns_header.h"

// transaction id
static int id = 100;

/**
 * @description: 将域名转化成dns报文信息需要的格式
 *               eg: www.baidu.com--> 3www5baidu3com
 * @param {in} host 指向输入域名的指针
 * @param {out} dns 转换完成之后的传出参数 
 * @return: NULL
 */
void dns_name_format(unsigned char *dns, unsigned char *host)
{
    int lock = 0, i;
    strcat((char *)host, ".");
    for (i = 0; i < strlen((char *)host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

/**
 * @description: 查询模式，输入域名输出ip地址
 * @param {in} fd 客户端文件描述符 
 * @param {in} serv 服务器的套接字
 * @param {in} len 服务器套接字的长度
 * @return: NULL
 */
void query_mode(int fd, struct sockaddr_in serv, socklen_t len)
{
    printf("请输入要解析的域名\n");
    char domain[128] = {0};

    // fflush 有问题， 读取两次， 清空回车字符
    fgets(domain, sizeof(domain), stdin);
    fgets(domain, sizeof(domain), stdin);
    domain[strlen(domain) - 1] = '\0';

    unsigned char buf[65536] = {0};
    DNS_HEADER *dns = (DNS_HEADER *)&buf;
    dns->id = (unsigned short)htons(id);
    dns->flags = htons(0x0000);
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char *qname = (unsigned char *)&buf[sizeof(DNS_HEADER)];
    dns_name_format(qname, domain);

    QUESTION *qinfo = (QUESTION *)&buf[sizeof(DNS_HEADER) + (strlen((const char *)qname) + 1)];
    qinfo->qtype = htons(1);
    qinfo->qclass = htons(1);

    int sendlen = sendto(fd, (char *)buf, sizeof(DNS_HEADER) + (strlen((const char *)qname) + 1) + sizeof(QUESTION), 0, (const struct sockaddr *)&serv, len);

    int recvlen = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);

    if (sendlen == recvlen)
    {
        printf("DNSrequest timed out\n");
    }
    else
    {
        char ip[20];
        inet_ntop(AF_INET, buf + recvlen - 4, ip, sizeof(ip));
        printf("the %s's ip addr is :%s\n", domain, ip);
    }
}

/**
 * @description: 添加模式，输入域名和对应的ip，添加到服务器的缓存中
 * @param {in} fd 客户端文件描述符 
 * @param {in} serv 服务器的套接字
 * @param {in} len 服务器套接字的长度
 * @return: NULL
 */
void add_mode(int fd, struct sockaddr_in serv, socklen_t len)
{
    printf("请输入要增加记录的域名和ip: eg: baidu.com 192.168.5.1\n");
    char mess[128] = {0};
    fgets(mess, sizeof(mess), stdin);
    fgets(mess, sizeof(mess), stdin);
    mess[strlen(mess) - 1] = '\0';

    unsigned char buf[65536] = {0};
    DNS_HEADER *dns = (DNS_HEADER *)&buf;
    dns->id = (unsigned short)htons(1);
    dns->flags = htons(0x0000);
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    memcpy(&buf[sizeof(DNS_HEADER)], mess, strlen(mess));
    int sendlen = sendto(fd, (char *)buf, sizeof(DNS_HEADER) + strlen(mess) + 1, 0, (const struct sockaddr *)&serv, len);
    int recvlen = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    printf("%s\n", buf);
}

/**
 * @description: 删除模式，输入要删除的域名，从服务器缓存中删除对应的记录
 * @param {in} fd 客户端文件描述符 
 * @param {in} serv 服务器的套接字
 * @param {in} len 服务器套接字的长度
 * @return: NULL
 */
void remove_mode(int fd, struct sockaddr_in serv, socklen_t len)
{
    printf("请输入要删除记录的域名: eg: baidu.com\n");
    char mess[128] = {0};
    fgets(mess, sizeof(mess), stdin);
    fgets(mess, sizeof(mess), stdin);
    mess[strlen(mess) - 1] = '\0';

    unsigned char buf[65536] = {0};
    DNS_HEADER *dns = (DNS_HEADER *)&buf;
    dns->id = (unsigned short)htons(2);
    dns->flags = htons(0x0000);
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    memcpy(&buf[sizeof(DNS_HEADER)], mess, strlen(mess));
    int sendlen = sendto(fd, (char *)buf, sizeof(DNS_HEADER) + strlen(mess) + 1, 0, (const struct sockaddr *)&serv, len);
    int recvlen = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    printf("%s\n", buf);
}

/**
 * @description: 同步模式，将服务器缓存中的dns记录同步到磁盘中
 * @param {in} fd 客户端文件描述符 
 * @param {in} serv 服务器的套接字
 * @param {in} len 服务器套接字的长度
 * @return: NULL
 */
void sync_mode(int fd, struct sockaddr_in serv, socklen_t len)
{
    printf("start sync, please wait\n");
    unsigned char buf[65536] = {0};
    DNS_HEADER *dns = (DNS_HEADER *)&buf;
    dns->id = (unsigned short)htons(3);
    dns->flags = htons(0x0000);
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    int sendlen = sendto(fd, (char *)buf, sizeof(DNS_HEADER), 0, (const struct sockaddr *)&serv, len);
    int recvlen = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    printf("%s\n", buf);
}

int main(int argc, const char *argv[])
{
    // 创建套接字
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        printf("创建套接字失败\n");
        exit(1);
    }

    // 初始化服务器的IP和端口信息
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    inet_pton(AF_INET, "127.0.0.1", &serv.sin_addr.s_addr);
    //   serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53);
    socklen_t len = sizeof(serv);
    bind(fd, (const struct sockaddr *)&serv, len);
    while (1)
    {

        int mode;
        while (1)
        {
            printf("请输入模式：0:query, 1:add, 2:remove, 3:sync\n");
            // fgetc(stdin)
            scanf("%d", &mode);
            if (mode == 0 || mode == 1 || mode == 2 || 3)
                break;
        }
        switch (mode)
        {
        case 0:
            query_mode(fd, serv, len);
            break;
        case 1:
            add_mode(fd, serv, len);
            break;
        case 2:
            remove_mode(fd, serv, len);
            break;
        case 3:
            sync_mode(fd, serv, len);
            break;
        default:
            break;
        }
        ++id;
    }
}
