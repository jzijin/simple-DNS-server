#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <signal.h>
#include <pthread.h>
#include "hashtable.h"
#include "dns_header.h"

// 创建一个哈希表来存储值
HashTable *table;

// 保存到哪个文件
const char *filename = "dns_cache.txt";
FILE *dns_cache = NULL;

/**
 * @description: 增加dns记录到缓存中
 * @param {in} domain 要增加记录的域名
 * @param {in} ip 要增加记录的ip地址
 * @return: 成功返回0,失败返回1
 */
int add_dns(char *domain, char *ip)
{
    if (hashtable_add(table, (void *)domain, (void *)ip) == CC_OK)
        return 0;
    return 1;
}

/**
 * @description: 从哈希表中删除DNS记录
 * @param {in} domain 要删除记录的域名
 * @return: 成功返回0,失败返回1
 */
int remove_dns(char *domain)
{
    if (hashtable_remove(table, (void *)domain, NULL) == CC_OK)
        return 0;
    return 1;
}

/**
 * @description: 从哈希表中查询dns记录
 * @param {in} 要查询记录的域名
 * @param {out} ip 传出参数，将查到的ip传出
 * @return: 成功返回0,失败返回1
 * @note: 这边的ip使用的二级指针
 */
int query_dns(char *domain, char **ip)
{
    if (hashtable_get(table, domain, (void *)ip) == CC_OK)
        return 0;
    return 1;
}

// split with space
/**
 * @description: 将域名ip字符串解析成域名ip传出
 *               eg: www.baidu.com 1.1.1.1->domain=www.baidu.com ip=1.1.1.1
 * @param {in} name_ip 域名ip字符串 
 * @param {out} domain 输出域名指针
 * @param {out} ip 输出ip地址
 * @return: NULL
 * @note: memcpy 没有拷贝\0, domain和ip开辟内存空间的时候需要初始化为0.
 */
void exstract_domain_ip(char *name_ip, char *domain, char *ip)
{
    int i = 0;
    char *tmp = name_ip;
    while (*tmp++ != ' ')
    {
        ++i;
    }
    memcpy(domain, name_ip, i);
    // 字符串的结束符
    // 这里memory copy 并没有加上 结束符 \0, 因此需要在开辟内存空间的时候就初始化为0
    // strncat(domain, "\0", 1);
    memcpy(ip, name_ip + i + 1, strlen(name_ip) - i - 1);
    // strncat(ip, "\0", 1);
}

// 从文件中加载DNS到哈希表中
/**
 * @description: 从文件加载dns记录到哈希表中
 * @param {in} filename 文件名 
 * @return: NULL
 */
void load_dns_from_file(const char *filename)
{
    dns_cache = fopen(filename, "r");
    if (dns_cache == NULL)
    {
        printf("con not load file error\n");
    }
    while (!feof(dns_cache))
    {
        // 由于hashtable_add 直接使用浅拷贝，所以这边不能用数组, 必须用malloc开辟空间才不会出错
        // 会在hashtable_remove内部实现释放
        // the create memory and init with 0 is very important in here.
        // It is very important when you malloc memory with init
        char *name = calloc(256, sizeof(char));
        char *ip = calloc(256, sizeof(char));

        char line[100] = {0};
        fgets(line, sizeof(line), dns_cache);

        if(line[strlen(line) - 1] == '\n')
            line[strlen(line)-1] = '\0';

        // if there is another function ? delete the new line of the file?
        // here init the line so this place use '\0' to jadge
        // printf("line = %s, %d\n", line, strlen(line));
        if(line[0] != '\0')
        {
            exstract_domain_ip(line, name, ip);
        }
        else
        {
            continue; 
        }
        // fscanf(dns_cache, "%s %s", name, ip);
        // if(name == "\n" || ip == "\n")
        // {
        //     printf("error\n");
        //     continue;
        // }
        if (add_dns(name, ip) != 0)
        {
            printf("hashtable add error");
            exit(1);
        }
    }
    fclose(dns_cache);
}

// convert 5baidu3com to baidu.com
/**
 * @description: 从dns报文格式的域名信息中得到域名
 *               eg: 5baidu3com -> baidu.com
 * @param {in} dns_host dns报文格式的域名信息
 * @param {out} domain 输出的域名  
 * @return: NULL
 */
void domain_name_format(char *domain, char *dns_host)
{
    while (*dns_host)
    {
        int len = (int)*dns_host;
        ++dns_host;
        while (len--)
        {
            *domain++ = *dns_host++;
        }
        *domain++ = '.';
    }
    domain--;
    *domain = '\0';
}

/**
 * @description: 查询模式下的应答信息
 * @param {in} recvlen 接受到信息的长度 
 * @param {in} old_buf 接收到信息的缓存
 * @param {in} fd 服务器的文件描述符
 * @param {in} client 客户端的套接字
 * @param {in} len 客户端套接字的长度
 * @return: NULL
 */
void query_response(int recvlen, char old_buf[65536], int fd, struct sockaddr_in client, socklen_t len)
{

    char buf[65536];
    // 为什么要深拷贝才能使用呢？？？？？
    for (int i = 0; i < 65536; i++)
    {
        buf[i] = old_buf[i];
    }

    // store the domain message
    char domain[128];
    // store the dnsdomainmessage
    char dns_host[128];
    int dns_host_length = recvlen - sizeof(DNS_HEADER) - sizeof(QUESTION);

    // printf("name length = %d\n", );
    memcpy(dns_host, buf + sizeof(DNS_HEADER), dns_host_length);

    domain_name_format(domain, dns_host);

    DNS_HEADER *dns = (DNS_HEADER *)&buf;
    // set response header
    dns->flags = htons(0x8000);
    // set response flags
    dns->q_count = htons(1);

    char *ip;
    if (query_dns(domain, &ip) != 0)
    {
        // if can't find the ip in hashtable
        dns->ans_count = htons(0);
        sendto(fd, buf, recvlen, 0, (const struct sockaddr *)&client, len);
    }
    else
    {

        dns->ans_count = htons(1);
        ANSWERS *ans = (ANSWERS *)&buf[recvlen];
        ans->offset = htons(0xc00c);
        ans->atype = htons(1);
        ans->aclass = htons(1);
        ans->ttl = htons(ntohs(2));
        ans->data_length = htons(4);

        // convert a string ip to network ip
        int res = inet_pton(AF_INET, ip, &ans->ip);

        if (res == 0)
        {
            printf("error\n");
            exit(1);
        }
        sendto(fd, buf, recvlen + sizeof(ANSWERS), 0, (const struct sockaddr *)&client, len);
    }
}


/**
 * @description: 添加模式下的应答信息
 * @param {in} recvlen 接受到信息的长度 
 * @param {in} old_buf 接收到信息的缓存
 * @param {in} fd 服务器的文件描述符
 * @param {in} client 客户端的套接字
 * @param {in} len 客户端套接字的长度
 * @return: NULL
 */
void add_response(int recvlen, char old_buf[65536], int fd, struct sockaddr_in client, socklen_t len)
{

    char buf[65536];
    // hashtable_add need calloc or malloc memory
    char *domain = (char *)calloc(128, sizeof(char));
    char *ip = (char *)calloc(20, sizeof(char));
    for (int i = 0; i < 65536; i++)
    {
        buf[i] = old_buf[i];
    }
    char *name_ip = &buf[sizeof(DNS_HEADER)];
    exstract_domain_ip(name_ip, domain, ip);
    // add dns record to hashtable
    if (add_dns(domain, ip) != 0)
    {
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "error", strlen("error"));
        // sendto(fd, buf, strlen(buf), 0, )
        sendto(fd, buf, strlen(buf) + 1, 0, (const struct sockaddr *)&client, len);
    }
    else
    {
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "OK", strlen("OK"));
        sendto(fd, buf, strlen(buf) + 1, 0, (const struct sockaddr *)&client, len);
    }
}

/**
 * @description: 删除模式下的应答信息
 * @param {in} recvlen 接受到信息的长度 
 * @param {in} old_buf 接收到信息的缓存
 * @param {in} fd 服务器的文件描述符
 * @param {in} client 客户端的套接字
 * @param {in} len 客户端套接字的长度
 * @return: NULL
 */
void remove_response(int recvlen, char old_buf[65536], int fd, struct sockaddr_in client, socklen_t len)
{

    char buf[65536];
    for (int i = 0; i < 65536; i++)
    {
        buf[i] = old_buf[i];
    }
    char *domain = &buf[sizeof(DNS_HEADER)];
    // remove from hashtable
    if (remove_dns(domain) != 0)
    {
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "error", strlen("error"));
        sendto(fd, buf, strlen(buf) + 1, 0, (const struct sockaddr *)&client, len);
    }
    else
    {
        memset(buf, 0, sizeof(buf));
        strncpy(buf, "OK", strlen("OK"));
        sendto(fd, buf, strlen(buf) + 1, 0, (const struct sockaddr *)&client, len);
    }
}

/**
 * @description: 遍历存储dns记录的哈希表时的回调函数，实现将dns记录写道磁盘文件的功能
 * @param {in} 哈希表中的键值，即域名 
 * @return: NULL
 */
void write_to_file(const void *key)
{
    char *value;
    query_dns((char *)key, &value);
    fprintf(dns_cache, "%s %s\n", key, value);
}

/**
 * @description: 同步模式下的应答信息
 * @param {in} recvlen 接受到信息的长度 
 * @param {in} old_buf 接收到信息的缓存
 * @param {in} fd 服务器的文件描述符
 * @param {in} client 客户端的套接字
 * @param {in} len 客户端套接字的长度
 * @return: NULL
 */
void sync_response(int recvlen, char old_buf[65536], int fd, struct sockaddr_in client, socklen_t len)
{

    char buf[256] = {0};
    printf("start sync the domain and ip\n");
    dns_cache = fopen(filename, "w");
    if (dns_cache == NULL)
    {
        perror("open failed");
        exit(1);
    }
    void write_to_file(const void *key);
    hashtable_foreach_key(table, write_to_file);
    fclose(dns_cache);
    strncpy(buf, "OK", strlen("OK"));
    sendto(fd, buf, strlen(buf) + 1, 0, (const struct sockaddr *)&client, len);
    printf("success sync\n");

}

// void *timer_sync(void *arg)
// {

//     printf("child id = %lu\n", pthread_self());
//     // 每隔10s 自动刷新 dns记录到文件中
//     struct sigaction act;
//     act.sa_flags = 0;
//     sigemptyset(&act.sa_mask);
//     // 添加屏蔽信号 临时的屏蔽信号
//     // sigaddset(&act.sa_mask, SIGALRM);
//     act.sa_handler = sync_dns;
//     sigaction(SIGALRM, &act, NULL);

//     struct itimerval new_val;
//     // 设置第一次触发的时间
//     new_val.it_value.tv_sec = 2;
//     new_val.it_value.tv_usec = 0;
//     // 设置周期性触发的时间
//     new_val.it_interval.tv_usec = 0;
//     new_val.it_interval.tv_sec = 2;
//     setitimer(ITIMER_REAL, &new_val, NULL);

//     return NULL;
// }

int main(int argc, const char *argv[])
{
    // init hash table;
    if (hashtable_new(&table) != CC_OK)
    {
        printf("create hashtable error");
        exit(1);
    }

    load_dns_from_file(filename);

    // 创建套接字
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        perror("创建套接字失败\n");
        exit(1);
    }
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53);
    socklen_t len = sizeof(serv);
    int ret = bind(fd, (const struct sockaddr *)&serv, len);
    if (ret == -1)
    {
        perror("bind error");
        exit(1);
    }

    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    while (1)
    {
        // 接受数据
        char buf[65536] = {0};
        int recvlen = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&client, &client_len);
        if (recvlen == -1)
        {
            perror("recvfrom error");
            exit(1);
        }

        // 判断模式
        DNS_HEADER *dns = (DNS_HEADER *)&buf;
        unsigned short mode = ntohs(dns->id);
        if (mode == 1)
        {
            add_response(recvlen, buf, fd, client, len);
        }
        else if (mode == 2)
        {
            remove_response(recvlen, buf, fd, client, len);
        }
        else if (mode == 3)
        {
            sync_response(recvlen, buf, fd, client, len);
        }
        else
        {
            query_response(recvlen, buf, fd, client, len);
        }
    }
    close(fd);
    hashtable_destroy(table);
    return 0;
}
