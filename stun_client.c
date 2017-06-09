// (c) joric 2010, public domain

#include <stdio.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <memory.h>

#ifndef __NET_H__
#define __NET_H__

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include "md5.h"
#include "hmac.h"
#define THREAD DWORD
#else
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <pthread.h>
#define SOCKET int
#define THREAD pthread_t
#define closesocket close
#define Sleep(t) usleep(t*1000)
#endif

#define ADDRESS struct sockaddr_in

#ifndef __HEX_H__
#define __HEX_H__

int hex_encode(char *dest, char *src, int len)
{
    char *table = "0123456789abcdef";
    int j;
    for (j = 0; j < len; j++)
    {
        dest[j * 2] = table[((src[j] >> 4) & 0xF)];
        dest[j * 2 + 1] = table[(src[j]) & 0x0F];
    }
    dest[len * 2] = 0;
    return len * 2;
}

void hex_decode(char *dest, char *src, int len)
{
    unsigned char v = 0;
    char *d = dest;
    char *p = src;
    int res;

    while ((res = sscanf(p, "%02x", &v)) > 0)
    {
        *d++ = v;
        p += res * 2;
    }
}

char *hex_string(char *buf, int len)
{
    static char msg[256];
    hex_encode(msg, buf, len);
    return msg;
}

#endif //__HEX_H__

typedef struct
{
    char *buf;
    int ofs;
    int size;
    int len;
} PACKET;

int packet_init(PACKET * m, char *buf, int buf_size)
{
    m->buf = buf;
    m->size = buf_size;
    m->len = 0;
    m->ofs = 0;
}

int packet_write(PACKET * m, int v)
{
    if (m && m->ofs < m->size - 1)
    {
        m->buf[m->ofs++] = v & 0xff;

        if (m->len < m->ofs)
            m->len++;

        return 1;
    }
    return 0;
}

unsigned long long packet_read(PACKET * m)
{
    return (m && (m->ofs < m->size - 1)) ? m->buf[m->ofs++] & 0xff : 0;
}

#define w8(m, v) packet_write(m, v & 0xff)
#define w16(m, v) w8(m, v >> 8) + w8(m, v)
#define w32(m, v) w16(m, v >> 16) + w16(m, v)
#define w64(m, v) w32(m, v >> 32) + w32(m, v)
#define wBuf(m, buf, len) { int k = 0, i = 0; for (i = 0; i < len; i++) k += w8(m, buf[i]); }
#define r8(m) packet_read(m)
#define r16(m) (((r8(m) << 8) | r8(m)) & 0xffff)
#define r32(m) ((r16(m) << 16) | r16(m))
#define r64(m) ((r32(m) << 32) | r32(m))
#define rBuf(m, buf, len) { int i= 0; for (i = 0; i < len; i++) buf[i] = r8(m); }

int round_int(int offset, int align)
{
    return offset + ((align - (offset % align)) % align);
}

void random_data(char *buf, int a, int b, int len)
{
    int i;
    for (i = 0; i < len; i++)
        buf[i] = a + rand() % (b - a);
}

typedef struct
{
    ADDRESS *addr;
    SOCKET sock;
    THREAD thread;
    char *host;
    int port;       //local port
    int started;
} LINK;

char *net_to_string(ADDRESS * addr)
{
    static char msg[64];
    unsigned char *ip = (unsigned char *) &addr->sin_addr.s_addr;
    sprintf(msg, "%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], ntohs(addr->sin_port));
    return msg;
}

void net_make_address(ADDRESS * addr, unsigned int ip, int port)
{
    memset(addr, 0, sizeof(ADDRESS));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = ip;
}

int net_resolve_address(ADDRESS * addr, char *host, int port)
{
    net_make_address(addr, 0, port);
    struct hostent *hp = (struct hostent *) gethostbyname(host);
    if (hp)
        *(int *) &addr->sin_addr.s_addr = *(int *) hp->h_addr_list[0];
}

int net_is_local_address(ADDRESS * addr)
{
    SOCKET sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ADDRESS loc_addr;
    net_make_address(&loc_addr, addr->sin_addr.s_addr, 0);  //ephemeral

    printf("Checking NAT: trying to bind to %s\n", net_to_string(&loc_addr));

    if (bind(sock, (struct sockaddr *) &loc_addr, sizeof(ADDRESS)) == 0)
    {
        printf("success, no NAT\n");
        closesocket(sock);
        return 1;
    }
    printf("failed, NAT present\n");
    return 0;
}

extern void net_recv(char *buf, int len);

static void *net_thread(void *param)
{
    int buf_size = 8192;
    char buf[buf_size];
    int len = 0;

    LINK *link = (LINK *) param;

    printf("resolving host %s\n", link->host);

    if (link->host)
        net_resolve_address(link->addr, link->host, link->port);

    printf("resolved to %s\n", net_to_string(link->addr));

    if ((link->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        goto cleanup;


    {
        link->port = 0; //ephemeral
        ADDRESS loc_addr;
        net_make_address(&loc_addr, INADDR_ANY, link->port);  

        if (bind(link->sock, (struct sockaddr *) &loc_addr, sizeof(ADDRESS)) < 0)
            goto cleanup;

        //trying to figure out local port

        int addr_size = sizeof(ADDRESS);
        getsockname(link->sock, (struct sockaddr *) &loc_addr, &addr_size);

        link->port = loc_addr.sin_port;

        printf("sitting on: %s\n", net_to_string(&loc_addr));
    }


    link->started = 1;

    while (link != NULL)
    {
        ADDRESS addr;
        int addr_size = sizeof(ADDRESS);

        len = recvfrom(link->sock, buf, buf_size, 0, (struct sockaddr *) &addr, &addr_size);

        if (len >= 0)
        {
            printf("received %d bytes from %s\n", len, net_to_string(&addr));
            net_recv(buf, len);
        }

        Sleep(1);
    }

cleanup:
    closesocket(link->sock);
}

int net_init()
{
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#endif
    return 0;
}

int net_open_link(LINK * link)
{
#ifdef _WIN32
    CreateThread((LPSECURITY_ATTRIBUTES) NULL, 0, (LPTHREAD_START_ROUTINE) net_thread, link, 0, &link->thread);
#else
    pthread_create(&link->thread, NULL, net_thread, link);
#endif
    return 0;
}

int net_send(LINK * link, char *buf, int len)
{
    printf("sending %d bytes to %s\n", len, net_to_string(link->addr));

    sendto(link->sock, buf, len, 0, (struct sockaddr *) link->addr, sizeof(struct sockaddr));
}

#endif //__NET_H__

#ifndef __STUN_H__
#define __STUN_H__

typedef struct
{
    ADDRESS base_address;
    ADDRESS mapped_address;
    ADDRESS changed_address;
    LINK *link;
    int state;
    int received;
    int test;
    int nat;
    int finished;
    int send_time;
    int results[4];
    int timeout;
    int presport;
} STUN;

#define TN(id) {static char buf[16]; sprintf(buf, "0x%04x", id); return buf; }
#define T(id) if (type == id) return #id+5; else

enum
{
    STUN_HEADER_SIZE = 20,
    STUN_MAGIC_COOKIE = 0x2112A442,
    STUN_BINDING_METHOD = 1,
    STUN_SHARED_SECRET_METHOD = 2,
    STUN_ALLOCATE_METHOD = 3,
    STUN_REFRESH_METHOD = 4,
    STUN_SEND_METHOD = 6,
    STUN_DATA_METHOD = 7,
    STUN_CHANNEL_BIND_METHOD = 9,
    STUN_REQUEST_CLASS = 0,
    STUN_INDICATION_CLASS = 1,
    STUN_SUCCESS_CLASS = 2,
    STUN_ERROR_CLASS = 3,
};

enum stun_vars
{
    STUN_MAPPED_ADDRESS = 0x0001,
    STUN_RESPONSE_ADDRESS = 0x0002,
    STUN_CHANGE_REQUEST = 0x0003,
    STUN_SOURCE_ADDRESS = 0x0004,
    STUN_CHANGED_ADDRESS = 0x0005,
    STUN_USERNAME = 0x0006,
    STUN_PASSWORD = 0x0007,
    STUN_MESSAGE_INTEGRITY = 0x0008,
    STUN_ERROR_CODE = 0x0009,
    STUN_UNKNOWN_ATTRIBUTES = 0x000A,
    STUN_REFLECTED_FROM = 0x000B,
    STUN_CHANNEL_NUMBER = 0x000C,
    STUN_LIFETIME = 0x000D,
    STUN_BANDWIDTH = 0x0010,
    STUN_PEER_ADDRESS = 0x0012,
    STUN_DATA = 0x0013,
    STUN_REALM = 0x0014,
    STUN_NONCE = 0x0015,
    STUN_RELAYED_ADDRESS = 0x0016,
    STUN_REQUESTED_ADDRESS_TYPE = 0x0017,
    STUN_REQUESTED_PROPS = 0x0018,
    STUN_REQUESTED_TRANSPORT = 0x0019,
    STUN_XOR_MAPPED_ADDRESS = 0x8020,
    STUN_TIMER_VAL = 0x0021,
    STUN_RESERVATION_TOKEN = 0x0022,
    STUN_XOR_REFLECTED_FROM = 0x0023,
    STUN_PRIORITY = 0x0024,
    STUN_USE_CANDIDATE = 0x0025,
    STUN_ICMP = 0x0030,
    STUN_END_MANDATORY_ATTR,
    STUN_START_EXTENDED_ATTR = 0x8021,
    STUN_SOFTWARE = 0x8022,
    STUN_ALTERNATE_SERVER = 0x8023,
    STUN_REFRESH_INTERVAL = 0x8024,
    STUN_FINGERPRINT = 0x8028,
    STUN_ICE_CONTROLLED = 0x8029,
    STUN_ICE_CONTROLLING = 0x802A,
};

#define TN(id) {static char buf[16]; sprintf(buf, "0x%04x", id); return buf; }
#define T(id) if (type == id) return #id+5; else

char *ATTR_NAME(int type)
{
    T(STUN_MAPPED_ADDRESS);
    T(STUN_RESPONSE_ADDRESS);
    T(STUN_CHANGE_REQUEST);
    T(STUN_SOURCE_ADDRESS);
    T(STUN_CHANGED_ADDRESS);
    T(STUN_USERNAME);
    T(STUN_PASSWORD);
    T(STUN_MESSAGE_INTEGRITY);
    T(STUN_ERROR_CODE);
    T(STUN_UNKNOWN_ATTRIBUTES);
    T(STUN_REFLECTED_FROM);
    T(STUN_CHANNEL_NUMBER);
    T(STUN_LIFETIME);
    T(STUN_BANDWIDTH);
    T(STUN_PEER_ADDRESS);
    T(STUN_DATA);
    T(STUN_REALM);
    T(STUN_NONCE);
    T(STUN_RELAYED_ADDRESS);
    T(STUN_REQUESTED_ADDRESS_TYPE);
    T(STUN_REQUESTED_PROPS);
    T(STUN_REQUESTED_TRANSPORT);
    T(STUN_XOR_MAPPED_ADDRESS);
    T(STUN_TIMER_VAL);
    T(STUN_RESERVATION_TOKEN);
    T(STUN_XOR_REFLECTED_FROM);
    T(STUN_PRIORITY);
    T(STUN_USE_CANDIDATE);
    T(STUN_ICMP);
    T(STUN_END_MANDATORY_ATTR);
    T(STUN_START_EXTENDED_ATTR);
    T(STUN_SOFTWARE);
    T(STUN_ALTERNATE_SERVER);
    T(STUN_REFRESH_INTERVAL);
    T(STUN_FINGERPRINT);
    T(STUN_ICE_CONTROLLED);
    T(STUN_ICE_CONTROLLING);
    TN(type);
};

void stun_write_header(PACKET * m, int type)
{
    char tsx_id[12];
    random_data(tsx_id, 0, 0xff, 12);
    w16(m, type);
    w16(m, 0);
    w32(m, STUN_MAGIC_COOKIE);
    wBuf(m, tsx_id, 12);
}

void stun_write_footer(PACKET * m)
{
    m->ofs = 2;
    w16(m, m->len - STUN_HEADER_SIZE);
}

int stun_xor_address(ADDRESS * addr)
{
    int i;
    int x = htonl(STUN_MAGIC_COOKIE);
    char *p = (char *) &x;
    int msb = ((char *) &x)[0] << 8 | ((char *) &x)[1];
    addr->sin_port ^= htons(msb);
    char *ip = (char *) &addr->sin_addr.s_addr;
    for (i = 0; i < 4; i++)
        ip[i] ^= p[i];
}

int stun_parse_address(PACKET * m, ADDRESS * addr)
{
    addr->sin_family = r16(m) == 1 ? 2 : 1;
    addr->sin_port = htons(r16(m));
    char *p = (char *) &addr->sin_addr.s_addr;
    rBuf(m, p, 4);
}

int stun_parse(STUN * stun, PACKET * m)
{
    m->ofs = 0;
    int type = r16(m);
    int length = r16(m);
    int magic = r32(m);
    char tsx_id[12];

    if (magic != STUN_MAGIC_COOKIE)
        return 0;

    rBuf(m, tsx_id, 12);

    int msg = type & ~0x110;
    int code = type & 0x110;

    printf(" Message: %d (%d)\n", msg, code);
    printf("  hdr: length=%d, magic=0x%x, tsx_id=%s", length, magic, hex_string(tsx_id, 12));
    printf("\n");
    printf("  Attributes:\n");

    int offset = m->ofs;

    while ((offset - STUN_HEADER_SIZE) < length)
    {
        int attr = r16(m);
        int len = r16(m);

        //printf(" 0x%04x length=%d, ", attr, len);
        printf("  %s length=%d, ", ATTR_NAME(attr), len);

        switch (attr)
        {
            case STUN_MAPPED_ADDRESS:
            case STUN_RESPONSE_ADDRESS:
            case STUN_SOURCE_ADDRESS:
            case STUN_CHANGED_ADDRESS:
            case STUN_XOR_MAPPED_ADDRESS:
            {
                ADDRESS addr;

                stun_parse_address(m, &addr);

                if (attr == STUN_XOR_MAPPED_ADDRESS)
                    stun_xor_address(&addr);

                printf(net_to_string(&addr));

                if (attr == STUN_MAPPED_ADDRESS)
                    memcpy(&stun->mapped_address, &addr, sizeof(ADDRESS));

                if (attr == STUN_CHANGED_ADDRESS)
                    memcpy(&stun->changed_address, &addr, sizeof(ADDRESS));

                break;
            }

            case STUN_SOFTWARE:
                printf(m->buf + m->ofs);
                break;

            default:
                printf(hex_string(m->buf + m->ofs, len));
                break;
        }

        printf("\n");
        len = round_int(len, 4);
        offset += len + 4;
        m->ofs = offset;

        stun->received = 1;
    }

    return 1;
}

void stun_write_attr(PACKET * m, int attr, char *buf, int len)
{
    int pad = round_int(len, 4) - len;
    w16(m, attr);
    w16(m, len);
    wBuf(m, buf, len);
    m->ofs += pad;
}

#define stun_write_str(m,attr,str) stun_write_attr(m, attr, str, strlen(str));
#define stun_write_uint(m,attr,value) w16(m, attr); w16(m, 4); w32(m, value);

void stun_recv(STUN * stun, char *buf, int len)
{
    PACKET m;
    packet_init(&m, buf, len);
    stun_parse(stun, &m);
}

int stun_send_message(STUN * stun, int type)
{
    LINK *link = stun->link;
    PACKET mp;
    PACKET *m = &mp;

    char buf[1024];
    int buf_size = 1024;


    packet_init(m, buf, buf_size);

    switch (type)
    {
        case 1: // Test I 
            link->addr = &stun->base_address;
            stun_write_header(m, STUN_BINDING_METHOD);
            stun_write_footer(m);
            break;

        case 2: // Test II
            link->addr = &stun->base_address;
            stun_write_header(m, STUN_BINDING_METHOD);
            stun_write_uint(m, STUN_CHANGE_REQUEST, 4 + 2); //change addr & port
            stun_write_footer(m);
            break;

        case 3: // Test I(2)
            link->addr = &stun->changed_address;
            stun_write_header(m, STUN_BINDING_METHOD);
            stun_write_footer(m);
            break;

        case 4: // Test III
            link->addr = &stun->base_address;
            stun_write_header(m, STUN_BINDING_METHOD);
            stun_write_uint(m, STUN_CHANGE_REQUEST, 2); //change port
            stun_write_footer(m);
            break;

        default:
            break;
    }

    if (m->len)
    {
        net_send(link, m->buf, m->len);
        stun_parse(stun, m);
    }

    return m->len;
}

int stun_start(LINK * link, STUN * stun)
{
    stun->state = 0;
    link->addr = &stun->base_address;
    link->started = 0;
    stun->test = 1;
    stun->link = link;
    net_open_link(stun->link);
}

int stun_update(STUN * stun)
{
    int state = stun->state;

    switch (stun->state)
    {
        case 0: //starting
            if (stun->link->started)
            {
                int i;
                stun->timeout = 4;
                for (i = 0; i < 4; i++)
                    stun->results[i] = 0;
                state = 1;
            }
            break;

        case 1: //send message
            printf("\nTEST %d\n", stun->test);
            stun_send_message(stun, stun->test);
            stun->received = 0;
            stun->send_time = time(0);
            state = 2;
            break;

        case 2: //wait result
            if (time(0) - stun->send_time > stun->timeout)
                state = 3;
            if (stun->received)
                state = 4;
            break;

        case 3:
            printf("[timeout]\n");

            if (stun->test == 1)
                stun->finished = 1;

            if (stun->test == 2 && !stun->nat)
                stun->finished = 1;

            stun->results[stun->test - 1] = 0;
            stun->test++;
            state = 1;
            break;

        case 4:
            printf("[received %d]\n", stun->test);
            stun->timeout = time(0) - stun->send_time + 1;

            if (stun->test == 1)
                stun->nat = !net_is_local_address(&stun->mapped_address);

            if (stun->test != 1)
                stun->presport = (stun->mapped_address.sin_port == stun->link->port);


            stun->results[stun->test - 1] = 1;
            stun->test++;
            state = 1;
            break;
    }

    if (stun->test == 5)
        stun->finished = 1;

    stun->state = state;

    return !stun->finished;
}

#endif //__STUN_H__

STUN m_stun;
LINK m_link;

void net_recv(char *buf, int len)
{
    stun_recv(&m_stun, buf, len);
}

int main(int argc, char **argv)
{
    int port = 3478;
    char *host = "stun.xten.com";

    if (argc > 1)
        host = argv[1];

    net_init();

    LINK *link = &m_link;
    STUN *stun = &m_stun;

    link->host = host;
    link->port = port;

    stun_start(link, stun);

    while (stun_update(stun))
        Sleep(5);


    //make a mask for tests, i.e. 1,0,1,1 == 0x1011
    int i, mask = 0;
    for (i = 0; i < 4; i++)
        mask |= stun->results[i] << (3 - i) * 4;

    char *type = "Restricted NAT";

    switch (mask)
    {        
        case 0x0000:
            type = "UDP Blocked";
            break;
        case 0x1000:
            type = "UDP Firewall";
            break;
        case 0x1100:
            type = "Open Internet";
            break;
        case 0x1011:
            type = "Full Cone NAT";
            break;
    }

    printf("tests: %04x\n", mask);
    printf("NAT present: %d\n", stun->nat);
    printf("preserves port: %d\n", stun->presport);
    printf("type: %s\n", type);

}
