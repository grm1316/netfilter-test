#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define IP_HEADER_LENGTH 20
#define TCP_HEADER_LENGTH 20

char* host;

static int parse_packet(unsigned char* data, int len) {
    struct iphdr* ip_header = (struct iphdr*)data;
    if (ip_header->protocol != IPPROTO_TCP) return 0;
    
    struct tcphdr* tcp_header = (struct tcphdr*)(data + IP_HEADER_LENGTH);
    if (ntohs(tcp_header->dest) != 80) return 0;

    unsigned char* payload = data + IP_HEADER_LENGTH + TCP_HEADER_LENGTH;
    int payload_len = len - IP_HEADER_LENGTH - TCP_HEADER_LENGTH;
    if (payload_len <= 0) return 0;

    // HTTP GET 요청인지 확인
    if (memcmp(payload, "GET ", 4) != 0 && memcmp(payload, "POST ", 5) != 0) {
        return 0;
    }

    void* host_pattern = memmem(payload, payload_len, "Host: ", 6);
    if (host_pattern == NULL) return 0;

    char* host_start = (char*)host_pattern + 6;
    char* host_end = memchr(host_start, '\r', payload_len - (host_start - (char*)payload));
    if (host_end == NULL) return 0;

    int host_len = host_end - host_start;
    char detected_host[256] = {0};
    memcpy(detected_host, host_start, host_len);

    if (strncmp(detected_host, host, strlen(host)) == 0) {
        printf("Detected harmful site: %s\n", detected_host);
        return 1;
    }

    return 0;
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data) {
    unsigned char *packet_data;
    int len = nfq_get_payload(nfa, &packet_data);
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    u_int32_t id = ntohl(ph->packet_id);

    if (len >= 0) {
        if (parse_packet(packet_data, len)) {
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("syntax: netfilter-test <host>\n");
        printf("sample: netfilter-test test.gilgil.net\n");
        return -1;
    }

    host = argv[1];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &callback, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
