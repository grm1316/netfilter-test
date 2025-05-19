#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

#define IP_HEADER_LENGTH 20
#define TCP_HEADER_LENGTH 20

class PacketHandler {
private:
    string target_host;

public:
    PacketHandler(const string& host) : target_host(host) {}

    static uint32_t get_packet_id(struct nfq_data *tb) {
        struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
            return ntohl(ph->packet_id);
        }
        return 0;
    }

    bool parse_packet(unsigned char* data, int len) {
        if (len < IP_HEADER_LENGTH + TCP_HEADER_LENGTH) return false;

        struct iphdr* ip_header = (struct iphdr*)data;
        if (ip_header->protocol != IPPROTO_TCP) return false;

        struct tcphdr* tcp_header = (struct tcphdr*)(data + IP_HEADER_LENGTH);
        if (ntohs(tcp_header->dest) != 80) return false;

        unsigned char* payload = data + IP_HEADER_LENGTH + TCP_HEADER_LENGTH;
        int payload_len = len - IP_HEADER_LENGTH - TCP_HEADER_LENGTH;

        void* host_ptr = memmem(payload, payload_len, "Host: ", 6);
        if (!host_ptr) return false;

        char* host_start = (char*)host_ptr + 6;
        char* host_end = (char*)memchr(host_start, '\r', payload_len - (host_start - (char*)payload));
        if (!host_end) return false;

        int host_len = host_end - host_start;
        string detected_host(host_start, host_len);

        if (detected_host == target_host) {
            cout << "Detected harmful site: " << detected_host << endl;
            return true;
        }

        return false;
    }
};

PacketHandler* handler = nullptr;

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data)
{
    uint32_t id = PacketHandler::get_packet_id(nfa);
    
    unsigned char *packet_data;
    int len = nfq_get_payload(nfa, &packet_data);
    
    if (len >= 0 && handler->parse_packet(packet_data, len)) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        cout << "syntax: netfilter-test <host>" << endl;
        cout << "sample: netfilter-test test.gilgil.net" << endl;
        return 1;
    }

    handler = new PacketHandler(argv[1]);

    struct nfq_handle *h = nfq_open();
    if (!h) exit(1);

    if (nfq_unbind_pf(h, AF_INET) < 0) exit(1);
    if (nfq_bind_pf(h, AF_INET) < 0) exit(1);

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &callback, NULL);
    if (!qh) exit(1);

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) exit(1);

    int fd = nfq_fd(h);
    char buf[4096] __attribute__ ((aligned));

    while ((recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, sizeof(buf));
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    delete handler;
    
    return 0;
}
