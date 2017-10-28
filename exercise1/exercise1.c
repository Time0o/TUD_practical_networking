#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "pcap_sniff.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s [DEVICE]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char const *dev = argv[1];

    pcap_t *tcp_handle = pcap_sniff(dev, "tcp port 4242");
    pcap_t *udp_handle = pcap_sniff(dev, "udp port 2323");

    struct pcap_pkthdr *hdr;
    u_char const *pkt;

    printf("Waiting for packets on device '%s'...\n", dev);

    if (pcap_next_ex(tcp_handle, &hdr, &pkt) != 1) {
        pcap_perror(tcp_handle, "An error occured while reading a TCP package");
        exit(EXIT_FAILURE);
    }
    printf("Sniffed a TCP package on device '%s', port 4242!\n", dev);

    if (pcap_next_ex(udp_handle, &hdr, &pkt) != 1) {
        pcap_perror(udp_handle, "An error occured while reading a UDP package");
        exit(EXIT_FAILURE);
    }
    printf("Sniffed a UDP package on device '%s', port 2323!\n", dev);

    printf("Sniffed all packages, exiting...\n", dev);

    pcap_close(tcp_handle);
    pcap_close(udp_handle);

    exit(EXIT_SUCCESS);
}
