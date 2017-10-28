#include <pcap.h>
#include <stdlib.h>

pcap_t *pcap_sniff(char const *dev, char const *filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    pcap_t *handle;
    struct bpf_program fp;

    // find network address and mask for given device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Failed to find properties for device '%s': %s\n", dev,
                errbuf);
        exit(EXIT_FAILURE);
    }

    // create a live capture handle
    handle = pcap_create(dev, errbuf);
    if (!handle) {
        fprintf(stderr, "Failed to create handle for device '%s': %s\n", dev,
                errbuf);
        exit(EXIT_FAILURE);
    }

    // set snapshot length to ensure that only whole packages are received
    pcap_set_snaplen(handle, 65535);

    // activate handle
    int ret_code = pcap_activate(handle);
    if (ret_code > 0) {
        pcap_perror(handle, "Warning");
    } else if (ret_code < 0) {
        pcap_perror(handle, "Failed to activate handle");
        exit(EXIT_FAILURE);
    }

    // compile filter program (0 => do not optimize)
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Failed to compile filter '%s': %s\n", filter, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to install filter '%s': %s\n", filter, errbuf);
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&fp);

    return handle;
}
