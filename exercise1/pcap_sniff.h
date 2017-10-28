#ifndef PCAP_SNIFF_H
#define PCAP_SNIFF_H

#include <pcap.h>

pcap_t *pcap_sniff(char const *device, char const *filter);

#endif
