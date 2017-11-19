//============================================================================
// Name        : pcap_sockets.cpp
// Author      : 
// Version     :
// Copyright   : Adrian Moreno
//============================================================================

#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

using namespace std;
const std::string snif_iface = "wlo1";

void pcap_handler_callback(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet) {
	cout << "------- paquete recibido -------" << endl;
	cout << "Len :" << std::dec << header->len << endl;
	cout << "CapLen :" << header->caplen << endl;
	ether_header * ethernet_header = (ether_header *) packet;
	uint16_t ethernet_frame_type = ntohs(ethernet_header->ether_type);
	switch (ethernet_frame_type) {
	case ETHERTYPE_IP: {
		cout << "-- IP --" << endl;
		const ip * ip_header = ((const ip *) (packet + 24));
		char ip_addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip_header->ip_src), ip_addr, INET_ADDRSTRLEN);
		cout << "src: " << ip_addr << endl;
		inet_ntop(AF_INET, &(ip_header->ip_dst), ip_addr, INET_ADDRSTRLEN);
		cout << "dst: " << ip_addr << endl;

		break;
	}
	case ETHERTYPE_ARP:
		cout << "-- ARP --" << endl;
		break;
	default:
		cout << "-- UNKNOWN --" << endl;
		cout << "Type: " << ethernet_frame_type << endl;
		break;
	}
	pcap_stat p_stat;
	pcap_stats(((pcap_t *)(args)),&p_stat);
	cout << "Received: "<< std::dec << p_stat.ps_recv << " pckts  - Drop: " << p_stat.ps_drop << " Pckts - ifDrop: " << p_stat.ps_ifdrop << " pckts" << endl;

}

int main() {
	pcap_if_t * ifaces;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_findalldevs(&ifaces, errbuf);
	pcap_if_t * it = ifaces;
	pcap_if_t * wlo1_iface = 0;
	while (it) {
		if (string(it->name) == snif_iface) {
			wlo1_iface = it;
			break;
		}
		it = it->next;
	}
	if (wlo1_iface == 0) {
		cout << "Error: wlo1 iface not found" << endl;
	}
	cout << "Interface : " << wlo1_iface->name << endl;

	pcap_t * p_handler;
	p_handler = pcap_open_live(wlo1_iface->name, BUFSIZ, 0, -1, errbuf);
	if (p_handler == 0) {
		cout << "Error: cannot open pcap session on " << wlo1_iface->name
				<< "interface" << endl;
	}
	cout << "Empezamos a capturar" << endl;

	if (pcap_datalink(p_handler) != DLT_EN10MB) {
		fprintf(stderr,
				"Device %s doesn't provide Ethernet headers - not supported\n",
				wlo1_iface->name);
		return (2);
	}

	pcap_loop(p_handler, 1000, pcap_handler_callback, (u_char *)(p_handler));

	pcap_close(p_handler);
	return 0;
}
