#include "lib.h"
#include "protocols.h"
#include "queue.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>


int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s, (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

int send_to_link(int intidx, char *frame_data, size_t len)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 */
	int ret;
	ret = write(interfaces[intidx], frame_data, len);
	DIE(ret == -1, "write");
	return ret;
}

ssize_t receive_from_link(int intidx, char *frame_data)
{
	ssize_t ret;
	ret = read(interfaces[intidx], frame_data, MAX_PACKET_LEN);
	return ret;
}

int socket_receive_message(int sockfd, char *frame_data, size_t *len)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the
	 * interface, eg 1500 bytes
	 * */
	int ret = read(sockfd, frame_data, MAX_PACKET_LEN);
	DIE(ret < 0, "read");
	*len = ret;
	return 0;
}

int recv_from_any_link(char *frame_data, size_t *length) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				ssize_t ret = receive_from_link(i, frame_data);
				DIE(ret < 0, "receive_from_link");
				*length = ret;
				return i;
			}
		}
	}

	return -1;
}

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	int ret;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ret = ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	DIE(ret == -1, "ioctl SIOCGIFADDR");
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	int ret;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ret = ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	DIE(ret == -1, "ioctl SIOCGIFHWADDR");
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;

	return (a << 4) | b;
}

int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}

void init(int argc, char *argv[])
{
	for (int i = 0; i < argc; ++i) {
		printf("Setting up interface: %s\n", argv[i]);
		interfaces[i] = get_sock(argv[i]);
	}
}


uint16_t checksum(uint16_t *data, size_t len)
{
	unsigned long checksum = 0;
	uint16_t extra_byte;
	while (len > 1) {
		checksum += ntohs(*data++);
		len -= 2;
	}
	if (len) {
		*(uint8_t *)&extra_byte = *(uint8_t *)data;
		checksum += extra_byte;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >>16);
	return (uint16_t)(~checksum);
}

int read_rtable(const char *path, struct route_table_entry *rtable)
{
	FILE *fp = fopen(path, "r");
	int j = 0, i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL) {
		p = strtok(line, " .");
		i = 0;
		while (p != NULL) {
			if (i < 4)
				*(((unsigned char *)&rtable[j].prefix)  + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *)&rtable[j].next_hop)  + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *)&rtable[j].mask)  + i % 4) = atoi(p);

			if (i == 12)
				rtable[j].interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}
		j++;
	}
	return j;
}

int parse_arp_table(char *path, struct arp_entry *arp_table)
{
	FILE *f;
	fprintf(stderr, "Parsing ARP table\n");
	f = fopen(path, "r");
	DIE(f == NULL, "Failed to open %s", path);
	char line[100];
	int i = 0;
	for(i = 0; fgets(line, sizeof(line), f); i++) {
		char ip_str[50], mac_str[50];
		sscanf(line, "%s %s", ip_str, mac_str);
		fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
		arp_table[i].ip = inet_addr(ip_str);
		int rc = hwaddr_aton(mac_str, arp_table[i].mac);
		DIE(rc < 0, "invalid MAC");
	}
	fclose(f);
	fprintf(stderr, "Done parsing ARP table.\n");
	return i;
}

struct route_table_entry *get_best_route(struct route_table_entry *rtable, uint32_t ip_dest, int rtable_len) 
{
	struct route_table_entry *best = NULL;

	int left = 0;
	int right = rtable_len;
	int idx = -1;

	while (left <= right) {
        int mid = (left + right) / 2;
        if (rtable[mid].prefix == (rtable[mid].mask & ip_dest)) {
            idx = mid;
        } else if (rtable[mid].prefix < (rtable[mid].mask & ip_dest)) {
           	left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    for (int i = idx; i < rtable_len; i++) {
		if(((ip_dest & rtable[i].mask) == rtable[i].prefix) && (best == NULL || best->mask < rtable[i].mask)) {
			best = &rtable[i];
		}
    }
	
    return best;
}

struct arp_entry *get_mac_entry(struct arp_entry *arp_table, uint32_t ip_dest, int arp_len)
{
    for (int i = 0; i < arp_len; i++) {
        if (arp_table[i].ip == ip_dest)
            return &arp_table[i];
    }
    return NULL;
}

void send_icmp(void *ip, uint32_t daddr, uint32_t saddr, uint8_t *dha, uint8_t *sha, uint16_t type, uint16_t code, int interface)
{
	int length = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr);
	char payload[1600];
	char *message = payload;

	struct ether_header eth_hdr;
	memcpy(eth_hdr.ether_dhost, sha, 6);
	memcpy(eth_hdr.ether_shost, dha, 6);
	eth_hdr.ether_type = htons(0x0800);

	struct iphdr ip_hdr;
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = 1;
	ip_hdr.ttl = 64;
	ip_hdr.daddr = saddr;
	ip_hdr.saddr = daddr;
	ip_hdr.check = 0;
	ip_hdr.check = htons(checksum((void *)&ip_hdr, sizeof(struct iphdr)));
	
	struct icmphdr icmp_hdr;
	icmp_hdr.type = type;
	icmp_hdr.code = code;
	icmp_hdr.checksum = 0;
	icmp_hdr.checksum = htons(checksum((void *)&icmp_hdr, sizeof(struct icmphdr)));
	
	memcpy(message, &eth_hdr, sizeof(struct ether_header));
	memcpy(message + sizeof(struct ether_header), &ip_hdr, sizeof(struct iphdr));
	memcpy(message + sizeof(struct ether_header) +  sizeof(struct iphdr), &icmp_hdr, sizeof(struct icmphdr));
	memcpy(message + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip, sizeof(struct iphdr)); 
	
	send_to_link(interface, message, length);
}

void send_arp(uint32_t daddr, uint32_t saddr, void *eth_hdr, int interface, uint16_t arp_op, uint8_t *sha)
{
	int length = sizeof(struct arp_header) + sizeof(struct ether_header);
	char payload[1600];
	char *message = payload;

	struct arp_header arp_hdr;	
	arp_hdr.htype = htons(1);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = arp_op;
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	arp_hdr.spa = saddr;
	arp_hdr.tpa = daddr;
	get_interface_mac(interface, arp_hdr.sha);
	memcpy(arp_hdr.tha, sha, 6);

	memcpy(message, eth_hdr, sizeof(struct ether_header));
	memcpy(message + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));
	
	send_to_link(interface, message, length);
}

void add_in_arp_table(struct arp_entry *arp_table, int *size, uint8_t *mac, uint32_t ip) 
{
	arp_table[*size].ip = ip;
	memcpy(arp_table[*size].mac, mac, 6);
	(*size)++;
}

queue packets_left(queue packets_queue, uint32_t spa, uint8_t *sha, uint32_t interface) 
{
	queue q_aux = queue_create();
	while (!queue_empty(packets_queue)) {
					
		struct packet *to_send = (struct packet*) queue_deq(packets_queue);
				
		if (to_send->nexthop == spa) {
			memcpy(to_send->payload, sha, 6);
			send_to_link(interface, to_send->payload, to_send->len);	
		} else {						
			queue_enq(q_aux, to_send);
		}
	}
	return q_aux;
}


