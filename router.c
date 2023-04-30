#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <arpa/inet.h>
#include <string.h>


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	int size_of_rtable = read_rtable(argv[1], rtable);
	
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 80000);
	int size_of_arp_table = 0;

	queue queue_of_packets = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct  ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
		struct arp_header *arp_hdr = (struct arp_header*)(buf + sizeof(struct ether_header));

		// /* Note that packets received are in network order,
		// any header field which has more than 1 byte will need to be conerted to
		// host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		// sending a packet on the link */

		/* IPV4 type*/
		if (ntohs(eth_hdr->ether_type) == 0x0800) {
			
			if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
				
				if (icmp_hdr->type == 8 && icmp_hdr->code == 0) {
					
					send_icmp(ip_hdr, ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
							0, 0, interface);
					continue;
				}
			}

			/* Valid MAC */
			uint8_t *mac_interface = malloc(sizeof(uint8_t) * 6);
			get_interface_mac(interface, mac_interface);
			int not_ok = 1;

			for (int i = 0; i < 6; i++) {
				if (mac_interface[i] != eth_hdr->ether_dhost[i]) {
					not_ok = 0;
				}
			}

			if (not_ok == 0) {
				continue;
			}

			/* Valid checksum */
			uint16_t check_ok = checksum((void *) ip_hdr, sizeof(struct iphdr));

			if (check_ok != 0) {
				continue;
			}

			/* Exceeded time */	
			ip_hdr->ttl --;		
			if (ip_hdr->ttl <= 0) {
				send_icmp(ip_hdr, ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
						11, 0, interface);
				continue;
			}

			/* Checksum update */
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((void *) ip_hdr, sizeof(struct iphdr)));

			/* Valid next hop */
			struct route_table_entry *best_route = get_best_route(rtable, ip_hdr->daddr, size_of_rtable);

			if (best_route == NULL) {
				send_icmp(ip_hdr, ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
						3, 0, interface);
				continue;	
			} 

			struct arp_entry *arp_entry = get_mac_entry(arp_table, best_route->next_hop, size_of_arp_table);

			/* If we don't have the entry, send a request */		
			if (arp_entry == NULL) {

				struct packet* to_send = malloc(sizeof(struct packet));
				memcpy(to_send->payload, buf, len);
				to_send->len = len;
				to_send->nexthop = best_route->next_hop;
				
				queue_enq(queue_of_packets, to_send);

				struct ether_header* eth_hdr_send = malloc(sizeof(struct ether_header));
				memset(eth_hdr_send->ether_dhost, 0xFF, 6);
				get_interface_mac(best_route->interface, eth_hdr_send->ether_shost);
				eth_hdr_send->ether_type = htons(0x0806);

				send_arp(best_route->next_hop, inet_addr(get_interface_ip(best_route->interface)), eth_hdr_send, best_route->interface,
						htons(1), eth_hdr_send->ether_dhost);

				
				free(eth_hdr_send);
				continue;
			}

			memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * 6);
            send_to_link(best_route->interface, buf, len);

			free(mac_interface);
		}

		/* ARP type */
		if (ntohs(eth_hdr->ether_type) == 0x0806) {

			/* If request, reply */
			if (arp_hdr->op == htons(1)) {
				
				if (arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {
				
					get_interface_mac(interface, eth_hdr->ether_shost);
					memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);
					
					send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, interface, htons(2), arp_hdr->sha);
					continue;
				}
				else {
					continue;
				}
			} 
			
			/* If reply, update the arp table */
			if (arp_hdr->op == htons(2)) {
				
				if (arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {

					add_in_arp_table(arp_table, &size_of_arp_table, arp_hdr->sha, arp_hdr->spa);
					queue_of_packets = packets_left(queue_of_packets, arp_hdr->spa, arp_hdr->sha, interface);
			
				}
				else {
					continue;
				} 
			}
		}
	}
	free(arp_table);
	free(rtable);
}