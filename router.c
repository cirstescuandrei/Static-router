#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"
#include <string.h>
#include <arpa/inet.h>

/* Gets ARP entry from table */
struct arp_table_entry* get_arp_entry(uint32_t dest_ip, struct arp_table_entry *arp_table, int arp_table_len) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == dest_ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

/* Checks to see if the destination MAC is the router interface */
int check_mac(uint8_t *router_mac, uint8_t *dest_mac) {
	char broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	return (!strncmp(broadcast_addr, (char *)dest_mac, 6) || !strncmp((char *)router_mac, (char *)dest_mac, 6));
}

/* Returns the best route from the route table or null if no route
 * is found using a trie
 * Each trie node has two children (one for each bit)
 * We go down the trie according to the ip bits
 * Whenever a non-null route node is found within the trie
 * it is saved as the best match 
 */
struct route_table_entry* get_best_route(uint32_t ip_dest, struct route_table_entry* rtable, int rtable_len, struct trie_node *trie) {
	struct route_table_entry *best_route = NULL;

	uint32_t ip = ntohl(ip_dest);

	uint8_t position = 31;
	uint32_t bitmask = 1 << position;

	uint8_t current_bit = (ip & bitmask) >> position;

	while(trie->child[current_bit] != NULL) {
		if (trie->child[current_bit]->route != NULL) {
			best_route = trie->child[current_bit]->route;
		}

		trie = trie->child[current_bit];
		bitmask >>= 1;
		position--;
		current_bit = (bitmask & ip) >> position;
	}

	return best_route;
}

/* Send ARP reply */
void send_arp_reply(struct ether_header *eth_hdr, int len, int interface, uint8_t *router_mac) {
	struct arp_header *arp_hdr = (struct arp_header*)((uint8_t *)eth_hdr + sizeof(struct ether_header));

	/* For the Layer 2 addresses, the destination becomes the original sender
	 * and the sender becomes the router	
	 */
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, router_mac, 6);

	arp_hdr->op = htons(ARP_REPLY);

	/* Reply header should be:
	 *	sha = MAC of router
	 *	spa = IP of original target
	 *	tha = MAC of the host
	 *	tpa = IP of the host
	 */

	/* Swap sender and target IP */
	uint32_t sender_ip = arp_hdr->spa;
	arp_hdr->spa = arp_hdr->tpa;
	arp_hdr->tpa = sender_ip;

	/* Change target MAC to sender's and sender MAC to the router's */
	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	memcpy(arp_hdr->sha, router_mac, 6);


	send_to_link(interface, (char *)eth_hdr, len);
}

/* Populated ARP header */
void init_arp_request_header(struct arp_header *arp_hdr) {
	arp_hdr->htype = htons(1); // Ethernet protocol
	arp_hdr->ptype = htons(IPV4); // IPv4 protocol
	arp_hdr->hlen = 6; // 6 bytes for MAC address
	arp_hdr->plen = 4; // 4 bytes for IPv4
	arp_hdr->op = htons(ARP_REQUEST); // ARP request
}

void send_arp_request(struct ether_header *eth_hdr, char *buf, int len, int interface,
		queue packet_queue, struct route_table_entry *best_route) {

	/* Enqueue packet until we get an ARP reply */
	struct ether_packet* packet = malloc(sizeof(struct ether_packet));
	memcpy(packet->buf, buf, len);
	packet->len = len;

	queue_enq(packet_queue, packet);

	/* Set Layer 2 broadcast; ether_shost is already the router's MAC */
	eth_hdr->ether_type = htons(ARP);
	memset(eth_hdr->ether_dhost, 0xff, 6);
	
	struct arp_header arp_hdr;
	init_arp_request_header(&arp_hdr);
			
	/* Sender IP and MAC are the router's */
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6);
	arp_hdr.spa = inet_addr(get_interface_ip(best_route->interface));

	/* Set target MAC to 0 and target ip to next hop */
	memset(arp_hdr.tha, 0, 6);
	arp_hdr.tpa = best_route->next_hop;

	/* Set up packet */
	memcpy((uint8_t *)eth_hdr + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));
	len = sizeof(struct ether_header) + sizeof(struct arp_header);

	/* Send packet to link */
	send_to_link(best_route->interface, buf, len);
}

/* Send ICMP echo reply */
void send_icmp_echo_reply(struct ether_header *eth_hdr, int len, int interface) {
	struct iphdr *ip_hdr = (struct iphdr *)((uint8_t *)eth_hdr + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)((uint8_t *)ip_hdr + sizeof(struct iphdr));

	/* The router only handles echo requests
	 * Drop all other ICMP packets with the router as the destination
	 */
	if (icmp_hdr->type != ICMP_ECHO_REQUEST) {
		return;
	}

	uint8_t temp_buf[6];
	uint32_t ip_addr;

	/* Change code to ECHO_REPLY */
	icmp_hdr->type = ICMP_ECHO_REPLY;

	/* Swap Level 2 and Level 3 addresses */
	memcpy(temp_buf, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, temp_buf, 6);

	ip_addr = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = ip_addr;

	/* Recalculate IP and ICMP checksums */
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

	send_to_link(interface, (char *)eth_hdr, len);
}

/* Send ICMP message of given type */
void send_icmp_msg(struct ether_header *eth_hdr, int interface, uint8_t type) {
	struct iphdr *ip_hdr = (struct iphdr *)((uint8_t *)eth_hdr + sizeof(struct ether_header));
	struct icmphdr icmp_hdr;

	uint8_t temp_buf[6];
	uint32_t ip_addr;

	/* Swap Level 2 and Level 3 addresses */
	memcpy(temp_buf, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, temp_buf, 6);

	struct iphdr old_hdr;
	memcpy(&old_hdr, ip_hdr, sizeof(struct iphdr));

	ip_addr = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = ip_addr;

	ip_hdr->tos = 0;
	ip_hdr->tot_len += sizeof(struct icmphdr);
	ip_hdr->id = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = ICMP;

	icmp_hdr.type = type;
	icmp_hdr.code = 0;

	/* Calculate cheksums */
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	icmp_hdr.checksum = 0;
	icmp_hdr.checksum = checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	struct ether_packet packet;

	/* Copy Level 2 and Level 3 headers */
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr);
	memcpy(packet.buf, eth_hdr, packet.len);

	/* Copy ICMP header */
	memcpy(packet.buf + packet.len, &icmp_hdr, sizeof(struct icmphdr));
	packet.len += sizeof(struct icmphdr);

	/* Copy old IP header */
	memcpy(packet.buf + packet.len, &old_hdr, sizeof(struct iphdr));
	packet.len += sizeof(struct iphdr);

	/* Copy first 64 bytes of payload */
	memcpy(packet.buf + packet.len, (uint8_t *)ip_hdr + sizeof(struct iphdr), 8);
	packet.len += 8;

	send_to_link(interface, packet.buf, packet.len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(80000 * sizeof(struct route_table_entry));
	DIE(rtable == NULL, "malloc");

	int rtable_len = read_rtable(argv[1], rtable);
	DIE(rtable_len < 0, "read_rtable");

	struct trie_node *trie_root = create_trie_from_rtable(rtable, rtable_len);

	struct arp_table_entry arp_table[10];
	int arp_table_len = 0;

	queue packet_queue = queue_create();

	while (1) {

		int interface;
		size_t len;
		uint8_t router_mac[6];

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/* Drop if malformed */
		if (len < sizeof(struct ether_header)) {
			continue;
		}

		get_interface_mac(interface, router_mac);

		/* Drop if MACs don't match or the destination address isn't broadcast */
		if (!check_mac(router_mac, eth_hdr->ether_dhost)) {
			continue;
		}

		/* IPv4 packets */
		if (ntohs(eth_hdr->ether_type) == IPV4) {
			struct iphdr* ip_hdr = (struct iphdr*)((uint8_t *)eth_hdr + sizeof(struct ether_header));

			/* Checksum invalid -> drop packet */
			if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
				continue;
			}

			uint8_t old_ttl = ip_hdr->ttl;
			ip_hdr->ttl--;

			/* ttl reached 0 -> drop packet and send ICMP response */
			if(ip_hdr->ttl < 1) {
				send_icmp_msg(eth_hdr, interface, ICMP_TTL_EXCEEDED);
				continue;
			}

			/* Handle ICMP packet addressed for the router */
			if (ip_hdr->protocol == ICMP && (ip_hdr->daddr == inet_addr(get_interface_ip(interface)))) {
				send_icmp_echo_reply(eth_hdr, len, interface);
				continue;
			}

			uint16_t old_checksum = ip_hdr->check;
			ip_hdr->check = ~(~old_checksum + ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_len, trie_root);

			/* No route found -> drop packet and send ICMP response */
			if (best_route == NULL) {
				send_icmp_msg(eth_hdr, interface, ICMP_DEST_UNREACHABLE);
				continue;
			}

			/* Set sender MAC to router's */
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			struct arp_table_entry *nexthop = get_arp_entry(best_route->next_hop, arp_table, arp_table_len);
			if (nexthop) {
				/* If we have found the MAC in the ARP table, send packet */
				memcpy(eth_hdr->ether_dhost, nexthop->mac, sizeof(eth_hdr->ether_dhost));

				send_to_link(best_route->interface, buf, len);
				continue;
			}

			/* Mac not found, send ARP request */
			send_arp_request(eth_hdr, buf, len, interface, packet_queue, best_route);

		/* ARP packets */
		} else if (ntohs(eth_hdr->ether_type) == ARP) {
			struct arp_header *arp_hdr = (struct arp_header*)((uint8_t *)eth_hdr + sizeof(struct ether_header));

			/* Handle ARP request and send reply */
			if (ntohs(arp_hdr->op) == ARP_REQUEST) {
				send_arp_reply(eth_hdr, len, interface, router_mac);

			/* Handle ARP reply -> check packet queue for routable packets */
			} else if (ntohs(arp_hdr->op) == ARP_REPLY) {

				/* Continue if we already have the MAC for the given IP
				 * As we don't know any new MACs, we won't be able to route
				 * the enqueued packets
				 */
				if (get_arp_entry(arp_hdr->spa, arp_table, arp_table_len)) {
					continue;
				}

				/* Update ARP table with new MAC */
				struct arp_table_entry arp_entry;
				arp_entry.ip = arp_hdr->spa;
				memcpy(arp_entry.mac, arp_hdr->sha, 6);

				arp_table[arp_table_len++] = arp_entry;


				/* That packets that still can't be sent will be requeued */
				queue unsent_queue = queue_create();

				while (!queue_empty(packet_queue)) {
					struct ether_packet *packet = queue_deq(packet_queue);
					struct iphdr *ip_hdr = (struct iphdr *)(packet->buf + sizeof(struct ether_header));

					struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_len, trie_root);

					struct arp_table_entry *nexthop = get_arp_entry(best_route->next_hop ,arp_table, arp_table_len);

					/* If host is unreacheable or we still don't know
					 * the MAC for the nexthop enqueue the packet
					 */
					if (best_route == NULL || nexthop == NULL) {
						queue_enq(unsent_queue, packet);
						continue;
					}

					struct ether_header *temp_eth_header = (struct ether_header *)packet->buf;

					/* Set Level 2 MACs */
					get_interface_mac(best_route->interface, temp_eth_header->ether_shost);
					memcpy(temp_eth_header->ether_dhost, nexthop->mac, 6);

					send_to_link(best_route->interface, packet->buf, packet->len);
					free(packet);
				}

				free(packet_queue);
				packet_queue = unsent_queue;
			}
		}
	}
}

