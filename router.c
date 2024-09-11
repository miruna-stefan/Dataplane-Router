// STEFAN MIRUNA ANDREEA 324CA
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


#define IP_ETHERTYPE 0x0800
#define ARP_ETHERTYPE 0x0806
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP_TIME_EXCEEDED 11
#define ICMP_DEST_UNREACHABLE 3
#define ARP_CACHE_CAPACITY 1000
#define RTABLE_CAPACITY 100000

struct arp_table_entry *arp_cache;
int arp_cache_size = 0;
struct route_table_entry rtable[RTABLE_CAPACITY];
queue arp_waiting_queue;
int arp_waiting_queue_size = 0;

struct waiting_for_arp_packet
{
	char buf[MAX_PACKET_LEN];
	int len;
	int best_route_interface;
	uint32_t next_hop_IP_address;
};

struct trie_node
{
	struct route_table_entry *entry;
	struct trie_node *left; // if current bit == 0 => go left
	struct trie_node *right; // if current bit == 1 => go right
	bool end_of_mask;
};

struct trie_node* create_node()
{
	struct trie_node* node = malloc(sizeof(struct trie_node));
	DIE(node == NULL, "malloc failed\n");
	
	node->entry = NULL;
	node->left = NULL;
	node->right = NULL;
	node->end_of_mask = false;

	return node;
}

struct route_table_entry* search_for_best_entry_in_trie(uint32_t ip_dest, struct trie_node* root)
{
	struct route_table_entry* best_entry = NULL;
	
	// look bit by bit in the trie for the best entry
	for (int i = 31; i >= 0; --i)
	{
		/* evaluate each of the 32 bits in the IP address
		and decide in which subtree we can advance */
		// start with the MSB
		uint32_t current_bit = 1 << i;

		// check if we reached end of the mask and update the best entry
		if (root->end_of_mask)
			best_entry = root->entry;

		// if the current bit is 0 => go left
		// if it is 1 => go right
		if (!(current_bit & ntohl(ip_dest))) {
			/* if we have nowhere to go in the left subtree anymore => 
			we cannot find a more specific prefix => return the last
			best entry that we have found */
			if (!root->left)
				return best_entry;

			// if there is a left neighbour, go deeper in the left subtree
			root = root->left;
		} else {
			/* if we have nowhere to go in the right subtree anymore => 
			we cannot find a more specific prefix => return the last
			best entry that we have found */
			if (!root->right)
				return best_entry;
			// if there is a right neighbour, go deeper in the right subtree
			root = root->right;
		}
	}

	return best_entry;
}

void insert_rtentry_in_trie(struct route_table_entry *entry, struct trie_node* root) {
	uint32_t prefix = ntohl(entry->prefix);
	uint32_t mask = ntohl(entry->mask);
	
	// parse the rtentry bit by bit and build the corresponding path in the trie
	for (int i = 31; i >= 0; --i) {
		uint32_t current_bit = 1 << i;

		// check if the mask has ended
		if (!(current_bit & mask)) {
			root->end_of_mask = true;
			root->entry = entry;
			return;
		}

		// identify the current bit of the prefix: 
		// if it is 1 => go right; if it is 0 => go left
		if (!(current_bit & prefix)) {
			// if there is no left neighbour, create a new node
			if (root->left == NULL)
				root->left = create_node();

			// go deeper in the left subtree
			root = root->left;
		} else {
			// if there is no right neighbour, create a new node
			if (root->right == NULL)
				root->right = create_node();

			// go deeper in the right subtree
			root = root->right;
		}
	}
}

/* function that inserts each rtentry of the rtable in the trie*/
void populate_trie_with_all_rt_entries(struct trie_node* root, struct route_table_entry *rtable, 
										int rtable_len)
{
	for (int i = 0; i < rtable_len; ++i)
		insert_rtentry_in_trie(&rtable[i], root);
}

/* function that creates the root of the trie and then builds the whole trie from
there and populates it with all the the rtentries from the rtable*/
void create_trie_for_rtentries(struct route_table_entry *rtable, int rtable_len, struct trie_node **root)
{
	(*root) = create_node();
	populate_trie_with_all_rt_entries(*root, rtable, rtable_len);
}

/* function that looks in the ARP cache for a specific MAC address corresponding
to the given IP address */
struct arp_table_entry *get_mac_from_arp_cache(uint32_t given_ip)
{
	// parse the ARP cache until finding the given IP address
	for (int i = 0; i < arp_cache_size; ++i) {
		if (given_ip == arp_cache[i].ip)
			return &arp_cache[i];
	}

	return NULL;
}

void swap_uint32s(uint32_t *a, uint32_t *b)
{
	uint32_t aux = *a;
	*a = *b;
	*b = aux;
}

/* function that allocates memory for an ICMP header and populates its fields
according to a flag that indicates the reason why the ICMP packet is sent*/
struct icmphdr *create_ICMP_header(int flag)
{
	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
	DIE(icmp_hdr == NULL, "malloc failed\n");

	switch (flag) {
		case ICMP_ECHO_REQUEST:
			icmp_hdr->type = ICMP_ECHO_REPLY;
			break;
		case ICMP_TIME_EXCEEDED:
			icmp_hdr->type = ICMP_TIME_EXCEEDED;
			icmp_hdr->un.echo.id = 0;
			icmp_hdr->un.echo.sequence = 0;
			break;
		case ICMP_DEST_UNREACHABLE:
			icmp_hdr->type = ICMP_DEST_UNREACHABLE;
			icmp_hdr->un.echo.id = 0;
			icmp_hdr->un.echo.sequence = 0;
			break;
	}

	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
	return icmp_hdr;
}

/* function that interchanges source and destination addreses of MAC format: uint8_t addres[6]*/
void swap_MAC_format_addresses(uint8_t src[6], uint8_t dest[6], int interface)
{
	memcpy(dest, src, 6);
	get_interface_mac(interface, src);
}

/* function that swaps source and destination addreses not only from the ethernet header, but also
from the IP header, which will be the first step when sending an ICMP reply*/
void update_all_addresses_ICMP_response(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int interface)
{
	// update ethernet header by swapping source and destination MAC addresses
	swap_MAC_format_addresses(eth_hdr->ether_shost, eth_hdr->ether_dhost, interface);

	// update IP header by swapping source and destination IP addresses
	swap_uint32s(&ip_hdr->saddr, &ip_hdr->daddr);
}

void send_ICMP_response(int interface, int flag, char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr,
						struct iphdr *ip_hdr)
{
	// swap source and destination addresses in the ethernet header and IP header
	update_all_addresses_ICMP_response(eth_hdr, ip_hdr, interface);

	// update protocol field in IP header
	ip_hdr->protocol = IPPROTO_ICMP;

	// update total length in IP header
	ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;

	// allocate memory for an ICMP header structure and populate its fields
	struct icmphdr *icmp_hdr = create_ICMP_header(flag);

	// add the created ICMP header to the packet, as well as the first 8 bytes of the original payload
	memcpy((char *)ip_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr + sizeof(struct iphdr), 8);
	memcpy((char *)ip_hdr + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));

	send_to_link(interface, buf, ip_hdr->tot_len + sizeof(struct ether_header));
	free(icmp_hdr);
}

// function that returns true if the checksum of the packet is valid and false otherwise
bool is_checksum_valid(struct iphdr *ip_hdr)
{
	/* store the old checksum from the dedicated field of the ip header of the packet
	(the checksum that the packet is supposed to respect) */
	uint16_t old_checksum = ntohs(ip_hdr->check);

	// reinitialize checksum
	ip_hdr->check = 0;

	/* recalculate checksum and compare it to the old one to see if they are equal.
	If they are different, the packet must be thrown away because the actual checksum
	does not respect the expected checksum, so the packet is corrupt */

	uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	if (old_checksum == new_checksum)
		return true;

	return false;
}

/* function that returns false if the TTL has expired and true if the TTL is valid
it also performs other different operations related to TTL */
bool perform_TTL_operations(int interface, char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr,
							struct iphdr *ip_hdr)
{
	// if our TTL is valid, update it, update checksum and then return true
	if (ip_hdr->ttl > 1) {
		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		return true;
	}

	// if we reached this point, it means that ttl expired, so we need to send an ICMP "Time exceeded" response
	send_ICMP_response(interface, ICMP_TIME_EXCEEDED, buf, eth_hdr, ip_hdr);
	return false;
}

// function that returns pointer to a packet that is going to be enqueued because it is waiting for ARP response
struct waiting_for_arp_packet *create_waiting_for_arp_packet(char buf[MAX_PACKET_LEN], int len,
																struct route_table_entry *rtentry)
{
	// allocate memory for the packet
	struct waiting_for_arp_packet *waiting_packet = malloc(sizeof(struct waiting_for_arp_packet));
	DIE(waiting_packet == NULL, "malloc failed\n");

	// populate the fields of the structure
	memcpy(waiting_packet->buf, buf, len);
	waiting_packet->len = len;
	waiting_packet->best_route_interface = rtentry->interface;
	waiting_packet->next_hop_IP_address = rtentry->next_hop;

	return waiting_packet;
}

/* function that builds the ethernet header that will
be placed in the ARP request packet and returns pointer to it*/
struct ether_header* create_ethernet_header_for_ARP(struct route_table_entry *best_route)
{
	// allocate memory for the ethernet header
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "malloc failed\n");

	// populate the fields of the ethernet header

	// set the destination MAC address to broadcast
	for (int i = 0; i < 6; ++i)
		eth_hdr->ether_dhost[i] = 255;

	// set the source MAC address to the MAC address of the interface
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);

	// set the ethernet type to ARP
	eth_hdr->ether_type = htons(ARP_ETHERTYPE);

	return eth_hdr;
}

/* function dedicated to seting all addresses for the arp request */
void set_addresses_ARP_header(struct arp_header *arp_hdr, struct ether_header* eth_hdr,
								struct route_table_entry *best_route)
{
	// set the sender hardware address to the MAC address of the interface
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));

	// set the sender IP address to the IP address of the interface
	arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));

	// set the target IP address to the next hop IP address
	arp_hdr->tpa = best_route->next_hop;
}

/* function that builds the ARP header for the ARP request
packet and returns pointer to it*/
struct arp_header* create_ARP_header(struct route_table_entry *best_route,
										struct ether_header* eth_hdr)
{
	// allocate memory for the ARP header
	struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
	DIE(arp_hdr == NULL, "malloc failed\n");

	// populate the fields of the ARP header

	// set the format of hardware address to Ethernet
	arp_hdr->htype = htons(1);

	// set the format of protocol address to IPv4
	arp_hdr->ptype = htons(IP_ETHERTYPE);

	// set the hardware address length to 6
	arp_hdr->hlen = 6;

	// set the protocol address length to 4
	arp_hdr->plen = 4;

	// this header is for an ARP REQUEST => set the opcode to 1
	arp_hdr->op = htons(1);

	set_addresses_ARP_header(arp_hdr, eth_hdr, best_route);

	return arp_hdr;
}

/* function that allocates memory for an ARP request packet,
populates its fields and then returns pointer to it*/
char *create_ARP_request_packet(struct route_table_entry *best_route)
{
	char *ARP_packet = malloc(MAX_PACKET_LEN);
	DIE(ARP_packet == NULL, "malloc failed\n");

	// create the ethernet header and integrate it into the ARP packet
	struct ether_header* eth_hdr = create_ethernet_header_for_ARP(best_route);
	memcpy(ARP_packet, eth_hdr, sizeof(struct ether_header));

	// create the ARP header and add it to the ARP packet right after the ethernet header
	struct arp_header* arp_hdr = create_ARP_header(best_route, eth_hdr);
	memcpy(ARP_packet + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
	
	// free the memory allocated to the headers after integrating them into the ARP packet
	free(eth_hdr);
	free(arp_hdr);

	return ARP_packet;
}

/* function that makes sure to update the queue of packets that are waiting
for an arp reply by adding the current packet and then actually sends the arp request */
void prepare_ARP_request(struct route_table_entry *best_route, char buf[MAX_PACKET_LEN], size_t len)
{
	// save packet for later (keep packet in a queue and send it after receiving ARP reply)
	struct waiting_for_arp_packet *waiting_packet = create_waiting_for_arp_packet(buf, len, best_route);

	// enqueue the packet
	queue_enq(arp_waiting_queue, waiting_packet);
	arp_waiting_queue_size++;

	// generate ARP request and send it
	send_to_link(best_route->interface, create_ARP_request_packet(best_route),
					sizeof(struct ether_header) + sizeof(struct arp_header));

}

/* function whose purpose is to find the MAC address corresponding to the next hop ip address
and update the ethernet header of the packet

it returns true if the MAC address has been updated successfully, meaning that the MAC could be found in the ARP cache,
otherwise it returns false (the MAC could not be found in the ARP cache, so an ARP request was sent,
but the ethernet header has not been updated)*/
bool could_update_MAC_in_ethernet_header(struct route_table_entry *best_route, char buf[MAX_PACKET_LEN], 
											struct ether_header *eth_hdr, struct iphdr *ip_hdr, size_t len)
{
	// look for the ip address in the ARP cache
	struct arp_table_entry *dest_mac = get_mac_from_arp_cache(best_route->next_hop);

	// if we could not find the ip address in the ARP cache, we need to send an ARP request
	if (!dest_mac) {
		prepare_ARP_request(best_route, buf, len);
		return false;
	}

	// update the MAC address in the ethernet header
	memcpy(eth_hdr->ether_dhost, dest_mac->mac, sizeof(eth_hdr->ether_dhost));
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);

	return true;
}

/* function that returns false if the destination of the packet could not be found
and true if the addresses have been updated successfully */
bool is_destination_reachable(char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr, struct iphdr *ip_hdr,
								size_t len, struct trie_node *root, int interface)
{
	// Search for the best route to the IP destination in the route table
	struct route_table_entry *best_route = search_for_best_entry_in_trie(ip_hdr->daddr, root);
	if (!best_route) {
			/* the destination could not be found in the route table
			=> we need to send ICMP response "Destination unreachable" */
			send_ICMP_response(interface, ICMP_DEST_UNREACHABLE, buf, eth_hdr, ip_hdr);
			return false;
		}

	/* if we are here, it means that we could find the corresponding entry for our
	destination in the route table, so we need to update addresses */
	if (could_update_MAC_in_ethernet_header(best_route, buf, eth_hdr, ip_hdr, len) == false)
		return false;
	
	/* if we reached this point, it means that we have updated the MAC address
	in the ethernet header, so the packet is ready to be sent to its next hop */
	send_to_link(best_route->interface, buf, len);
	return true;
}

void IP_packet_redirection(char buf[MAX_PACKET_LEN], struct iphdr *ip_hdr, struct ether_header *eth_hdr,
							size_t len, struct trie_node *root, int interface)
{
	if (is_checksum_valid(ip_hdr) == false)
		return; // drop packet

	if (perform_TTL_operations(interface, buf, eth_hdr, ip_hdr) == false)
		return; // drop packet

	if (is_destination_reachable(buf, eth_hdr, ip_hdr, len, root, interface) == false)
		return; // drop packet
}

void handle_IP_packet(char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr, struct iphdr *ip_hdr, int interface,
						size_t len, struct trie_node *root)
{
	/* check if the final destination is the router itself, meaning that
	the packet is an "Echo request" packet */

	uint32_t ip_addr = inet_addr(get_interface_ip(interface));
	if (ip_addr != ip_hdr->daddr)
		// the router must redirect packet
		IP_packet_redirection(buf, ip_hdr, eth_hdr, len, root, interface);
	else
		// send ICMP response (echo reply)
		// the router itself was the final destination
		send_ICMP_response(interface, ICMP_ECHO_REQUEST, buf, eth_hdr, ip_hdr);
}

/* when transforming an ARP request packet into an an ARP reply, the first step
is to interchange all the source and the destination addresses (not only in the
ethernet header, but also in the arp_header) and this is exactly what this function is doing*/
void update_all_addresses_ARP_reply(struct ether_header *eth_hdr, struct arp_header *arp_hdr,int interface)
{
	/* swap the source and the destination MAC addresses from the ethernet header;
	the ethertype remains the same, the response packet will still be an ARP packet */
	swap_MAC_format_addresses(eth_hdr->ether_shost, eth_hdr->ether_dhost, interface);
	
	// interchange the source and the destination IP addresses from the ARP header
	// we need to swap some copies of the addresses in order to preserve the alignment
	uint32_t spa_aligned = arp_hdr->spa;
	uint32_t tpa_aligned = arp_hdr->tpa;

	swap_uint32s(&spa_aligned, &tpa_aligned);

	arp_hdr->spa = spa_aligned;
	arp_hdr->tpa = tpa_aligned;

	// interchange the source and the destination hardware addresses from the ARP header
	swap_MAC_format_addresses(arp_hdr->sha, arp_hdr->tha, interface);
}

// function that sends back an ARP reply to the sender of the ARP request
void respond_to_ARP_request(char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr, struct arp_header *arp_hdr,
							int interface, size_t len)
{
	// modify the fields of the packet so as to send back the packet as an ARP reply

	// swap all source and destination addresses
	update_all_addresses_ARP_reply(eth_hdr, arp_hdr, interface);

	// this packet is an ARP reply => set the opcode to 2
	arp_hdr->op = htons(2);

	// send the packet
	send_to_link(interface, buf, len);
}

void add_new_entry_in_ARP_cache(struct arp_header *arp_hdr)
{
	// check if we still have space in the arp cache; if not, we need to reallocate
	if (arp_cache_size == ARP_CACHE_CAPACITY) {
		// realloc ARP cache
		arp_cache = realloc(arp_cache, (arp_cache_size + 1) * sizeof(struct arp_table_entry));
		DIE(arp_cache == NULL, "realloc failed\n");
	}

	arp_cache[arp_cache_size].ip = arp_hdr->spa;
	memcpy(arp_cache[arp_cache_size].mac, arp_hdr->sha, sizeof(arp_hdr->sha));
	arp_cache_size++;
}

/* function that returns true if the waiting packet received as parameter needs to be sent
(its MAC dest is now available in the ARP cache) or false if the packet needs to be enqued again */
bool needs_to_be_sent(struct waiting_for_arp_packet* packet, struct ether_header *eth_hdr)
{
	// look for the packet's next hop destination IP address in the ARP cache
	for (int k = 0; k < arp_cache_size; ++k) {
		if (packet->next_hop_IP_address == arp_cache[k].ip) {
			// update the MAC destination in the ethernet header of the packet
			memcpy(eth_hdr->ether_dhost, arp_cache[k].mac, sizeof(eth_hdr->ether_dhost));
			return true;
		}
	}

	/* if we reached this point, it means that the MAC destination
	is not available in the ARP cache, so the packet cannot be sent */
	return false;
}

/* function that parses the waiting queue and sends the packets whose MAC destination is
now available in the ARP cache because the ARP request has received a reply */
void send_waiting_packets()
{
	for (int i = 0; i < arp_waiting_queue_size; ++i) {
		struct waiting_for_arp_packet* packet;
		packet = (struct waiting_for_arp_packet*) queue_deq(arp_waiting_queue);
		arp_waiting_queue_size--;
		struct ether_header *eth_hdr = (struct ether_header*) packet->buf;

		if (needs_to_be_sent(packet, eth_hdr) == true) {
			send_to_link(packet->best_route_interface, packet->buf, packet->len);
			free(packet);
		} else {
			queue_enq(arp_waiting_queue, packet);
			arp_waiting_queue_size++;
		}
	}
}

void handle_ARP_reply(char buf[MAX_PACKET_LEN], struct arp_header *arp_hdr)
{	
	// update the ARP cache by adding a new corresponding entry
	add_new_entry_in_ARP_cache(arp_hdr);

	/* parse the queue of packets that are waiting for ARP replies and send the
	ones that have now the destination MAC written in the ARP cache */
	send_waiting_packets();
}

/* function that identifies which type of ARP packet (request or reply) we are currently handling
and calls the corresponding function according to this*/
void handle_ARP_packet(char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr, struct arp_header *arp_hdr, size_t len, int interface)
{
	// check if the current packet is an arp request or reply
	if (ntohs(arp_hdr->op) == 2)
		// we are handling an ARP reply
		handle_ARP_reply(buf, arp_hdr);
	else
		// we are handling an ARP request
		respond_to_ARP_request(buf, eth_hdr, arp_hdr, interface, len);
}

/* function that identifies which type of packet we are handling (IPv4 or ARP) and calls
the specific handling function accordingly*/
void handle_packet_according_to_ethertype(char buf[MAX_PACKET_LEN], struct ether_header *eth_hdr, int interface, size_t len, struct trie_node *root)
{
	if (ntohs(eth_hdr->ether_type) == IP_ETHERTYPE) {
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		handle_IP_packet(buf, eth_hdr, ip_hdr, interface, len, root);
	} else {
		struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
		handle_ARP_packet(buf, eth_hdr, arp_hdr, len, interface);
	}
}

/* function that frees the memory that had been allocated
for all the nodes in the trie*/
void free_trie(struct trie_node* root) {
    if (root == NULL) {
        return;
    }
    
    // free the left subtree recursively
    free_trie(root->left);
    
    // free the right subtree recursively
    free_trie(root->right);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	int rtable_len = read_rtable(argv[1], rtable);
	struct trie_node *root = NULL;
	create_trie_for_rtentries(rtable, rtable_len, &root);

	arp_cache = malloc(sizeof(struct arp_table_entry) * ARP_CACHE_CAPACITY);
	DIE(arp_cache == NULL, "malloc failed\n");

	arp_waiting_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		uint16_t ether_type = ntohs(eth_hdr->ether_type);

		// we are going to ignore all the packets that are not IPv4 or ARP
		if (ether_type != IP_ETHERTYPE && ether_type != ARP_ETHERTYPE)
			continue;

		handle_packet_according_to_ethertype(buf, eth_hdr, interface, len, root);
	}

	free(arp_cache);
	free(rtable);

	free_trie(root);
	free(root);
}
