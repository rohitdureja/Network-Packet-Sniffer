#ifndef DATALIST_H
#define DATALIST_H

#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

typedef u_int tcp_seq;
/* Data structure to hold packet information */
struct packet_data {
	struct in_addr ip_src;
	struct in_addr ip_dst;
	u_short th_sport;
	u_short th_dport;
	u_char th_flags;
	unsigned int payload_size;
	tcp_seq th_seq;
	tcp_seq th_ack;
};

/* list structure to hold connection information */
struct connection_list {
	unsigned int connection_id;
	struct in_addr ip_initiator;
	struct in_addr ip_responder;
	u_short port_initiator;
	u_short port_responder;
	unsigned long num_packets_initiator_to_responder;
	unsigned long num_packets_responder_to_initiator;
	unsigned long num_bytes_initiator_to_responder;
	unsigned long num_bytes_responder_to_initiator;

	// seq and ack numbers of last recorded packet of initiator and responder
	tcp_seq last_seq_initiator;
	tcp_seq last_seq_responder;
	tcp_seq last_ack_initiator;
	tcp_seq last_ack_responder;
	unsigned int termination_status;
	unsigned int connection_state;
	unsigned int syn_ack_status;
	struct packet_data packet_data;
	struct connection_list *next_connection;
	unsigned int duplicates_initiator;
	unsigned int duplicates_responder;

};

/* add connection data to the list */
int add_packet_to_connection_list(struct connection_list **list, struct packet_data data);

/* search active connection in the list and return position if found otherwise -1 */
int search_active_connection(struct connection_list ***list, struct packet_data data);

/* print the list */
void print_connection_list(struct connection_list **list);

void print_payload_content(struct connection_list **list, struct packet_data data, const u_char* payload);

#endif

