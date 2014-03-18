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
	unsigned int duplicate_initiator_to_responder;
	unsigned int duplicate_responder_to_initiator;
	unsigned int termination_status;
	unsigned int connection_state;
	unsigned int syn_ack_status;
	struct packet_data packet_data;
	struct connection_list *next_connection;
	tcp_seq sequence_initiator_to_responder;
	tcp_seq sequence_responder_to_initiator;
	char date[100];
	char sender[100];
	char receiver[100];
	unsigned int accept;

	// keeps track of what we have already printed
	unsigned int status;

};

/* add connection data to the list */
int add_packet_to_connection_list(struct connection_list **list, struct packet_data data);

/* search active connection in the list and return position if found otherwise -1 */
int search_active_connection(struct connection_list ***list, struct packet_data data);

/* print the list */
void print_connection_list(struct connection_list **list);

/* prints payload */
void print_payload_content(struct connection_list **list, struct packet_data data, const char* payload, int size_payload);

void parse_email_traffic(struct connection_list **list, const char* payload, int size_payload, struct packet_data data);

#endif

