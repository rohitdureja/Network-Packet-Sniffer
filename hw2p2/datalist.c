#include "datalist.h"
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

int unique_id = 1;

int add_packet_to_connection_list(struct connection_list **list, struct packet_data data)
{
	struct connection_list *current, *newnode;
	int connection_exists;
	int direction;
	in_addr_t ipinitiator;
	in_addr_t ipsrc;
	in_addr_t ipdst;
	int duplicate;
	current = *list;
	int i;
	if(*list == NULL) /*first connection in the list */
	{
		newnode = (struct connection_list *)malloc(sizeof(struct connection_list));
		if(newnode == NULL) {
			printf("Can't create new node!");
			return 1;
		}
		/* put packet data into connection list node */
		newnode->packet_data.ip_src = data.ip_src;
		newnode->packet_data.ip_dst = data.ip_dst;
		newnode->packet_data.th_sport = data.th_sport;
		newnode->port_initiator = data.th_sport;
		newnode->port_responder = data.th_dport;
		newnode->packet_data.th_dport = data.th_dport;
		newnode->packet_data.th_flags = data.th_flags;
		newnode->packet_data.payload_size = data.payload_size;
		newnode->num_packets_initiator_to_responder = 1;
		newnode->num_packets_responder_to_initiator = 0;
		newnode->num_bytes_initiator_to_responder = data.payload_size;
		newnode->num_bytes_responder_to_initiator = 0;
		newnode->sequence_initiator_to_responder = data.th_seq + data.payload_size;
		newnode->sequence_responder_to_initiator = 0;
		newnode->duplicate_initiator_to_responder = 0;
		newnode->duplicate_responder_to_initiator = 0;
		newnode->connection_id = 0;
		newnode->ip_initiator = data.ip_src;
		newnode->ip_responder = data.ip_dst;
		newnode->connection_state = 0;
		newnode->termination_status = 0;
		newnode->syn_ack_status = 0;
		newnode-> next_connection = NULL;
		*list = newnode;
		duplicate = 0;
	}
	else
	{
		connection_exists = search_active_connection(&list, data);
		if(connection_exists!=-1) {
			/* connection already exists */
			for(i = 0 ; i < connection_exists ; i++) {
				current = current -> next_connection;
			}
			if(current->connection_state == 0)
			{
				if((data.th_flags & TH_SYN) && (data.th_flags & TH_ACK))
				{
					current->syn_ack_status = 1;
				}
			}
			if(current->syn_ack_status == 1)
			{
				if((data.th_flags & TH_ACK) && !(data.th_flags & TH_SYN))
				{
					current->connection_state = 1;
					current->syn_ack_status = 0;
					
					current->connection_id = unique_id;
					unique_id ++;
				}
			}
			if(data.th_flags & TH_FIN || data.th_flags & TH_RST)
			{
				current->termination_status = 1;
			}


			ipinitiator = inet_addr(inet_ntoa(current->ip_initiator));
			ipsrc = inet_addr(inet_ntoa(data.ip_src));
			ipdst = inet_addr(inet_ntoa(data.ip_dst));

			if(ipinitiator == ipsrc) {
				/* check for duplicates */
				if(data.th_seq < current->sequence_initiator_to_responder) {
					current->duplicate_initiator_to_responder++;
					duplicate = 1;
				}
				else {
					current->sequence_initiator_to_responder = data.th_seq + data.payload_size;
					duplicate = 0;
				}
				
				current->num_bytes_initiator_to_responder += data.payload_size;
				current->num_packets_initiator_to_responder += 1;
			}

			else if(ipinitiator == ipdst) {
				/* check for duplicates */
				if(data.th_seq < current->sequence_responder_to_initiator) {
					current->duplicate_responder_to_initiator++;
					duplicate = 1;
				}
				else {
					current->sequence_responder_to_initiator = data.th_seq + data.payload_size;
					duplicate = 0;
				}

				current->num_bytes_responder_to_initiator += data.payload_size;
				current->num_packets_responder_to_initiator += 1;
			}
		}
		else {
			while(current -> next_connection != NULL)
				current = current -> next_connection;
			newnode = (struct connection_list *)malloc(sizeof(struct connection_list));
			if(newnode == NULL) {
				printf("Can't create new node!");
				return 1;
			}
			/* connection doesn't exist. add new connection data */
			newnode->packet_data.ip_src = data.ip_src;
			newnode->packet_data.ip_dst = data.ip_dst;
			newnode->packet_data.th_sport = data.th_sport;
			newnode->packet_data.th_dport = data.th_dport;
			newnode->port_initiator = data.th_sport;
			newnode->port_responder = data.th_dport;
			newnode->packet_data.th_flags = data.th_flags;
			newnode->num_packets_initiator_to_responder = 1;
			newnode->num_packets_responder_to_initiator = 0;
			newnode->packet_data.payload_size = data.payload_size;
			newnode->num_bytes_initiator_to_responder = data.payload_size;
			newnode->sequence_initiator_to_responder = data.th_seq + data.payload_size;
			newnode->sequence_responder_to_initiator = 0;
			newnode->num_bytes_responder_to_initiator = 0;
			newnode->duplicate_initiator_to_responder = 0;
			newnode->duplicate_responder_to_initiator = 0;
			newnode->connection_id = 0;
			newnode->ip_initiator = data.ip_src;
			newnode->ip_responder = data.ip_dst;
			newnode->connection_state = 0;
			newnode->termination_status = 0;
			newnode -> next_connection = NULL;
			current -> next_connection = newnode;
			duplicate = 0;
		}
	}
	return duplicate;
}

int search_active_connection(struct connection_list ***list, struct packet_data data)
{
	struct connection_list *current;
	int pos = 0;
	int flag = 0;
	current = **list;
	in_addr_t ipinitiator;
	in_addr_t ipresponder;
	in_addr_t ipsrc;
	in_addr_t ipdst;
	while(current != NULL)
	{
	    ipinitiator = inet_addr(inet_ntoa(current->ip_initiator));
	    ipresponder = inet_addr(inet_ntoa(current->ip_responder));
	    ipsrc = inet_addr(inet_ntoa(current->packet_data.ip_src));
	    ipdst = inet_addr(inet_ntoa(current->packet_data.ip_dst));

	    if(ipinitiator == ipsrc || ipinitiator == ipdst)
	    {
	    	if(ipresponder == ipsrc || ipresponder == ipdst)
	    	{
	    		if((current->port_initiator==data.th_sport) | (current->port_initiator==data.th_dport))
				{
					if((current->port_responder==data.th_sport) | (current->port_responder==data.th_dport))
						flag = 1;
				}
			}
		}
		if(flag==1){
			return pos;
		}
		else {
		}
		current = current -> next_connection;
		pos = pos + 1;
	}
	return (int)-1;
}



/*
 * print packet payload data (avoid printing binary data)
 */
void
write_to_file( char* file_name, const char *payload, int size_payload)
{
	FILE *fp2;
	int i;
	fp2 = fopen(file_name, "a+");
	for(i = 0 ; i < size_payload ; i++)
		fprintf(fp2, "%c", payload[i]);
	fclose(fp2);
	return;
}


void print_payload_content(struct connection_list **list, struct packet_data data, 
	 const char* payload, int size_payload) {
	struct connection_list * current = *list;
	int connection_exists = search_active_connection(&list, data);
	
	if(connection_exists!=-1) {
		/* connection already exists */
		int i;
		for(i = 0 ; i < connection_exists ; i++) {
			current = current -> next_connection;
		}
		/*if (current->connection_state != 1 || !(data.th_flags & TH_ACK)){
			return;*/
		in_addr_t ipinitiator = inet_addr(inet_ntoa(current->ip_initiator));
		in_addr_t ipsrc = inet_addr(inet_ntoa(data.ip_src));
		in_addr_t ipdst = inet_addr(inet_ntoa(data.ip_dst));
		char filename[50];
		if(ipinitiator == ipsrc){
		    sprintf(filename, "%d.initiator", current->connection_id);
		}
		else if(ipinitiator == ipdst){
		    sprintf(filename, "%d.responder", current->connection_id);
		}
		write_to_file(filename, payload, size_payload);
	}
}

void print_connection_list(struct connection_list **list)
{
	int connection_number = 1;
	char filename[50];
	FILE *fp;
	if(*list == NULL) {
		printf("No active connections!");
	}
	else {
		struct connection_list *current;
		current = *list;
		while(current != NULL) {
			if(current -> connection_state == 1)
			{
				sprintf(filename, "%d.meta", connection_number);
				fp = fopen(filename, "w+");
				fprintf(fp, "%s %s \n%d %d \n%ld %ld \n%ld %ld \n%d %d\n%d \n", inet_ntoa(current->ip_initiator), inet_ntoa(current->ip_responder),
					ntohs(current->port_initiator), ntohs(current->port_responder),
					current->num_packets_initiator_to_responder, current->num_packets_responder_to_initiator,
					current->num_bytes_initiator_to_responder, current->num_bytes_responder_to_initiator,
					current->duplicate_initiator_to_responder, current->duplicate_responder_to_initiator, current->termination_status);
				fclose(fp);
				printf("Connection number : %d\n", connection_number);
				printf("%s ", inet_ntoa(current->ip_initiator));
				printf("%s \n", inet_ntoa(current->ip_responder));
				printf("%d ", ntohs(current->port_initiator));
				printf("%d \n", ntohs(current->port_responder));
				printf("%ld ", current->num_packets_initiator_to_responder);
				printf("%ld \n", current->num_packets_responder_to_initiator);
				printf("%ld ", current->num_bytes_initiator_to_responder);
				printf("%ld \n", current->num_bytes_responder_to_initiator);
				printf("%d ", current->duplicate_initiator_to_responder);
				printf("%d\n", current->duplicate_responder_to_initiator);
				printf("%d \n", current->termination_status);
				connection_number ++;
			}
			current = current -> next_connection;
			
		}
	}
}

