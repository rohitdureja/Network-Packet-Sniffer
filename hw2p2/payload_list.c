#include "payload_list.h"

int add_payload(struct payload_list **list, const char * payload){
	struct payload_list *current, *newnode;
	newnode = (struct payload_list *)malloc(sizeof(struct payload_list));
	current = *list;
	if(newnode == NULL) {
		printf("Can't create new node!");
		return 1;
	}
	//memset(newnode->payload_content, '\0', sizeof(newnode->payload_content));
	//strcpy(newnode->payload_content,payload);
	newnode->next_payload = NULL;
    //First element	
	if(*list == NULL){
		*list = newnode;
		return 0;
	}
	
	//Not the first element
	while((current->next_payload)!=NULL){
		current = current -> next_payload;
	}
	current -> next_payload = newnode;
	//printf("Added\n%s\n",newnode->payload_content);
	return 0;
}

void print_payload_list(const char* file_name, struct payload_list *list){
    printf("Payload for %s:\n",file_name);
	struct payload_list * current = list;
	while(current != NULL){
		printf("P:%s\n",current->payload_content);
		current = current -> next_payload;
	}
}