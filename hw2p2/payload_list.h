#include <stdio.h>
#include <stdlib.h>

struct payload_list {
	char * payload_content;
	struct payload_list * next_payload;
};

/* add payload to the list */
int add_payload(struct payload_list **list, const char * payload);

/* print payload*/
void print_payload_list(const char* file_name, struct payload_list *list);