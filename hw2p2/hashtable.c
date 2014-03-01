#include <stdlib.h>
#include <string.h>
#include "hashtable.h"
#include <stdio.h>

/*Function to create the hashtable*/
extern hashTable *createHashTable(int size) {
	hashTable *new_table;
	if(size<1) /* invalid size for table */
		return NULL;
	/* allocate memory to the table structure */
	if((new_table = malloc(sizeof(hashTable))) == NULL) {
		return NULL;
	}
	/* allocate memory for the table data */
	if((new_table->table = malloc(sizeof(dataList *)*size)) == NULL) {
		return NULL;
	}
	/* initialize elements of the table */
	for(int i = 0; i<size;i++)
		new_table->table[i] = NULL;
	/* set the table's size */
	new_table->size = size;
	return new_table;
}

extern unsigned int hash(hashTable *hashtable, dataList *data) {
	//printf("%s\n",data->str);
	unsigned int hashval;
	char *str = data->str;
	hashval = 0;
	for(; *str != '\0'; str++) 
		hashval = *str + (hashval << 5) - hashval;
	return hashval % hashtable->size;
}

extern dataList *lookupData(hashTable *hashtable, dataList *data) {
	dataList *list;
	unsigned int hashval = hash(hashtable, data);
	/* Go to the correct list based on the hash value and see if str is
     * in the list.  If it is, return return a pointer to the list element.
     * If it isn't, the item isn't in the table, so return NULL.
     */
	for(list = hashtable->table[hashval];list!=NULL;list=list->next) {
		if(strcmp(data->str, list->str)==0)
			return list;
	}
	return NULL;
}

extern int addData(hashTable *hashtable, dataList *data) {
	//printf("%s\n",data->str);
	dataList *new_list;
	dataList *current_list;
	unsigned int hashval = hash(hashtable, data);
	/* attempt to allocate memory for the list */
	if((new_list = malloc(sizeof(dataList)))==NULL) {
		return 1;
	}
	/* Does item already exist? */
	current_list = lookupData(hashtable, data);
	/* item already exists, don't insert it again. */
	if (current_list != NULL) {
		current_list->string = realloc(current_list->string, strlen(data->string));
		strcat(current_list->string, data->string);
		return 2;
	} 

	/* Insert into list */
	new_list->str = strdup(data->str);
	new_list->string = strdup(data->string);
    new_list->next = hashtable->table[hashval];
    hashtable->table[hashval] = new_list;
    return 0;
}

extern void freeHashTable(hashTable *hashtable)
{
    int i;
    dataList *list, *temp;
    if (hashtable==NULL) 
    	return;
    /* Free the memory for every item in the table, including the 
     * strings themselves.
     */
    for(i=0; i<hashtable->size; i++) {
        list = hashtable->table[i];
        while(list!=NULL) {
            temp = list;
            list = list->next;
            free(temp->str);
            free(temp);
        }
    }
    /* Free the table itself */
    free(hashtable->table);
    free(hashtable);
}
