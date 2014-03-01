#include<stdio.h>
#include "hashtable.h"

int main() {
	dataList *data;
	char *str="Rohit is the boss";
	char *string = "Rohit";
	data->str = str; 
	data->string = string;
	hashTable *my_hash_table;
	int size_of_table = 12;
	my_hash_table = createHashTable(size_of_table);
	dataList *temp;

	//char *string = "Fuck everyone else";
	addData(my_hash_table, data);
	string = "Dureja";
	data->string = string;
	addData(my_hash_table, data);
	temp = lookupData(my_hash_table, data);
		printf("%s\n",temp->string);

	return 0;
}