#ifndef HASH_TABLE_INCLUDE
#define HASH_TABLE_INCLUDE
/* Data structure to store list information */
typedef struct _list_t_ {
	struct in_addr 
	char *str;
	char *string;
	struct _list_t_ *next;
} dataList;


/* Data structure to store hash table */
typedef struct _hashTable {
	int size;
	dataList **table;
} hashTable;

/* Function to create the hashtable */
hashTable *createHashTable(int size);

/* Function to find the hash for given input data */
unsigned int hash(hashTable *hashtable, dataList *data);

/* Function to lookup data */
dataList *lookupData(hashTable *hashtable, dataList *data);

/*Function to add data to the hash table */
int addData(hashTable *hashtable, dataList *data);

/*Function to free up memory used by the hasbtable */
void freeHashTable(hashTable *hashtable);

#endif
