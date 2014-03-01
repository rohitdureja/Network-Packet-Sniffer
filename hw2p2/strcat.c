#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct Datastring {
	char *string;
};
int main()
{
	struct Datastring *data;
	//data = malloc(sizeof(Datastring *));
	char str[20];
	printf("Enter string 1: ");
	scanf("%s", str);
	data->string = strdup(str);
	//str=strdup(str1);
	printf("Enter string 2: ");
	scanf("%s", str);
	data->string = realloc(data->string, strlen(str));
	strcat(data->string, str);
	printf("%s\n", data->string);

}