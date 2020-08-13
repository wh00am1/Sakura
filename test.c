#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func(int *num){
	for(int i = 0; i < num; i++){
		num += i;
	}
	char *name = "BALABALABALA";
	char *sponebob = "I love Patric";
	printf("%d\n", num);
	puts(name);
	puts(sponebob);
}

int main(int argc, char const *argv[])
{
	int q = 100;
	func(q);
	puts("[BALABALA] done calling the useless function 'func'. (XD)");
	return 0;
}