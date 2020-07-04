#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
typedef void (*func)(void);

int main(void){
	setvbuf(stdout, NULL, _IONBF, 0);
	char tmp;
	int re;
	char * p = (char *)malloc(0x1000);
	printf("> ");

	for(int i = 0; i < 0x1000; i++){
		re = read(0, &tmp, 1);
		if(re == -1) {
			exit(0);
		}
		if(isalnum(tmp)) {
			*(p+i) = tmp;
		} else {
			break;
		}
	}

	if(mprotect((void *)((int)p&~0xfff),0x1000,7) != -1){
		puts("exec shellcode...");
		((func)p)();
	}else{
		puts("error ,tell admin");
	}

	return 0;
}


