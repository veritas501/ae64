#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <ctype.h>
typedef void (*func)(void *,void *);


//amd64
const char sc_start[] = "\x48\x89\xfc\x48\x89\xf0\x48\x31\xdb\x48\x31\xc9"
                        "\x48\x31\xd2\x48\x31\xff\x48\x31\xf6\x4d\x31\xc0"
                        "\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4"
                        "\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff\x48\x31\xed";

void check_sc(char *s){
    int len = strlen(s);
    for(int i=0;i<len;i++){
        if(!isalnum(s[i])){
            puts("Sorry i dont understand :(");
            exit(4);
        }
    }
}

int main(void){
    setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);

    int fd = open("/dev/urandom",0);
    if(fd<0){
		printf("Open urandom error!!\n");
		exit(1);
	}
	void * rwx_addr;
    void * rw_addr;
	if(read(fd,&rwx_addr,sizeof(void *)) == -1){
		printf("Read urandom error!!\n");
		exit(2);
	}
    if(read(fd,&rw_addr,sizeof(void *)) == -1){
		printf("Read urandom error!!\n");
		exit(2);
	}
	rwx_addr = (void *)(((size_t)(rwx_addr)&~0xfff)%0x133700000000);
    rw_addr = (void *)(((size_t)(rw_addr)&~0xfff)%0x133700000000);
	void * rwx_page = mmap(rwx_addr,0x1000,7,34,-1,0);
    void * rw_page = mmap(rw_addr,0x1000,3,34,-1,0);
	if((rwx_page != rwx_addr) || (rw_page != rw_addr)){
		printf("mmap error!!\n");
		exit(3);
	}

    int sc_start_len = strlen(sc_start);
    strcpy(rwx_addr,sc_start);

    char buffer[0x1000];
    memset(buffer,0,0x1000);
    int n = read(0,buffer,0x1000-sc_start_len);
    if(buffer[n-1] == '\n'){
        buffer[n-1]=0;
    }
    check_sc(buffer);
    strncpy(rwx_addr+sc_start_len,buffer,0x1000-sc_start_len);

    ((func)rwx_addr)(rw_addr+0x800,rwx_addr);
    return 0;
}