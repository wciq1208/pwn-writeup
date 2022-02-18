#include <stdlib.h>
#include <stdio.h>


unsigned int hash(int in) {
    int i;
    int v2[8];
    for (i = 0; i <= 7; ++i){
        v2[i] = rand();
    }
    /*printf("0x%08x\n", v2[1]);
    printf("0x%08x\n", v2[2]);
    printf("0x%08x\n", v2[3]);
    printf("0x%08x\n", v2[4]);
    printf("0x%08x\n", v2[5]);
    printf("0x%08x\n", v2[6]);
    printf("0x%08x\n", v2[7]);
    int sum = v2[4] - v2[6] + v2[7] + in + v2[2] - v2[3] + v2[1] + v2[5];
    */
    int out = in - v2[4] + v2[6] - v2[7] - v2[2] + v2[3] - v2[1] - v2[5];
    printf("%u\n", out);
    return out;
}

int main(int argc, const char *argv[]) {
    unsigned int v3;
    v3 = time(0);
    srand(v3);
    int in = atoi(argv[1]);
    unsigned int res = hash(in);
    //printf("%x\n", res);
    return 0;
}
