// gcc -O2 -o tools/gen_obf_k2 tools/gen_obf_k2.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int hex32(const char *h, uint8_t out[32]) {
    if (!h || strlen(h)!=64) return 0;
    for (int i=0;i<32;i++){
        unsigned x;
        if (sscanf(h+2*i,"%02x",&x)!=1) return 0;
        out[i]=(uint8_t)x;
    }
    return 1;
}

static int parse_dice5(const char *s, uint8_t d[5]) {
    if (!s || strlen(s)!=5) return 0;
    for (int i=0;i<5;i++){
        if (s[i]<'1'||s[i]>'6') return 0;
        d[i]=(uint8_t)(s[i]-'0');
    }
    return 1;
}

int main(int argc, char**argv){
    if (argc!=3){
        fprintf(stderr,"usage: %s <K2_HEX> <dice(5 digits)>\n", argv[0]);
        return 1;
    }

    uint8_t K2[32], d[5];
    if(!hex32(argv[1],K2)||!parse_dice5(argv[2],d)){
        fprintf(stderr,"bad args\n");
        return 1;
    }

    uint8_t OBF[32];
    for (int i=0;i<32;i++){
        uint8_t k = K2[i];
        k = (uint8_t)((k - d[4]) & 0xFF); // inverse of +d5
        k = (uint8_t)(k ^ d[3]);          // inverse of ^d4
        k = (uint8_t)((k + d[2]) & 0xFF); // inverse of -d3
        k = (uint8_t)(k ^ d[1]);          // inverse of ^d2
        k = (uint8_t)((k - d[0]) & 0xFF); // inverse of +d1
        OBF[i] = k;
    }

    printf("#pragma once\nstatic const unsigned char OBF_K2[32]={");
    for(int i=0;i<32;i++) printf("0x%02x%s", OBF[i], i==31? "": ",");
    printf("};\n");
    return 0;
}
