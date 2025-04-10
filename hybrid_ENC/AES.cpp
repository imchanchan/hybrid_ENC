﻿#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "header.h"
#define _CRT_SECURE_NO_WARNIGNS

//using namespace std;

const byte SBox[256] = {
   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

const word rCon[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

word Subword(word x) {
    word x1 = SBox[(x >> 24) & 0xff] << 24;
    word x2 = SBox[(x >> 16) & 0xff] << 16;
    word x3 = SBox[(x >> 8) & 0xff] << 8;
    word x4 = SBox[x & 0xff];
    return (x1 | x2 | x3 | x4);
}

word Rotword(word x) {
    word x1 = (x << 8);
    word x2 = (x >> 24);
    return (x1 | x2);
}

/* AES - 128 KeyExpansion 구현 */
void KeyExpansion(byte* masterkey, byte roundkey[11][16]) 
{
    word roundkey_word[44];
    word temp = 0;
    for (int i = 0; i < 4; i++) {
        roundkey_word[i] = GETU32(masterkey + i * 4);
    } // roundkey_word[0]~[3]

    for (int i = 4; i < 44; i++) {
        temp = roundkey_word[i - 1];
        if (i % 4 == 0) {
            temp = Subword(Rotword(temp)) ^ rCon[(i / 4) - 1];
        }
        roundkey_word[i] = roundkey_word[i - 4] ^ temp;
    }

    for (int i = 0; i < 11; i++) {
        PUTU32(roundkey[i], roundkey_word[4 * i]);
        PUTU32(roundkey[i] + 4, roundkey_word[4 * i + 1]);
        PUTU32(roundkey[i] + 8, roundkey_word[4 * i + 2]);
        PUTU32(roundkey[i] + 12, roundkey_word[4 * i + 3]);
    }
}

void AddRoundKey(byte* state, byte* roundkey)
{
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundkey[i];
    }
}

void SubBytes(byte* state)
{
    for (int i = 0; i < 16; i++) {
        state[i] = SBox[state[i]];
    }
}

void ShiftRows(byte* state)
{
    byte temp, tmp;
 
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    tmp = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp;
    state[14] = tmp;

    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;

}

#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

void MixColumns(byte* state)
{
    byte t;
    byte tm;
    byte tmp;

    for (int i = 0; i < 4; i++) {
        t = state[4 * i];
        tmp = state[4 * i] ^ state[4 * i + 1] ^ state[4 * i + 2] ^ state[4 * i + 3];

        tm = state[4 * i] ^ state[4 * i + 1];
        tm = xtime(tm);
        state[4 * i] ^= (tm ^ tmp);

        tm = state[4 * i + 1] ^ state[4 * i + 2];
        tm = xtime(tm);
        state[4 * i + 1] ^= (tm ^ tmp);

        tm = state[4 * i + 2] ^ state[4 * i + 3];
        tm = xtime(tm);
        state[4 * i + 2] ^= (tm ^ tmp);

        tm = state[4 * i + 3] ^ t;
        tm = xtime(tm);
        state[4 * i + 3] ^= (tm ^ tmp);
    }
}

void Enc_AES_128(byte* state, byte roundkey[11][16]) {
    //Round 0
    AddRoundKey(state, roundkey[0]);

    //Round 1~9
    for (int i = 1; i < 10; i++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundkey[i]);
    }

    //Round 10
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundkey[10]);
}

void file_enc(byte* masterkey) {

    FILE* fp1;
    byte input[16];
    byte roundkey[11][16];
    byte** state = NULL;

    fp1 = fopen("plaintext.txt", "rb");

    KeyExpansion(masterkey, roundkey);

    if (fp1 != NULL)
    {
        int bk = 1;
        int cnt;
        int Nb = 0;
        while (bk) {
            Nb++;
            memset(input, 0, 16);
            for (int i = 0; i < 16; i++) {
                fread(&input[i], sizeof(byte), 1, fp1);
                if (feof(fp1) != 0) {
                    bk = 0;
                    cnt = i;
                    break;
                }
            }
        }
        rewind(fp1);
        state = (byte**)malloc(sizeof(byte*) * Nb);
        for (int i = 0; i < Nb; i++) {
            state[i] = (byte*)malloc(sizeof(byte) * 16);
        }

        for (int i = 0; i < Nb - 1; i++) {
            memset(state[i], 0, 16);
            fread(state[i], sizeof(byte), 16, fp1);
            Enc_AES_128(state[i], roundkey);
        }

        if (cnt != 0) {
            memset(state[Nb - 1], 0, 16);
            fread(state[Nb - 1], sizeof(byte), cnt, fp1);
            for (int i = cnt; i < 16; i++) {
                state[Nb - 1][i] = 0x00;
            }
            Enc_AES_128(state[Nb - 1], roundkey);
        }

        /* 확인용 출력 코드 =========================================================*/
        printf("[AES]\n");
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 16; j++) {
                printf("%02x ", state[i][j]);
            }
            printf("\n");
        }
        /*============================================================================*/

        for (int i = 0; i < Nb; i++) {
            free(state[i]);
        }
        free(state);
    }

    fclose(fp1);
    
}