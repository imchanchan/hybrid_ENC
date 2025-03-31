#include <stdio.h>
#include <stdlib.h>

typedef unsigned long u32;

u32 H0 = 0x67452301;
u32 H1 = 0xefcdab89;
u32 H2 = 0x98badcfe;
u32 H3 = 0x10325476;
u32 H4 = 0xc3d2e1f0;

u32 K0_19 = 0x5a827999;
u32 K20_39 = 0x6ed9eba1;
u32 K40_59 = 0x8f1bbcdc;
u32 K60_79 = 0xca62c1d6;

u32 plaintext[16];
u32 M[16];
u32 W[80];
u32 HASH_MESSAGE[5];
u32 A, B, C, D, E;

u32 f_Ch(u32 B, u32 C, u32 D)
{
	return (B & C) | (~B & D);
}

u32 f_Parity(u32 B, u32 C, u32 D)
{
	return (B ^ C ^ D);
}

u32 f_Maj(u32 B, u32 C, u32 D)
{
	return (B & C) | (B & D) | (C & D);
}

u32 left_rotate(u32 x, int n) {

	for (int i = 0; i < n; i++) {
		if (x >> 31) {
			x = (x << 1) | 1;
		}
		else {
			x = x << 1;
		}
	}
	return x;

}

//u32 left_rotate(u32 x, int n) {
//	u32 i;
//	
//	for (i = 0; i < n; i++) {
//		if (x & 0x80000000) {
//			x = x << 1;
//			x = x | 1;
//		}
//		else {
//			x = x << 1;
//		}
//	}	
//	return x;
//
//}

void MtoW(u32* W, u32* M)
{
	for (int t = 0; t < 16; t++) {
		W[t] = M[t];
	}
	for (int t = 16; t < 80; t++) {
		u32 temp = 0;
		temp = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
		W[t] = left_rotate(temp, 1);
	}
}

void digest()
{
	u32 TEMP;
	A = H0;
	B = H1;
	C = H2;
	D = H3;
	E = H4;
	u32 K;

	MtoW(W, M);

	int r = 0;

	for (r = 0; r < 20; r++) {
		TEMP = (left_rotate(A, 5) + f_Ch(B, C, D) + E + W[r] + K0_19);
		E = D;
		D = C;
		C = left_rotate(B, 30);
		B = A;
		A = TEMP;
		printf("\n[%02d] %08X %08X %08X %08X %08X\n", r, A, B, C, D, E);
	}
	for (r = 20; r < 40; r++) {
		TEMP = (left_rotate(A, 5) + f_Parity(B, C, D) + E + W[r] + K20_39);
		E = D;
		D = C;
		C = left_rotate(B, 30);
		B = A;
		A = TEMP;
		printf("\n[%02d] %08X %08X %08X %08X %08X\n", r, A, B, C, D, E);
	}
	for (r = 40; r < 60; r++) {
		TEMP = (left_rotate(A, 5) + f_Maj(B, C, D) + E + W[r] + K40_59);
		E = D;
		D = C;
		C = left_rotate(B, 30);
		B = A;
		A = TEMP;
		printf("\n[%02d] %08X %08X %08X %08X %08X\n", r, A, B, C, D, E);
	}
	for (r = 60; r < 80; r++) {
		TEMP = (left_rotate(A, 5) + f_Parity(B, C, D) + E + W[r] + K60_79);
		E = D;
		D = C;
		C = left_rotate(B, 30);
		B = A;
		A = TEMP;
		printf("\n[%02d] %08X %08X %08X %08X %08X\n", r, A, B, C, D, E);
	}

	/*for (int t = 0; t < 80; t++)
	{
		if ((0 <= t)&&(t <= 19)) {
			TEMP = (left_rotate(A, 5) + f_Ch(B, C, D) + E + W[t] + K0_19);
		}

		else if ((20 <= t) && (t <= 39)) {
			TEMP = (left_rotate(A, 5) + f_Parity(B, C, D) + E + W[t] + K20_39);
		}

		else if ((40 <= t) && (t <= 59)) {
			TEMP = (left_rotate(A, 5) + f_Maj(B, C, D) + E + W[t] + K40_59);
		}

		else if ((60 <= t) && (t <= 79)) {
			TEMP = (left_rotate(A, 5) + f_Parity(B, C, D) + E + W[t] + K60_79);
		}

		E = D;
		D = C;
		C = left_rotate(B, 30);
		B = A;
		A = TEMP;
		printf("\n[%02d] %08X %08X %08X %08X %08X\n", t, A, B, C, D, E);
	}*/

	H0 += A;
	H1 += B;
	H2 += C;
	H3 += D;
	H4 += E;

	printf("\nH0 = %08X\n", H0);
	printf("H1 = %08X\n", H1);
	printf("H2 = %08X\n", H2);
	printf("H3 = %08X\n", H3);
	printf("H4 = %08X\n\n", H4);

	HASH_MESSAGE[0] = H0;
	HASH_MESSAGE[1] = H1;
	HASH_MESSAGE[2] = H2;
	HASH_MESSAGE[3] = H3;
	HASH_MESSAGE[4] = H4;
	for (int i = 0; i < 5; i++) {
		printf("%08X", HASH_MESSAGE[i]);
	}
	printf("\n\n\n\n\n");

}

// data data ... data 1 00...0 (64bits(2words)) bits size

void padding(u32 data[16], u32 bitsize)
{
	int n = bitsize/32;
	int r = bitsize % 32;
	int j;

	for (int i = 0; i < 14; i++) 
	{
		if (i < n) {
			M[i] = data[i];
		}
		else if (i == n) {
			for (j = 0; j < r; j++) {
				M[i] |= ((data[i] >> (31 - j)) & 0x01) << (31 - j);
			}
			M[i] |= (0x01 << 31 - j);
		}
		else {
			M[i] = 0x00;
		}
	}
	M[14] = 0x00;
	M[15] = bitsize;
}

int split_input(unsigned char* input, u32* output) {
    int size = 0;
    for (int i = 0; i < 64; i++) {                                                                                
        if (input[i] == NULL) {
            size = i;
            break;
        }
    }

    for (unsigned int i = 0; i < (size / 4) + 1; i++) {
        u32 tmp = 0;
        tmp = (input[4 * i + 3] & 0xff)
            | (input[4 * i + 2] & 0xff) << 8
            | (input[4 * i + 1] & 0xff) << 16
            | (input[4 * i + 0] & 0xff) << 24;
        output[i] = tmp;
    }
    return size;
}



int main() {
	unsigned char inputString[64] 
		= "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop";
	//unsigned char inputString[64] = "abc";
	int blocksize = 0;

	blocksize = split_input(inputString, plaintext);

	padding(plaintext, blocksize*8);
	for (int i = 0; i < 16; i++) {
		printf("W[%02d] = %08X\n", i, M[i]);
	}
	printf("\n\tA\tB\tC\tD\tE");
	digest();
	
}

