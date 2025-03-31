#pragma once

typedef unsigned long word;
typedef unsigned char byte;

word* hashing(byte* inputString, int iteration, word* hashingdata, int size);

#define PUTU32(ct, st) { (ct)[0] = (byte)((st) >> 24); (ct)[1] = (byte)((st) >> 16); (ct)[2] = (byte)((st) >>  8); (ct)[3] = (byte)(st); }
#define GETU32(pt) (((word)(pt)[0] << 24) ^ ((word)(pt)[1] << 16) ^ ((word)(pt)[2] <<  8) ^ ((word)(pt)[3]))

//void ECB_enc(const char* Plainfile, const char* Cipherfile, const char* Paddingfile, byte* MasterKey);
//void ECB(byte* MasterKey);
void file_enc(byte* masterkey);
void Enc_AES_128(byte* state, byte roundkey[11][16]);
void KeyExpansion(byte* masterkey, byte roundkey[11][16]);