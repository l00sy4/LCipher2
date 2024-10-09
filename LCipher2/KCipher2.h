#pragma once

#define INIT   0
#define NORMAL 1

typedef struct
{
	unsigned int  A[5];
	unsigned int  B[11];
	unsigned int  L1, R1, L2, R2;

} kcipher2_state;

void               kcipher2_encrypt(kcipher2_state state, unsigned char* in, const unsigned long len, unsigned char* out, const unsigned int* Key, const unsigned int* Iv);
kcipher2_state	   next(unsigned char mode, kcipher2_state state);
unsigned long long stream(kcipher2_state state);