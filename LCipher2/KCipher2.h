#pragma once

#define INIT   0
#define NORMAL 1

typedef struct
{
	unsigned int  A[5];
	unsigned int  B[11];
	unsigned int  L1, R1, L2, R2;

} kcipher2_state;

extern unsigned int   IK[12];
extern unsigned int   IV[4];
extern kcipher2_state State;

void kcipher2_encrypt(unsigned char* in, unsigned long len, unsigned char* out);
void init(unsigned int* key, unsigned int* iv);
