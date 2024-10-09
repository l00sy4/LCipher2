#include "Tables.h"
#include "KCipher2.h"

unsigned int   IK[12];
unsigned int   IV[4];
kcipher2_state State;

inline unsigned int nlf(const unsigned int a, const unsigned int b, const unsigned int c, const unsigned int d)
{
	return a + b ^ c ^ d;
}

inline unsigned char gf_multiply_by_2(const unsigned char t)
{
	unsigned int lq = t << 1;

	if ((lq & 0x100) != 0)
	{
		lq ^= 0x011B;
	}

	return (unsigned char)lq ^ 0xFF;
}

inline unsigned char gf_multiply_by_3(const unsigned char t)
{
	unsigned int lq = t << 1 ^ t;

	if ((lq & 0x100) != 0)
	{
		lq ^= 0x011B;
	}

	return (unsigned char)lq ^ 0xFF;
}

unsigned int sub_k2(const unsigned int in)
{
	unsigned char w0 = in & 0x000000ff;
	unsigned char w1 = in >> 8 & 0x000000ff;
	unsigned char w2 = in >> 16 & 0x000000ff;
	unsigned char w3 = in >> 24 & 0x000000ff;

	unsigned char t0 = s_box[w0];
	unsigned char t1 = s_box[w1];
	unsigned char t2 = s_box[w2];
	unsigned char t3 = s_box[w3];

	unsigned char q0 = gf_multiply_by_2(t0) ^ gf_multiply_by_3(t1) ^ t2 ^ t3;
	unsigned char q1 = t0 ^ gf_multiply_by_2(t1) ^ gf_multiply_by_3(t2) ^ t3;
	unsigned char q2 = t0 ^ t1 ^ gf_multiply_by_2(t2) ^ gf_multiply_by_3(t3);
	unsigned char q3 = gf_multiply_by_3(t0) ^ t1 ^ t2 ^ gf_multiply_by_2(t3);

	return q3 << 24 | q2 << 16 | q1 << 8 | q0;
}

inline void key_expansion(const unsigned int* key, const unsigned int* iv)
{
	IV[0] = iv[0];
	IV[1] = iv[1];
	IV[2] = iv[2];
	IV[3] = iv[3];

	IK[0] = key[0];
	IK[1] = key[1];
	IK[2] = key[2];
	IK[3] = key[3];

	IK[4] = IK[0] ^ sub_k2(IK[3] << 8 ^ IK[3] >> 24) ^ 0x01000000;
	IK[5] = IK[1] ^ IK[4]; IK[6] = IK[2] ^ IK[5];
	IK[7] = IK[3] ^ IK[6];
	IK[8] = IK[4] ^ sub_k2(IK[7] << 8 ^ IK[7] >> 24) ^ 0x02000000;
	IK[9] = IK[5] ^ IK[8]; IK[10] = IK[6] ^ IK[9];
	IK[11] = IK[7] ^ IK[10];
}

void setup_state_values(const unsigned int* key, const unsigned int* iv)
{
	key_expansion(key, iv);

	State.A[0] = IK[4];  State.A[1] = IK[3];  State.A[2] = IK[2];
	State.A[3] = IK[1];  State.A[4] = IK[0];
	State.B[0] = IK[10]; State.B[1] = IK[11]; State.B[2] = IV[0]; State.B[3] = IV[1];
	State.B[4] = IK[8];  State.B[5] = IK[9];  State.B[6] = IV[2]; State.B[7] = IV[3];
	State.B[8] = IK[7];  State.B[9] = IK[5];  State.B[10] = IK[6];

	State.L1 = State.R1 = State.L2 = State.R2 = 0x00000000;
}

void init(unsigned int *key, unsigned int *iv)
{
	setup_state_values(key, iv);

	for (unsigned char i = 0; i < 24; i++) 
	{
		next(INIT);
	}
}

void next(const unsigned char mode)
{
	unsigned int temp2;

	unsigned int nL1 = sub_k2(State.R2 + State.B[4]);
	unsigned int nR1 = sub_k2(State.L2 + State.B[9]);
	unsigned int nL2 = sub_k2(State.L1);
	unsigned int nR2 = sub_k2(State.R1);

	unsigned int nA[5];

	nA[0] = State.A[1]; nA[1] = State.A[2]; nA[2] = State.A[3]; nA[3] = State.A[4];

	unsigned int nB[11];

	nB[0] = State.B[1]; nB[1] = State.B[2]; nB[2] = State.B[3]; nB[3] = State.B[4];
	nB[4] = State.B[5]; nB[5] = State.B[6]; nB[6] = State.B[7]; nB[7] = State.B[8];
	nB[8] = State.B[9]; nB[9] = State.B[10];

	unsigned int temp1 = State.A[0] << 8 ^ amul0[(State.A[0] >> 24)];
	nA[4] = temp1 ^ State.A[3];

	if (mode == INIT)
	{
		nA[4] ^= nlf(State.B[0], State.R2, State.R1, State.A[4]);
	}

	if (State.A[2] & 0x40000000)  
	{
		temp1 = State.B[0] << 8 ^ amul1[(State.B[0] >> 24)];
	}
	else 
	{
		temp1 = State.B[0] << 8 ^ amul2[(State.B[0] >> 24)];
	}

	if (State.A[2] & 0x80000000)
	{
		temp2 = State.B[8] << 8 ^ amul3[(State.B[8] >> 24)];
	}
	else  
	{
		temp2 = State.B[8];
	}

	nB[10] = temp1 ^ State.B[1] ^ State.B[6] ^ temp2;

	if (mode == INIT)
	{
		nB[10] ^= nlf(State.B[10], State.L2, State.L1, State.A[0]);
	}

	State.A[0] = nA[0]; State.A[1] = nA[1]; State.A[2]  = nA[2];
	State.A[3] = nA[3]; State.A[4] = nA[4];
	State.B[0] = nB[0]; State.B[1] = nB[1]; State.B[2]  = nB[2]; State.B[3] = nB[3];
	State.B[4] = nB[4]; State.B[5] = nB[5]; State.B[6]  = nB[6]; State.B[7] = nB[7];
	State.B[8] = nB[8]; State.B[9] = nB[9]; State.B[10] = nB[10];

	State.L1 = nL1; State.R1 = nR1; State.L2 = nL2; State.R2 = nR2;
}

unsigned long long stream()
{
	const unsigned int zh = nlf(State.B[10], State.L2, State.L1, State.A[0]);
	const unsigned int zl = nlf(State.B[0],  State.R2, State.R1, State.A[4]);

	return (unsigned long long)zh << 32 | zl;
}

void kcipher2_encrypt(unsigned char* in, const unsigned long len, unsigned char* out)
{
	unsigned long long key_stream;
	unsigned long long* buffer     = (unsigned long long*)in;
	unsigned long long* out_buffer = (unsigned long long*)out;

	for (unsigned long i = 0; i < len / 8; i++)
	{
		key_stream = stream();
		next(NORMAL);

		out_buffer[i] = buffer[i] ^ key_stream;
	}

	unsigned long remaining_bytes = len % 8;

	if (remaining_bytes > 0)
	{
		unsigned char* byte_buffer = (unsigned char*)&buffer[len / 8];
		unsigned char* out_byte_buffer = (unsigned char*)&out_buffer[len / 8];

		key_stream = stream();
		next(NORMAL);

		for (unsigned long i = 0; i < remaining_bytes; i++)
		{
			out_byte_buffer[i] = byte_buffer[i] ^ ((unsigned char*)&key_stream)[i];
		}
	}
}
