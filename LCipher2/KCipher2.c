#include "Tables.h"
#include "KCipher2.h"

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

inline unsigned int* key_expansion(unsigned int* key, const unsigned int* iv)
{
	key[4]  = key[0] ^ sub_k2(key[3] << 8 ^ key[3] >> 24) ^ 0x01000000;
	key[5]  = key[1] ^ key[4]; key[6] = key[2] ^ key[5];
	key[7]  = key[3] ^ key[6];
	key[8]  = key[4] ^ sub_k2(key[7] << 8 ^ key[7] >> 24) ^ 0x02000000;
	key[9]  = key[5] ^ key[8]; key[10] = key[6] ^ key[9];
	key[11] = key[7] ^ key[10];

	return key;
}

kcipher2_state setup_state_values(kcipher2_state state, const unsigned int* key, const unsigned int* iv)
{
	key = key_expansion(key, iv);

	state.A[0] = key[4];  state.A[1] = key[3];  state.A[2] = key[2];
	state.A[3] = key[1];  state.A[4] = key[0];
	state.B[0] = key[10]; state.B[1] = key[11]; state.B[2] = iv[0]; state.B[3] = iv[1];
	state.B[4] = key[8];  state.B[5] = key[9];  state.B[6] = iv[2]; state.B[7] = iv[3];
	state.B[8] = key[7];  state.B[9] = key[5];  state.B[10] = key[6];

	state.L1 = state.R1 = state.L2 = state.R2 = 0x00000000;

	return state;
}

kcipher2_state init(const unsigned int *key, const unsigned int *iv, kcipher2_state state)
{
	state = setup_state_values(state, key, iv);

	for (unsigned char i = 0; i < 24; i++) 
	{
		state = next(INIT, state);
	}

	return state;
}

kcipher2_state next(const unsigned char mode, kcipher2_state state)
{
	unsigned int nL1 = sub_k2(state.R2 + state.B[4]);
	unsigned int nR1 = sub_k2(state.L2 + state.B[9]);
	unsigned int nL2 = sub_k2(state.L1);
	unsigned int nR2 = sub_k2(state.R1);

	unsigned int nA[5];

	nA[0] = state.A[1]; nA[1] = state.A[2]; nA[2] = state.A[3]; nA[3] = state.A[4];

	unsigned int nB[11];

	nB[0] = state.B[1]; nB[1] = state.B[2]; nB[2] = state.B[3]; nB[3] = state.B[4];
	nB[4] = state.B[5]; nB[5] = state.B[6]; nB[6] = state.B[7]; nB[7] = state.B[8];
	nB[8] = state.B[9]; nB[9] = state.B[10];

	unsigned int temp1 = state.A[0] << 8 ^ amul0[(state.A[0] >> 24)];
	nA[4] = temp1 ^ state.A[3];

	if (mode == INIT)
	{
		nA[4] ^= nlf(state.B[0], state.R2, state.R1, state.A[4]);
	}

	if (state.A[2] & 0x40000000)
	{
		temp1 = state.B[0] << 8 ^ amul1[(state.B[0] >> 24)];
	}
	else 
	{
		temp1 = state.B[0] << 8 ^ amul2[(state.B[0] >> 24)];
	}

	unsigned int temp2;

	if (state.A[2] & 0x80000000)
	{
		temp2 = state.B[8] << 8 ^ amul3[(state.B[8] >> 24)];
	}
	else  
	{
		temp2 = state.B[8];
	}

	nB[10] = temp1 ^ state.B[1] ^ state.B[6] ^ temp2;

	if (mode == INIT)
	{
		nB[10] ^= nlf(state.B[10], state.L2, state.L1, state.A[0]);
	}

	kcipher2_state new_state;

	new_state.A[0] = nA[0]; new_state.A[1] = nA[1]; new_state.A[2]  = nA[2];
	new_state.A[3] = nA[3]; new_state.A[4] = nA[4];
	new_state.B[0] = nB[0]; new_state.B[1] = nB[1]; new_state.B[2]  = nB[2]; new_state.B[3] = nB[3];
	new_state.B[4] = nB[4]; new_state.B[5] = nB[5]; new_state.B[6]  = nB[6]; new_state.B[7] = nB[7];
	new_state.B[8] = nB[8]; new_state.B[9] = nB[9]; new_state.B[10] = nB[10];

	new_state.L1 = nL1; new_state.R1 = nR1; new_state.L2 = nL2; new_state.R2 = nR2;

	return new_state;
}

unsigned long long stream(const kcipher2_state state)
{
	const unsigned int zh = nlf(state.B[10], state.L2, state.L1, state.A[0]);
	const unsigned int zl = nlf(state.B[0],  state.R2, state.R1, state.A[4]);

	return (unsigned long long)zh << 32 | zl;
}

void kcipher2_encrypt(kcipher2_state state, unsigned char* in, const unsigned long len, unsigned char* out, const unsigned int* Key, const unsigned int* Iv)
{

	state = init(Key, Iv, state);
	unsigned long long key_stream;
	unsigned long long* buffer     = (unsigned long long*)in;
	unsigned long long* out_buffer = (unsigned long long*)out;

	for (unsigned long i = 0; i < len / 8; i++)
	{
		key_stream = stream(state);
		state      = next(NORMAL, state);

		out_buffer[i] = buffer[i] ^ key_stream;
	}

	unsigned long remaining_bytes = len % 8;

	if (remaining_bytes > 0)
	{
		unsigned char* byte_buffer = (unsigned char*)&buffer[len / 8];
		unsigned char* out_byte_buffer = (unsigned char*)&out_buffer[len / 8];

		key_stream = stream(state);
		state      = next(NORMAL, state);

		for (unsigned long i = 0; i < remaining_bytes; i++)
		{
			out_byte_buffer[i] = byte_buffer[i] ^ ((unsigned char*)&key_stream)[i];
		}
	}
}