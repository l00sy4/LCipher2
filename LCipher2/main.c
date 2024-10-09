#include <stdio.h>
#include "KCipher2.h"

void HexDump(const char* desc, const void* addr, const int len)
{
    int i;
    int perLine = 16;
    unsigned char buff[17];
    const unsigned char* pc = addr;

    if (desc != NULL) printf("%s:\n", desc);

    if (len == 0)
    {
        printf("  ZERO LENGTH\n");
        return;
    }

    if (len < 0)
    {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    for (i = 0; i < len; i++)
    {
        if (i % perLine == 0)
        {
            if (i != 0) printf("  %s\n", buff);
            printf("  %04x ", i);
        }

        printf(" %02x", pc[i]);
        if (pc[i] < 0x20 || pc[i] > 0x7e)
        {
            buff[i % perLine] = '.';
        }
        else
        {
            buff[i % perLine] = pc[i];
        }
        buff[i % perLine + 1] = '\0';
    }

    while (i % perLine != 0)
    {
        printf("   ");
        i++;
    }

    printf("  %s\n", buff);
}

/*
 *  Original:
 *	  0000  4c 75 63 69 34 20 73 61 79 73 20 68 69 21 21 21  Luci4 says hi!!!
 * 	  0010  00                                               .
 *
 *	Encrypted:
 *	  0000  3e 07 38 fd db cb 02 99 4e 76 df 75 fd 25 2d c5  >.8.....Nv.u.%-.
 *	  0010  57                                               W
 *
 *	Decrypted:
 *	  0000  4c 75 63 69 34 20 73 61 79 73 20 68 69 21 21 21  Luci4 says hi!!!
 *	  0010  00                                               .
 */
int main()
{
    unsigned int  Key[4] = { 0 };
    unsigned int  Iv[4] = { 0 };
    unsigned char Secret[] = "Luci4 says hi!!!";
    kcipher2_state state;


    HexDump("Original", Secret, sizeof(Secret));
    puts("");


    kcipher2_encrypt(state, Secret, sizeof(Secret), Secret, Key, Iv);

    HexDump("Encrypted", Secret, sizeof(Secret));
    puts("");


    kcipher2_encrypt(state, Secret, sizeof(Secret), Secret, Key, Iv);

    HexDump("Decrypted", Secret, sizeof(Secret));
    puts("");


    kcipher2_encrypt(state, Secret, sizeof(Secret), Secret, Key, Iv);

    HexDump("Encrypted", Secret, sizeof(Secret));
    puts("");


    kcipher2_encrypt(state, Secret, sizeof(Secret), Secret, Key, Iv);

    HexDump("Decrypted", Secret, sizeof(Secret));
    puts("");

}