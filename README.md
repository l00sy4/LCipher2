# LCipher2
My small KCipher2 implementation in C

### Usage

After statically linking the library:

```
#include "KCipher2.h"

unsigned int key[4] = ...; 
unsigned int iv[4] = ...;

init(key, iv);


// Then, anywhere else in the project
unsigned char* text = "super secret";
unsigned char* ciphertext = ...;

kcipher2_encrypt_decrypt(text, strlen(text), ciphertext);
```
