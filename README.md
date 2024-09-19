# LCipher2
My small KCipher2 implementation in C

### Usage

After statically linking the library, initialize the cipher using `init` with your key and IV

```C
#include "KCipher2.h"

unsigned int key[4] = ...; 
unsigned int iv[4] = ...;

init(key, iv);
```

Then, you can encrypt a buffer using `kcipher2_encrypt`. As KCipher2 is a stream cipher, the same function can be used for decryption.

```C
unsigned char* text = "super secret";

kcipher2_encrypt(text, strlen(text), text); // Alternatively, output the encrypted buffer somewhere else
```

### Examples

Check out the example folder
