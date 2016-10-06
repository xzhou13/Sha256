# sha256
C++ implementation of Sha256, hashes to given number of bits.
NOTE the code is written for little endian machines.

Type `make` in the root of the repository, and then run `./sha256 <message>`.
Usage (Note the code is written for little endian machines):
```C++
#include "sha256.h"

Sha256 sha256;
char *message = "abc";
string s = message;
int msgSize = s.size();
char* hashResult;
numBitsToHash = msgSize*8;

hashResult = Sha256(message, msgSize, numBitsToHash).hash();
```

