# sha256
C++ implementation of Sha256, hashes to given number of bits. **NOTE the code is written for little endian machines.** </br>

Type `make` in the root of the repository, and then run `./sha256 <message>`.
Usage (Note the code is written for little endian machines):
```C++
#include "sha256.h"

Sha256 sha256;
char *message = "abc";
string s = message;
int msgSize = s.size();
numBitsToHash = msgSize*8;
char* hashResult;

hashResult = Sha256(message, msgSize, numBitsToHash).hash();
```

