#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <sstream>
#include <bitset>
#include <iomanip>
#include <new>
using namespace std;

class Sha256 {
	public:
		Sha256();
		Sha256(char* msg, unsigned int size, unsigned int numBits);
		~Sha256();
    		unsigned char* hash();
		int getNumberOfHashedBytes();
	
	protected:
		char* message;			// ptr to begining of initial message
		string msgString;		// initial message in string
		int messageSize;		// number of bytes/chars in initial message
		int messageBitLength;		// initial message bit length
		unsigned int numBitsToHash;     // number of bits to hash a given message
		int numBytesToHash;
		unsigned char* preProcessedMsg;	// ptr to begining of pre-processed message
		int numTotBits;			// number of bits in preProcessedMsg
		unsigned char* output;		// final hashed message
	
		void pre_processing();
		void processIn512Chunks();
};
