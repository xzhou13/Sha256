#include "sha256.h"
#define ROTR(w, n) (((w) >> (n)) | ((w) << ((sizeof(w) * 8) - (n))))
#define DOS0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define DOS1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))
#define DOSS1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ (ROTR(x, 25)))
#define DOSS0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ((ROTR(x, 22))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) 

unsigned char* Sha256::hash(){

	pre_processing();

	processIn512Chunks();

	delete[] preProcessedMsg;

	return output;
}

// null constructor
Sha256::Sha256(){

}

// constructor sets initial message and message sizes
Sha256::Sha256(char* msg, unsigned int size, unsigned int numBits){
	message = msg;
	messageSize = size;
	messageBitLength = messageSize * 8;
	numBitsToHash = numBits;
	numBytesToHash = numBitsToHash/8;
	if (numBitsToHash % 8 != 0){
		numBytesToHash++;
	}
	cout << "message to hash: " << message << endl;
	cout << "number of bits to hash: " << numBitsToHash << endl;
	cout << "number of bytes to hash to: " << numBytesToHash << endl;
}

Sha256::~Sha256(){}

void Sha256::pre_processing(){
	unsigned int k, i;
	unsigned long long int msgLength8Bytes; // used for appending message length in 64 bits because long long int is 64 bits

	// calculate the smallest k such that it pads the message to multiple of 512 bits
	// after appending '1' bit and 64 bits to the message
	k = 512 - (64 + 1 + numBitsToHash) % 512;

	// allocate enough bytes for preProcessedMsg
	numTotBits = 64 + 1 + numBitsToHash + k;
	preProcessedMsg = new unsigned char[numTotBits/8];

	// initialize preProcessedMsg to contain all 0s, then copy message into
	// begining of preProcessedMsg
	memset(preProcessedMsg, 0, numTotBits/8);
	memcpy(preProcessedMsg, message, numBytesToHash);

	/*
	// append '1', or 1000 0000 (byte unit) to where initial message ends
	 *(preProcessedMsg + messageSize) = 0x80;
	 */

	// append '1' and '0's
	*(preProcessedMsg + (numBitsToHash/8)) |= (1 << (7 - (numBitsToHash % 8)));
	for (i = 0; i <= (unsigned int) (6 - (numBitsToHash % 8)); i++){
		*(preProcessedMsg + (numBitsToHash/8)) &= ~(1 << i);
	}

	// find message size in bits to append to end of preProcessedMsg, append in big endian fashion
	msgLength8Bytes = numBitsToHash;
	for(i = 0; i < 8; i++){
		// this sets sets message size at end of preProcessedMsg one byte at a time, big endian
		*(preProcessedMsg + numTotBits/8 - i - 1) = (msgLength8Bytes >> (8*i));
	}
	
}

void Sha256::processIn512Chunks(){
	unsigned int numChunks;
	unsigned int i, j;
	unsigned int w[64];
	uint32_t a, b, c, d, e, f, g, H, S1, ch, temp1, S0, maj, temp2;
	uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	unsigned char* chunkPtr, *wcopy;	
	unsigned char* hcopy;

	numChunks = numTotBits/512;
	//printf("number of chunks is %d divided by 512 = %d\n", numTotBits, numChunks);

	chunkPtr = (unsigned char*) (preProcessedMsg);
	for (i = 0; i < numChunks; i++){

		// this only works for little endian machines, it moves chunk into first 16 words and 
		// makes sure the bits are in proper positions for little endian
		wcopy = (unsigned char*) (w);
		for (j = 0; j < 64; j += 4){
			wcopy[j] = chunkPtr[j+3];
			wcopy[j+1] = chunkPtr[j+2];
			wcopy[j+2] = chunkPtr[j+1];
			wcopy[j+3] = chunkPtr[j];
		}
		chunkPtr += 64;

		//Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
		for (j = 16; j < 64; j++){
			w[j] = w[j-16] + DOS0(w[j-15]) + w[j-7]	+ DOS1(w[j-2]);
		} 

		//Initialize working variables to current hash value
		a = h[0];
		b = h[1];
		c = h[2];
		d = h[3];
		e = h[4];
		f = h[5];
		g = h[6];
		H = h[7];

		//Compression function main loop:
		for (j = 0; j < 64; j++){
			S1 = DOSS1(e);
			ch = CH(e, f, g);
			temp1 = H + S1 + ch + k[j] + w[j];
			S0 = DOSS0(a);
			maj = MAJ(a, b, c);
			temp2 = S0 + maj;

			H = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		// Add the compressed chunk to the current hash value:
		h[0] = h[0] + a;
		h[1] = h[1] + b;
		h[2] = h[2] + c;
		h[3] = h[3] + d;
		h[4] = h[4] + e;
		h[5] = h[5] + f;
		h[6] = h[6] + g;
		h[7] = h[7] + H;

	}
	
	cout << endl;	
	cout << "complete hash of the first " << numBitsToHash << " bits is: " << endl;
	for (j = 0; j < 8; j++){
		cout << hex << h[j] << " ";
	}
	cout << endl << endl;

	// j/4 is integerdivision to show how many times we've looped through the
	// number 4 (as we only have 4 bytes for the integer before we come to the
	// next integer set where we need its most significant digit first again)
	// we start at 3 before for j = 0, we want the 3rd byte (the most sig.
	// digit). But for j = 1, we need the second byte. So every 4 bytes we need
	// to grab the digit that is 3 away from our current j value and then we
	//count down.
	// j | n | j | n  etc...
	// 0   3 | 4   7
	// 1   2 | 5   6
	// 2   3 | 6   5
	// 3   0 | 7   4
	output = new unsigned char[numBytesToHash];
	hcopy = (unsigned char*) h;
	for(j = 0; j < (unsigned int) numBytesToHash; j++){
		output[j] = hcopy[3 + (4*(j/4))-(j%4)];
	}

	//sets any extra bits in the bytes to 0
	for(j = 0; j <= (7 - (numBitsToHash % 8)); j++){
		*(output + (numBitsToHash/8)) &= ~(1 << j);
	}
	
	// print out final hash to be returned
	cout << dec << "final hash returned (" << numBitsToHash << " bits, " << numBytesToHash << " bytes) is : " << endl;
	for (i = 0; i < (unsigned int) numBytesToHash; i++){
		cout << hex << (int) (output[i]);
	}
	cout << endl << endl;

}

int Sha256::getNumberOfHashedBytes(){
	return numBytesToHash;
}

