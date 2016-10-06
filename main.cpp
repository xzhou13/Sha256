#include "sha256.h"

int main(int argc, char* argv[]){
	if (argc < 2) {
		cout << "usage: " << argv[0] << " <message>" << std::endl;
   		return EXIT_FAILURE;
	}
	
	Sha256 sha;
	string s;
	int stringLength, i;
	unsigned char *hash;

  	s = (argv[1]);
	stringLength = s.size();		
	
	// call Sha256's hash function
	sha = Sha256(argv[1], stringLength, stringLength*8);
	hash = sha.hash();
		
	// print out the hashed results in hex	
	cout << "double check: hash is " << endl;	
	for (i = 0; i < sha.getNumberOfHashedBytes(); i++){
		cout << hex << setw(2) << setfill('0') << (int) hash[i];
	}
	cout << endl;

	return 0;
}
