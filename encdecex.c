#include <stdio.h>
#include <gmp.h>
#include <paillier.h>


int main(int argc, char **argv) 
{
	// Generate Keys
	paillier_pubkey_t* pubKey;
	paillier_prvkey_t* secKey;
	paillier_keygen(256, &pubKey, &secKey, paillier_get_rand_devurandom);

	printf("Public key generated:\n%s\n", paillier_pubkey_to_hex(pubKey));

	// Create plaintext
	paillier_plaintext_t* vote;	
	vote = paillier_plaintext_from_ui(0);	
	gmp_printf("Plaintext created: %Zd\n", vote);

	// Encrypt the plaintext
	paillier_ciphertext_t* cipher;
	cipher = paillier_enc(NULL, pubKey, vote, paillier_get_rand_devurandom);
	gmp_printf("Ciphertext created: %Zd\n", cipher);

	// Decrypt the ciphertext
	paillier_plaintext_t* decrypted;
	decrypted = paillier_dec(NULL, pubKey, secKey, cipher);
	gmp_printf("Ciphertext decrypted: %Zd\n", decrypted);

	// Free memory
	paillier_freepubkey(pubKey);
	paillier_freeprvkey(secKey);
	paillier_freeplaintext(vote);
	paillier_freeplaintext(decrypted);
	paillier_freeciphertext(cipher);

	return 0;
}
