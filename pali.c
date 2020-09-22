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

	// Create plaintext of 0
	paillier_plaintext_t* vote;	
	vote = paillier_plaintext_from_ui(0);	
	gmp_printf("Plaintext created: %Zd\n", vote);

	// Encrypt the plaintext of 0
	paillier_ciphertext_t* cipher;
	cipher = paillier_enc(NULL, pubKey, vote, paillier_get_rand_devurandom);
	gmp_printf("Ciphertext created: %Zd\n", cipher);

	// Decrypt the ciphertext of 0
	paillier_plaintext_t* decrypted;
	decrypted = paillier_dec(NULL, pubKey, secKey, cipher);
	gmp_printf("Ciphertext decrypted: %Zd\n", decrypted);

	// Create plaintext of 1

	// Encrypt the plaintext of 1

	// Decrypt the ciphertext of 1

	// Create plaintext of 2

	// Encrypt the plaintext of 2

	// Decrypt the ciphertext of 2

	// Make 100 random valid votes 

	// Print the result of the election


	// Show that a vote can't be invalid invoking zkps

	// Free memory
	paillier_freepubkey(pubKey);
	paillier_freeprvkey(secKey);
	paillier_freeplaintext(vote);
	paillier_freeplaintext(decrypted);
	paillier_freeciphertext(cipher);

	return 0;
}
