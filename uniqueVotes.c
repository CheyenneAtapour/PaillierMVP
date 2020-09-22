/*
	This program demonstrates that the same vote will appear different
*/


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
	paillier_plaintext_t* vote1;	
	vote1 = paillier_plaintext_from_ui(1);	
	gmp_printf("Plaintext created: %Zd\n", vote1);

	// Encrypt the plaintext of 1
	paillier_ciphertext_t* cipher1;
	cipher1 = paillier_enc(NULL, pubKey, vote1, paillier_get_rand_devurandom);
	gmp_printf("Ciphertext created: %Zd\n", cipher1);

	// Decrypt the ciphertext of 1
	paillier_plaintext_t* decrypted1;
	decrypted1 = paillier_dec(NULL, pubKey, secKey, cipher1);
	gmp_printf("Ciphertext decrypted: %Zd\n", decrypted1);

	// Create plaintext of 2
	paillier_plaintext_t* vote2;	
	vote2 = paillier_plaintext_from_ui(2);	
	gmp_printf("Plaintext created: %Zd\n", vote2);

	// Encrypt the plaintext of 2
	paillier_ciphertext_t* cipher2;
	cipher2 = paillier_enc(NULL, pubKey, vote2, paillier_get_rand_devurandom);
	gmp_printf("Ciphertext created: %Zd\n", cipher2);

	// Decrypt the ciphertext of 2
	paillier_plaintext_t* decrypted2;
	decrypted2 = paillier_dec(NULL, pubKey, secKey, cipher2);
	gmp_printf("Ciphertext decrypted: %Zd\n", decrypted2);

	// Make another vote of 2 and prove that it's different
	// Create plaintext of 2	
	paillier_plaintext_t* vote3;	
	vote3 = paillier_plaintext_from_ui(2);	
	gmp_printf("Plaintext created: %Zd\n", vote3);

	// Encrypt the plaintext of 2
	paillier_ciphertext_t* cipher3;
	cipher3 = paillier_enc(NULL, pubKey, vote3, paillier_get_rand_devurandom);
	gmp_printf("Ciphertext created: %Zd\n", cipher3);

	// Decrypt the plaintext of 2
	paillier_plaintext_t* decrypted3;
	decrypted3 = paillier_dec(NULL, pubKey, secKey, cipher3);
	gmp_printf("Ciphertext decrypted: %Zd\n", decrypted3);

	// Free memory
	paillier_freepubkey(pubKey);
	paillier_freeprvkey(secKey);
	paillier_freeplaintext(vote);
	paillier_freeplaintext(vote1);
	paillier_freeplaintext(vote2);
	paillier_freeplaintext(vote3);
	paillier_freeplaintext(decrypted);
	paillier_freeplaintext(decrypted1);
	paillier_freeplaintext(decrypted2);
	paillier_freeplaintext(decrypted3);
	paillier_freeciphertext(cipher);
	paillier_freeciphertext(cipher1);
	paillier_freeciphertext(cipher2);
	paillier_freeciphertext(cipher3);

	return 0;
}
