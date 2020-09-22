#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <paillier.h>


void get_rand_file( void* buf, int len, char* file )
{
	FILE* fp;
	void* p;

	fp = fopen(file, "r");

	p = buf;
	while( len )
	{
		size_t s;
		s = fread(p, 1, len, fp);
		p += s;
		len -= s;
	}

	fclose(fp);
}

void get_rand_devurandom( void* buf, int len )
{
	get_rand_file(buf, len, "/dev/urandom");
}


int main(int argc, char *argv[])
{
	// Security parameter (number of bits of the modulus)
	mpz_t n;
	mpz_init(n);
	mpz_set_ui(n, 256);  
    
	// Generate keys
	paillier_pubkey_t* pubKey;
	paillier_prvkey_t* secKey;
	paillier_keygen(256, &pubKey, &secKey, paillier_get_rand_devurandom);

	// Plaintexts initialization
	paillier_plaintext_t* m;
	m = paillier_plaintext_from_ui(100);
	gmp_printf("Plaintext created: %Zd\n", m);	

	// Encrypt the messages
	paillier_ciphertext_t* c;
	c = paillier_enc(NULL, pubKey, m, paillier_get_rand_devurandom);
	gmp_printf("Ciphertext created: %Zd\n", c);

	// Now verify that ctxt1 is a valid message
	// Following https://paillier.daylightingsociety.org/Paillier_Zero_Knowledge_Proof.pdf
	// Declare variables
	mpz_t u_1;
	mpz_t u_2;
	mpz_t u_3;
	
	mpz_t m1;
	mpz_t m2;
	mpz_t m3;

	mpz_t g_m1;
	mpz_t g_m2;
	mpz_t g_m3;

	// Init variables
	mpz_init(u_1);
	mpz_init(u_2);
	mpz_init(u_3);

	mpz_init(g_m1);
	mpz_init(g_m2);
	mpz_init(g_m3);

	mpz_init(m1);
	mpz_init(m2);
	mpz_init(m3);

	// Assign values of valid votes to m_k's
	mpz_set_ui(m1, 1);
	mpz_set_ui(m2, 100);
	mpz_set_ui(m3, 10000);

	// Assign values for g_k
	mpz_powm(g_m1, pubKey->n_plusone, m1, pubKey->n_squared);
	mpz_powm(g_m2, pubKey->n_plusone, m2, pubKey->n_squared);
	mpz_powm(g_m3, pubKey->n_plusone, m3, pubKey->n_squared);
	
	// Calculate u_k's	
	mpz_invert(u_1, g_m1, pubKey->n_squared);
	mpz_mul(u_1, c->c, u_1);
	mpz_mod(u_1, u_1, pubKey->n_squared);

	mpz_invert(u_2, g_m2, pubKey->n_squared);
	mpz_mul(u_2, c->c, u_2);
	mpz_mod(u_2, u_2, pubKey->n_squared);

	mpz_invert(u_3, g_m3, pubKey->n_squared);
	mpz_mul(u_3, c->c, u_3);
	mpz_mod(u_3, u_3, pubKey->n_squared);
	
/*
	PASSED	
	// Test that the following holds: u_2 = r^n mod n^2
	// divide c by u_2 and I should get g^m:
	//mpz_div(u_3, c->c, u_2);
	//mpz_mod(u_3, u_3, pubKey->n_squared);
	mpz_invert(u_3, u_2, pubKey->n_squared);
	mpz_mul(u_3, c->c, u_3);
	mpz_mod(u_3, u_3, pubKey->n_squared);
	gmp_printf("c divided by u2 should be g^m: %Zd\n", u_3); 
	gmp_printf("g^m: %Zd\n", g_m2);
	// Try g^m * u_2 and see if we get c
	mpz_mul(u_3, g_m2, u_2);
	mpz_mod(u_3, u_3, pubKey->n_squared);
	gmp_printf("c: %Zd\n", c->c);	
	gmp_printf("gm * u2: %Zd\n", u_3);
*/
	
	// Select 2 random e_k, z_k, and a random w_k
	// TODO: use better random number generation
	mpz_t e_1;
	mpz_t e_3;
		
	mpz_init(e_1);
	mpz_init(e_3);
	
	// Initialize random state for rng
	void* buf;
	mpz_t s;
	buf = malloc(16);
	get_rand_devurandom(buf, 16);
	mpz_init(s);
	mpz_import(s, 16, 1, 1, 0, 0, buf);
	gmp_randstate_t rand_state;
	gmp_randinit_mt(rand_state);
	srand(time(0));
	gmp_randseed(rand_state, s);
	
	// Generate e_1 and e_3
	mpz_urandomb(e_1, rand_state, 256 / 2 - 1);
	mpz_urandomb(e_3, rand_state, 256 / 2 - 1); 
	
	// Generate co-primes for z_k's
	

	// Create an invalid ctxt2 and prove it's invalid
    
	// Cleaning up
	paillier_freepubkey(pubKey);
	paillier_freeprvkey(secKey);
	paillier_freeplaintext(m);
	paillier_freeciphertext(c);
    
	return 0;
}
