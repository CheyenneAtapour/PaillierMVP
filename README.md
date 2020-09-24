# PaillierMVP
Proof of concept demonstrating Paillier cryptosystem to architect a voting system

I have edited libpaillier to expose the random 'r' for use in ZKP to prove vote validity

Compile with:

gcc pali.c -lpaillier -lgmp -lm -o output.out

gcc zkp.c -lgmp -lm -lssl -lcrypto

gcc paillier.c -c
