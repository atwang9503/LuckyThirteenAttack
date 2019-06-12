#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "FEAL4_functions.h"

int numPlain;
unsigned long long plain0[10000];
unsigned long long cipher0[10000];
unsigned long long plain1[10000];
unsigned long long cipher1[10000];

void undoFinalOperation()
{
        int c;
        for(c = 0; c < numPlain; c++)
        {
            unsigned long cipherLeft0 = leftHalf(cipher0[c]);
            unsigned long cipherRight0 = rightHalf(cipher0[c]) ^ cipherLeft0;
            unsigned long cipherLeft1 = leftHalf(cipher1[c]);
            unsigned long cipherRight1 = rightHalf(cipher1[c]) ^ cipherLeft1;

			cipher0[c] = combineHalves(cipherLeft0, cipherRight0);
			cipher1[c] = combineHalves(cipherLeft1, cipherRight1);
         }
}

unsigned long crackLastRound(unsigned long outdiff)
{
    printf("Output differential: 0x%08lx\n", outdiff);

    unsigned long fakeK;
    for(fakeK = 0x00000000L; fakeK < 0xFFFFFFFFL; fakeK++)
    {
        int score = 0;

        int c;
        for(c = 0; c < numPlain; c++)
        {
            unsigned long cipherLeft = (cipher0[c] >> 32LL);
            cipherLeft ^= (cipher1[c] >> 32LL);

            unsigned long Z = cipherLeft ^ outdiff;

            unsigned long Y0 = cipher0[c] & 0xFFFFFFFFLL;
            unsigned long Y1 = cipher1[c] & 0xFFFFFFFFLL;

            unsigned long fakeInput0 = Y0 ^ fakeK;
            unsigned long fakeInput1 = Y1 ^ fakeK;
            unsigned long fakeOut0 = fBox(fakeInput0);
            unsigned long fakeOut1 = fBox(fakeInput1);
            unsigned long fakeDiff = fakeOut0 ^ fakeOut1;

            if (fakeDiff == Z) score++; else break;
        }

        if (score == numPlain)
        {
            printf("subkey : 0x%08lx\n", fakeK);
            return fakeK;
        }
    }

    printf("failed\n");
    return 0;
}

void chosenPlaintext(unsigned long long diff)
{
 	printf("Generating %d chosen-plaintext pairs\n", numPlain);
	printf("Input differential: 0x%016llx\n", diff);

    srand(time(NULL));

    int c;
    for(c = 0; c < numPlain; c++)
    {
        plain0[c] = (rand() & 0xFFFFLL) << 48LL;
        plain0[c] += (rand() & 0xFFFFLL) << 32LL;
        plain0[c] += (rand() & 0xFFFFLL) << 16LL;
        plain0[c] += (rand() & 0xFFFFLL);

        cipher0[c] = encrypt(plain0[c]);
        plain1[c] = plain0[c] ^ diff;
        cipher1[c] = encrypt(plain1[c]);
    }
}

void undoLastRound(unsigned long crackedSubkey)
{
 	 int c;
 	 for(c = 0; c < numPlain; c++)
 	 {
 	        unsigned long cipherLeft0 = leftHalf(cipher0[c]);
            unsigned long cipherRight0 = rightHalf(cipher0[c]);
            unsigned long cipherLeft1 = leftHalf(cipher1[c]);
            unsigned long cipherRight1 = rightHalf(cipher1[c]);

			cipherLeft0 = cipherRight0;
			cipherLeft1 = cipherRight1;
			cipherRight0 = fBox(cipherLeft0 ^ crackedSubkey) ^ (cipher0[c] >> 32LL);
			cipherRight1 = fBox(cipherLeft1 ^ crackedSubkey) ^ (cipher1[c] >> 32LL);


			cipher0[c] = combineHalves(cipherLeft0, cipherRight0);
			cipher1[c] = combineHalves(cipherLeft1, cipherRight1);
   	 }
}

void prepForCrackingK0()
{
 	 int c;
	 for(c = 0; c < numPlain; c++)
	 {
  	  	    unsigned long cipherLeft0 = leftHalf(cipher0[c]);
            unsigned long cipherRight0 = rightHalf(cipher0[c]);
            unsigned long cipherLeft1 = leftHalf(cipher1[c]);
            unsigned long cipherRight1 = rightHalf(cipher1[c]);

			unsigned long tempLeft0 = cipherLeft0;
			unsigned long tempLeft1 = cipherLeft1;
			cipherLeft0 = cipherRight0;
			cipherLeft1 = cipherRight1;
			cipherRight0 = tempLeft0;
			cipherRight1 = tempLeft1;

			cipher0[c] = combineHalves(cipherLeft0, cipherRight0);
			cipher1[c] = combineHalves(cipherLeft1, cipherRight1);
     }
}

int main()
{

    generateSubkeys(time(NULL));
	numPlain = 12;
	unsigned long long inputDiff1 = 0x8080000080800000LL;
	unsigned long long inputDiff2 = 0x0000000080800000LL;
	unsigned long long inputDiff3 = 0x0000000002000000LL;
	unsigned long outDiff = 0x02000000L;

    printf("Retrieving Subkey 3\n");
 	chosenPlaintext(inputDiff1);
 	undoFinalOperation();
	unsigned long crackedSubkey3 = crackLastRound(outDiff);

    printf("Retrieving Subkey 2\n");
 	chosenPlaintext(inputDiff2);
 	undoFinalOperation();
 	undoLastRound(crackedSubkey3);
	unsigned long crackedSubkey2 = crackLastRound(outDiff);

    printf("Retrieving Subkey 1\n");
 	chosenPlaintext(inputDiff3);
 	undoFinalOperation();
 	undoLastRound(crackedSubkey3);
 	undoLastRound(crackedSubkey2);
	unsigned long crackedSubkey1 = crackLastRound(outDiff);

    printf("Retrieving other 3 Subkeys\n");
    undoLastRound(crackedSubkey1);
	unsigned long crackedSubkey0 = 0;
	unsigned long crackedSubkey4 = 0;
	unsigned long crackedSubkey5 = 0;

    unsigned long guessK0;
    for(guessK0 = 0; guessK0 < 0xFFFFFFFFL; guessK0++)
    {
	      unsigned long guessK4 = 0;
	      unsigned long guessK5 = 0;
 		  int c;
 		  for(c = 0; c < numPlain; c++)
 		  {
		   		unsigned long plainLeft0 = leftHalf(plain0[c]);
		   		unsigned long plainRight0 = rightHalf(plain0[c]);
		   		unsigned long cipherLeft0 = leftHalf(cipher0[c]);
		   		unsigned long cipherRight0 = rightHalf(cipher0[c]);

	 	   		unsigned long tempy0 = fBox(cipherRight0 ^ guessK0) ^ cipherLeft0;
	 	  		if (guessK4 == 0)
	 	  		{
				   guessK4 = tempy0 ^ plainLeft0;
  		           guessK5 = tempy0 ^ cipherRight0 ^ plainRight0;
			    }
			  	else if (((tempy0 ^ plainLeft0) != guessK4) || ((tempy0 ^ cipherRight0 ^ plainRight0) != guessK5))
  		        {
				 	 guessK4 = 0;
				 	 guessK5 = 0;
					  break;
 		 		}
           }
 	  	   if (guessK4 != 0)
  		   {

		   	  crackedSubkey0 = guessK0;
		   	  crackedSubkey4 = guessK4;
		   	  crackedSubkey5 = guessK5;

		   	  printf("subkey: 0x%08lx\nsubkey: 0x%08lx\nsubkey: 0x%08lx\n", guessK0, guessK4, guessK5);
		   	  break;

		   }
    }

	printf("Cracked Subkeys: \n");

	printf("%lu\n", crackedSubkey0);
	printf("%lu\n", crackedSubkey1);
	printf("%lu\n", crackedSubkey2);
	printf("%lu\n", crackedSubkey3);
	printf("%lu\n", crackedSubkey4);
	printf("%lu\n", crackedSubkey5);
	printf("\n");

    return 0;
}