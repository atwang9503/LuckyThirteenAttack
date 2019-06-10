#include <stdio.h>
#include <math.h>

unsigned long subkey[7];

int numPlain;
unsigned long long plain0[10000];
unsigned long long cipher0[10000];
unsigned long long plain1[10000];
unsigned long long cipher1[10000];

unsigned long long plain2[10000];
unsigned long long cipher2[10000];
unsigned long long plain3[10000];
unsigned long long cipher3[10000];

unsigned long key3winner;

void chosenPlaintext(unsigned long long diff)
{
    srand(time(NULL));

    printf("Plaintext Input Differential = 0x%llx\n", diff);

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

int main()
{
    generateSubkeys(time(NULL));

    numPlain = 6;
    chosenPlaintext(0x0200000282808082LL);

    unsigned long startTime = time(NULL);

    cipher2[3] = cipher0[3] ^ 0x0200000282808082LL;
    plain2[3] = decrypt(cipher2[3]);
    cipher3[3] = cipher1[3] ^ 0x0200000282808082LL;
    plain3[3] = decrypt(cipher3[3]);


    printf("Boomerang Differential Result = 0x%llx\n", plain2[3] ^ plain3[3]);

    //crackSubkey3ULTRA();

    unsigned long endTime = time(NULL);

    while(1){}

    return 0;
}
