#include <stdio.h>
#include <math.h>

int winner = 0;
int loser = 0;

unsigned long subkey[6];

unsigned char rotl2(unsigned char a) {return ((a << 2) | (a >> 6));}

unsigned long leftHalf(unsigned long long a) {return (a >> 32LL);}
unsigned long rightHalf(unsigned long long a) {return a;}
unsigned char sepByte(unsigned long a, unsigned char index) {return a >> (8 * index);}
unsigned long combineBytes(unsigned char b3, unsigned char b2, unsigned char b1, unsigned char b0)
{
 		 return b3 << 24L | (b2 << 16L) | (b1 << 8L) | b0;
}
unsigned long long combineHalves(unsigned long leftHalf, unsigned long rightHalf)
{
 		 return (((unsigned long long)(leftHalf)) << 32LL) | (((unsigned long long)(rightHalf)) & 0xFFFFFFFFLL);
}

unsigned char gBox(unsigned char a, unsigned char b, unsigned char mode)
{
    return rotl2(a + b + mode);
}

unsigned long fBox(unsigned long plain)
{
    unsigned char x0 = sepByte(plain, 0);
    unsigned char x1 = sepByte(plain, 1);
    unsigned char x2 = sepByte(plain, 2);
    unsigned char x3 = sepByte(plain, 3);

    unsigned char t0 = (x2 ^ x3);

    unsigned char y1 = gBox(x0 ^ x1, t0, 1);
    unsigned char y0 = gBox(x0, y1, 0);
    unsigned char y2 = gBox(t0, y1, 0);
    unsigned char y3 = gBox(x3, y2, 1);

    return combineBytes(y3, y2, y1, y0);
}

unsigned long long encrypt(unsigned long long plain)
{
    unsigned long left = leftHalf(plain);
    unsigned long right = rightHalf(plain);

    left = left ^ subkey[4];
    right = right ^ subkey[5];

    unsigned long round2Left = left ^ right;
    unsigned long round2Right = left ^ fBox(round2Left ^ subkey[0]);

    unsigned long round3Left = round2Right;
    unsigned long round3Right = round2Left ^ fBox(round2Right ^ subkey[1]);

    unsigned long round4Left = round3Right;
    unsigned long round4Right = round3Left ^ fBox(round3Right ^ subkey[2]);

    unsigned long cipherLeft = round4Left ^ fBox(round4Right ^ subkey[3]);
    unsigned long cipherRight = cipherLeft ^ round4Right;

    return combineHalves(cipherLeft, cipherRight);
}

void generateSubkeys(int seed)
{
    srand(seed);

    int c;
    for(c = 0; c <  6; c++)
        subkey[c] = (rand() << 16L) | (rand() & 0xFFFFL);
}
