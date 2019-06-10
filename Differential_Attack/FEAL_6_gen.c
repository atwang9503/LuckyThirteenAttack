#include <stdio.h>
#include <math.h>

unsigned long long shiftLeft2(unsigned long a)
{
    unsigned long b;

    unsigned long carry = (a >> 7LL);
    carry &= 0x1LL;
    b = a << 1LL;
    b += carry;
    b &= 0xFFLL;

    carry = (b >> 7LL);
    carry &= 0x1LL;
    b <<= 1LL;
    b += carry;
    b &= 0xFFLL;

    return b;
}

unsigned long gBox(unsigned long a, unsigned long b, unsigned long mode)
{
    return shiftLeft2((a + b + mode) % 256LL);
}

unsigned long fBox(unsigned long plain)
{
    unsigned long x0 = plain & 0xFFL;
    unsigned long x1 = (plain >> 8L) & 0xFFL;
    unsigned long x2 = (plain >> 16L) & 0xFFL;
    unsigned long x3 = (plain >> 24L) & 0xFFL;

    unsigned long t0 = (x2 ^ x3);
    unsigned long t1 = gBox(x0 ^ x1, t0, 1L);

    unsigned long y0 = gBox(x0, t1, 0L);
    unsigned long y1 = t1;
    unsigned long y2 = gBox(t0, t1, 0L);
    unsigned long y3 = gBox(x3, y2, 1L);

    unsigned long ret =  y3 << 24L;
                 ret += (y2 << 16L);
                 ret += (y1 << 8L);
                 ret += y0;

    return ret;
}

unsigned long long encrypt(unsigned long long plain)
{
    unsigned long left = (plain >> 32LL) & 0xFFFFFFFFLL;
    unsigned long right = plain & 0xFFFFFFFFLL;

    left = left ^ subkey[4];
    right = right ^ subkey[5];

    unsigned long round2Left = left ^ right;
    unsigned long round2Right = left ^ fBox(round2Left ^ subkey[0]);

    unsigned long round3Left = round2Right;
    unsigned long round3Right = round2Left ^ fBox(round2Right ^ subkey[1]);

    unsigned long round4Left = round3Right;
    unsigned long round4Right = round3Left ^ fBox(round3Right ^ subkey[2]);

    unsigned long round5Left = round4Right;
    unsigned long round5Right = round4Left ^ fBox(round4Right ^ subkey[3]);

    unsigned long round6Left = round5Right;
    unsigned long round6Right = round5Left ^ fBox(round5Right ^ subkey[6]);

    unsigned long cipherLeft = round6Left ^ fBox(round6Right ^ subkey[7]);
    unsigned long cipherRight = cipherLeft ^ round6Right;

    unsigned long long ret = (((unsigned long long)(cipherLeft)) << 32LL);
    ret += (((unsigned long long)(cipherRight)) & 0xFFFFFFFFLL);

    return ret;
}

unsigned long long decrypt(unsigned long long cipher)
{
    unsigned long left = (cipher >> 32LL) & 0xFFFFFFFFLL;
    unsigned long right = cipher & 0xFFFFFFFFLL;

    unsigned long round5Left = left ^ right;
    unsigned long round5Right = left ^ fBox(round5Left ^ subkey[7]);

    unsigned long round4Left = round5Right;
    unsigned long round4Right = round5Left ^ fBox(round4Left ^ subkey[6]);

    unsigned long round3Left = round4Right;
    unsigned long round3Right = round4Left ^ fBox(round3Left ^ subkey[3]);

    unsigned long round2Left = round3Right;
    unsigned long round2Right = round3Left ^ fBox(round2Left ^ subkey[2]);

    unsigned long round1Left = round2Right;
    unsigned long round1Right = round2Left ^ fBox(round1Left ^ subkey[1]);

    unsigned long plainLeft = round1Left ^ fBox(round1Right ^ subkey[0]);
    unsigned long plainRight = plainLeft ^ round1Right;

    plainLeft ^= subkey[4];
    plainRight ^= subkey[5];

    unsigned long long ret = (((unsigned long long)(plainLeft)) << 32LL);
    ret += (((unsigned long long)(plainRight)) & 0xFFFFFFFFLL);

    return ret;
}


void generateSubkeys(int seed)
{
    srand(time(NULL));

    int c;
    for(c = 0; c < 8; c++)
    {
        subkey[c] = rand() << 16L;
        subkey[c] += rand() & 0xFFFFL;
    }
}
