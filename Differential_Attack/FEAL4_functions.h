#ifndef FEAL4_FUNCTIONS
#define FEAL4_FUNCTIONS

unsigned char rotl2(unsigned char a);
unsigned long leftHalf(unsigned long long a);
unsigned long rightHalf(unsigned long long a);
unsigned char sepByte(unsigned long a, unsigned char index);
unsigned long combineBytes(unsigned char b3, unsigned char b2, unsigned char b1, unsigned char b0);
unsigned long long combineHalves(unsigned long leftHalf, unsigned long rightHalf);
unsigned char gBox(unsigned char a, unsigned char b, unsigned char mode);
unsigned long fBox(unsigned long plain);
unsigned long long encrypt(unsigned long long plain);
void generateSubkeys(int seed);

#endif