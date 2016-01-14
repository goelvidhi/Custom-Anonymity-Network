/**
 * CS 558L Final Project
 *
 *
 */

#ifndef _DES_H_
#define _DES_H_

#include <openssl/des.h>

#define KEY_SIZE			4
void readKey(char *, unsigned char *);
void writeKey(char *, unsigned char*);
int initDes(unsigned char* , DES_key_schedule* );
void encrypt(const unsigned char *, unsigned char *, DES_key_schedule *, long);
void decrypt(const unsigned char *, unsigned char *, DES_key_schedule *, long);

#endif
