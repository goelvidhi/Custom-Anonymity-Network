#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "des.h"


//DES_key_schedule schedule;

unsigned char ivdata[8];
FILE *fp;
int size_k;


void readKey(char *device_name, unsigned char *key){
    if (!device_name || !key){
        return;
    }
	char filename[20];
	sprintf(filename, "key_%s", device_name);
    fp = fopen(filename, "r");
    fread(key, size_k, 1, fp);
    fclose(fp);
}

void writeKey(char * device_name, unsigned char* sym_key){
    if (!device_name || !sym_key){
        return;
    }
	char filename[20];
    sprintf(filename, "key_%s", device_name);
    //printf("FILE %s \n", filename);
    fp = fopen(filename, "w+");
	size_k = sizeof(sym_key);
    fwrite(sym_key, 1, sizeof(sym_key), fp);
    fclose(fp);
}

int initDes(unsigned char* str, DES_key_schedule* schedule){
	//fprintf(stdout, "key = %s\n", str);
    int i, ret;
	unsigned char key[8];
    DES_string_to_key(str, &key);
    ret = DES_set_key_checked(key, schedule);
    for (i = 0; i < 8 ; i++)
        ivdata[i] = 0x00;
	return ret;
}

void encrypt(const unsigned char *pt, unsigned char *ct, DES_key_schedule* schedule, long length){
    DES_cbc_encrypt(pt, ct, length, schedule, &ivdata, 1);
}

void decrypt(const unsigned char *ct, unsigned char *pt, DES_key_schedule* schedule, long length){
    DES_cbc_encrypt(ct, pt, length, schedule, &ivdata, 0);
}

