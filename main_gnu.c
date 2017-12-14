/******************************************************************************
*	main.c
*
*	Main function for the DES cipher algorithm for the GNU C compiler.
*
*	Stuart Miller
*	Missouri S&T CpE 5420
*	Fall 2017
******************************************************************************/


/**********************************************************
*	Headers
**********************************************************/
#include <sys/time.h>
#include <stdio.h>
#include <algorithm>
#include "des.h"
#include "types.h"


/**********************************************************
*	Main Function
**********************************************************/
int main (int argc, char *argv[]){
	
	// Variables
	uint8 plainText[9];// = "Hello world!";
	uint8 cipherText[8];
	uint8 decryptedText[8];
	uint8* key;
	double secs = 0;
	struct timeval start, stop, global_start, global_stop;
	
	if(argc != 3){
		printf("----------------------------------\n");
		printf("  Error: incorrect usage!\n");
		printf("----------------------------------\n");
		printf("  encrypt.exe [key] [plainText]\n");
		printf("  decrypt.exe [key] [cipherText]\n");
		printf("----------------------------------\n");
		exit(1);
	}
	
	for(int i = 0; i < 8; i++){
		if(argv[1][i] == '\0'){
			printf("----------------------------------\n");
			printf("  Error: key must be 8 chars long!\n");
			printf("----------------------------------\n");
			exit(1);
		}
	}
	
	key = (uint8*)argv[1];
	key[8] = '\0';
	
	bool end = false;
	int round = 0;
	gettimeofday(&global_start, NULL);
	while(!end){
		if(argv[2][round*8] == '\0')
			break;
		for(int i = 0; i < 8; i++){
			if(argv[2][i+(round*8)] != '\0' && !end){
				plainText[i] = argv[2][i+(round*8)];
			}
			else{
				end = true;
				plainText[i] = 'x';
			}
		}
		plainText[8] = '\0';
		/*
		// Do encryption
		gettimeofday(&start, NULL);
		for(int i=0;i<100000;i++){
			*/
			encrypt(plainText, key, cipherText);
			/*
		}
		gettimeofday(&stop, NULL);
		secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 + (double)(stop.tv_sec - start.tv_sec);
		
		// Print output
		printf("Round %i:\n",round);
		printf("\tKey:        %s\n",key);
		printf("\tPlaintext:  %s\n",plainText);
		printf("\tCiphertext: ");
		for(int i=0;i<8;i++){
			printf("%X", cipherText[i]);
		}
		printf("\n\tTime:       %f\n",secs);
		*/
		
		round++;
	}
	
	gettimeofday(&global_stop, NULL);
	secs = (double)(global_stop.tv_usec - global_start.tv_usec) / 1000000 + (double)(global_stop.tv_sec - global_start.tv_sec);
	printf("\n\tTime:       %f\n",secs);
	
	// Encrypt
	encrypt(plainText, key, cipherText);
	encrypt(plainText + 8, key, cipherText + 8);
		
	// Decrypt
	decrypt(cipherText, key, decryptedText);
	decrypt(cipherText + 8, key, decryptedText + 8);
	
	return 0;
}


