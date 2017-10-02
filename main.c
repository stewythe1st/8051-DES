/******************************************************************************
*	main.c
*
*	Main function for the DES cipher algorithm.
*
*	Stuart Miller
*	Missouri S&T CpE 5420
*	Fall 2017
******************************************************************************/


/**********************************************************
*	Headers
**********************************************************/
#include <intrins.h>
#include "des.h"
#include "types.h"


/**********************************************************
*	Main Function
**********************************************************/
void main(void){

	// Variables
	uint8 plainText[16] = "Hello world!";
	uint8 cipherText[16];
	uint8 decryptedText[16];
	uint8 key[8] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
	
	// Encrypt
	encrypt(plainText, key, cipherText);
	encrypt(plainText + 8, key, cipherText + 8);
		
	// Decrypt
	decrypt(cipherText, key, decryptedText);
	decrypt(cipherText + 8, key, decryptedText + 8);
	
	return;
}


