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
#include "REG932.h"
#include "defs.h"
#include "des.h"
#include "types.h"
#include "uart.h"


/**********************************************************
*	Main Function
**********************************************************/
void main(void){
	
	// Variables
	uint8 plainText[16] = "Hello world!";
	uint8 cipherText[16];
	uint8 decryptedText[16];
	uint8 key[8] = "testtest";
	
	// Set Ports to BiDirectional
	P2M1 = 0x00;
	P1M1 = 0x00;
	P0M1 = 0x00;
	
	// Initialize UART
	uart_init();
	EA = 1;
		
	while(1){
		// UART decryption timing test
		if(!SW1){
			LED1 = LED_ON;
			encrypt(plainText, key, cipherText);
			LED1 = LED_OFF;
		}		
	}
	
	// Encrypt
	encrypt(plainText, key, cipherText);
	encrypt(plainText + 8, key, cipherText + 8);
		
	// Decrypt
	decrypt(cipherText, key, decryptedText);
	decrypt(cipherText + 8, key, decryptedText + 8);
	
	return;
}


