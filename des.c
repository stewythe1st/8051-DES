/******************************************************************************
*	des.c
*
*	Definitions for the DES cipher algorithm.
*
*	Stuart Miller
*	Missouri S&T CpE 5420
*	Fall 2017
******************************************************************************/


/**********************************************************
*	Headers
**********************************************************/
#include "des.h"


/**********************************************************
*	Variables
**********************************************************/
#ifdef __GNUC__
	#define des_table uint8
#else
	#define des_table code uint8
#endif

des_table ip[64] = {
	58,	50,	42,	34,	26,	18,	10,	2,
	60,	52,	44,	36,	28,	20,	12,	4,
	62,	54,	46,	38,	30,	22,	14,	6,
	64,	56,	48,	40,	32,	24,	16,	8,
	57,	49,	41,	33,	25,	17,	9,	1,
	59,	51,	43,	35,	27,	19,	11,	3,
	61,	53,	45,	37,	29,	21,	13,	5,
	63,	55,	47,	39,	31,	23,	15,	7
};

des_table fp[64] = {
	40,	8,	48,	16,	56,	24,	64,	32,
	39,	7,	47,	15,	55,	23,	63,	31,
	38,	6,	46,	14,	54,	22,	62,	30,
	37,	5,	45,	13,	53,	21,	61,	29,
	36,	4,	44,	12,	52,	20,	60,	28,
	35,	3,	43,	11,	51,	19,	59,	27,
	34,	2,	42,	10,	50,	18,	58,	26,
	33,	1,	41,	9,	49,	17,	57,	25
};

des_table pc1[56] = {
	57,	49,	41,	33,	25,	17,	9,	
	1,	58,	50,	42,	34,	26,	18,	
	10,	2,	59,	51,	43,	35,	27,	
	19,	11,	3,	60,	52,	44,	36,	
	63,	55,	47,	39,	31,	23,	15,	
	7,	62,	54,	46,	38,	30,	22,	
	14,	6,	61,	53,	45,	37,	29,	
	21,	13,	5,	28,	20,	12,	4
};

des_table pc2[48] = {
	14,	17,	11,	24,	1,	5,
	3,	28,	15,	6,	21,	10,
	23,	19,	12,	4,	26,	8,
	16,	7,	27,	20,	13,	2,
	41,	52,	31,	37,	47,	55,
	30,	40,	51,	45,	33,	48,
	44,	49,	39,	56,	34,	53,
	46,	42,	50,	36,	29,	32
};

des_table e[48] = {
	32,	1,	2,	3,	4,	5,
	4,	5,	6,	7,	8,	9,
	8,	9,	10,	11,	12,	13,
	12,	13,	14,	15,	16,	17,
	16,	17,	18,	19,	20,	21,
	20,	21,	22,	23,	24,	25,
	24,	25,	26,	27,	28,	29,
	28,	29,	30,	31,	32,	1
};

des_table p[32] = {
	16,	7,	20,	21,
	29,	12,	28,	17,
	1,	15,	23,	26,
	5,	18,	31,	10,
	2,	8,	24,	14,
	32,	27,	3,	9,
	19,	13,	30,	6,
	22,	11,	4,	25
};

des_table s1[64] = {
	14,	4,	13,	1,	2,	15,	11,	8,
	3,	10,	6,	12,	5,	9,	0,	7,
	0,	15,	7,	4,	14,	2,	13,	1,
	10,	6,	12,	11,	9,	5,	3,	8,
	4,	1,	14,	8,	13,	6,	2,	11,
	15,	12,	9,	7,	3,	10,	5,	0,
	15,	12,	8,	2,	4,	9,	1,	7,
	5,	11,	3,	14,	10,	0,	6,	13
};

des_table s2[64] = {
	15,	1,	8,	14,	6,	11,	3,	4,
	9,	7,	2,	13,	12,	0,	5,	10,
	3,	13,	4,	7,	15,	2,	8,	14,
	12,	0,	1,	10,	6,	9,	11,	5,
	0,	14,	7,	11,	10,	4,	13,	1,
	5,	8,	12,	6,	9,	3,	2,	15,
	13,	8,	10,	1,	3,	15,	4,	2,
	11,	6,	7,	12,	0,	5,	14,	9
};

des_table s3[64] = {
	10,	0,	9,	14,	6,	3,	15,	5,
	1,	13,	12,	7,	11,	4,	2,	8,
	13,	7,	0,	9,	3,	4,	6,	10,
	2,	8,	5,	14,	12,	11,	15,	1,
	13,	6,	4,	9,	8,	15,	3,	0,
	11,	1,	2,	12,	5,	10,	14,	7,
	1,	10,	13,	0,	6,	9,	8,	7,
	4,	15,	14,	3,	11,	5,	2,	12
};

des_table s4[64] = {
	7,	13,	14,	3,	0,	6,	9,	10,
	1,	2,	8,	5,	11,	12,	4,	15,
	13,	8,	11,	5,	6,	15,	0,	3,
	4,	7,	2,	12,	1,	10,	14,	9,
	10,	6,	9,	0,	12,	11,	7,	13,
	15,	1,	3,	14,	5,	2,	8,	4,
	3,	15,	0,	6,	10,	1,	13,	8,
	9,	4,	5,	11,	12,	7,	2,	14
};

des_table s5[64] = {
	2,	12,	4,	1,	7,	10,	11,	6,
	8,	5,	3,	15,	13,	0,	14,	9,
	14,	11,	2,	12,	4,	7,	13,	1,
	5,	0,	15,	10,	3,	9,	8,	6,
	4,	2,	1,	11,	10,	13,	7,	8,
	15,	9,	12,	5,	6,	3,	0,	14,
	11,	8,	12,	7,	1,	14,	2,	13,
	6,	15,	0,	9,	10,	4,	5,	3
};

des_table s6[64] = {
	12,	1,	10,	15,	9,	2,	6,	8,
	0,	13,	3,	4,	14,	7,	5,	11,
	10,	15,	4,	2,	7,	12,	9,	5,
	6,	1,	13,	14,	0,	11,	3,	8,
	9,	14,	15,	5,	2,	8,	12,	3,
	7,	0,	4,	10,	1,	13,	11,	6,
	4,	3,	2,	12,	9,	5,	15,	10,
	11,	14,	1,	7,	6,	0,	8,	13
};

des_table s7[64] = {
	4,	11,	2,	14,	15,	0,	8,	13,
	3,	12,	9,	7,	5,	10,	6,	1,
	13,	0,	11,	7,	4,	9,	1,	10,
	14,	3,	5,	12,	2,	15,	8,	6,
	1,	4,	11,	13,	12,	3,	7,	14,
	10,	15,	6,	8,	0,	5,	9,	2,
	6,	11,	13,	8,	1,	4,	10,	7,
	9,	5,	0,	15,	14,	2,	3,	12
};

des_table s8[64] = {
	13,	2,	8,	4,	6,	15,	11,	1,
	10,	9,	3,	14,	5,	0,	12,	7,
	1,	15,	13,	8,	10,	3,	7,	4,
	12,	5,	6,	11,	0,	14,	9,	2,
	7,	11,	4,	1,	9,	12,	14,	2,
	0,	6,	10,	13,	15,	3,	5,	8,
	2,	1,	14,	7,	4,	10,	8,	13,
	15,	12,	9,	0,	3,	5,	6,	11
};

des_table* sBoxes[8] = {s1, s2, s3, s4, s5, s6, s7, s8};
des_table keyShifts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};


/**********************************************************
*	des(uint8* msg, uint8* key, uint8* output, uint8 type)
*	Runs the DES encryption/decryption algorithm. 
*	 @param msg an 8-byte array containing the input
*	 @param key an 8-byte array containing the key
*	 @param output an 8-byte array to place the output into
*	 @param type either ENCRYPT or DECRYPT
**********************************************************/
void des(uint8* msg, uint8* key, uint8* output, uint8 type){
		
	// Variables
	uint8 i,j;
	uint8 keyTemp[8], keyLeft[4], keyRight[4], keyLeftShifted[4], keyRightShifted[4];
	uint8 msgTemp[8], msgLeft1[4], msgLeft2[4], msgRight1[4], msgRight2[4], msgRightExp1[6], msgRightExp2[6];
	uint8 k1[6], k2[6], k3[6], k4[6], k5[6], k6[6], k7[6], k8[6], k9[6], k10[6], k11[6], k12[6], k13[6], k14[6], k15[6], k16[6];
	uint8* keys[16] = {k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16};
	
	// Generate keys (x16)
	permute(key, keyTemp, pc1, 56);
	split(keyTemp, keyLeft, keyRight, 28);
	for(i = 0; i < 16; i++){
		shift(keyLeft, keyLeftShifted, keyShifts[i], 28);
		shift(keyRight, keyRightShifted, keyShifts[i], 28);
		combine(keyLeftShifted, keyRightShifted, keyTemp, 28);
		if(type == ENCRYPT)
			permute(keyTemp, keys[i], pc2, 48);
		else // type == DECRYPT
			permute(keyTemp, keys[15 - i], pc2, 48);
		for(j = 0; j < 4; j++){
			keyLeft[j] = keyLeftShifted[j];
			keyRight[j] = keyRightShifted[j];
		}
	}
	
	// Run encryptions rounds (x16)
	permute(msg, msgTemp, ip, 64);
	split(msgTemp, msgLeft1, msgRight1, 32);
	for(i = 0; i < 16; i++){
		permute(msgRight1, msgRightExp1, e, 48);
		for(j = 0; j < 4; j++){
			msgLeft2[j] = msgRight1[j];
		}
		for(j = 0; j < 6; j++){
			msgRightExp2[j] = msgRightExp1[j] ^ keys[i][j];
		}
		sBoxTransform(msgRightExp2, msgRight1);
		permute(msgRight1, msgRight2, p, 32);
		for(j = 0; j < 4; j++){
			msgRight1[j] = msgRight2[j] ^ msgLeft1[j];
		}
		for(j = 0; j < 4; j++){
			msgLeft1[j] = msgLeft2[j];
		}
	}
	
	// Swap and apply final permutation
	combine(msgRight1, msgLeft1, msgTemp, 32);
	permute(msgTemp, output, fp, 64);
	
	return;
}


/**********************************************************
*	permute(uint8* input, uint8* output, uint8* table, uint8 tableSz)
*	Rearranges the bits of input according to a transposition table.
*	 @param input an array containing the input
*	 @param output an array to place the output into
*	 @param table an array containing the transposition table
*	 @param tableSz the length of the transposition table array in bytes
**********************************************************/
void permute(uint8* input, uint8* output, uint8* table, uint8 tableSz) {
	
	// Variables
	uint8 i;
	uint8 inputBit;
	
	// Walk down table and write bits to output
	for(i=0;i<tableSz;i++){
		if(i % 8 == 0)
			output[i / 8] = 0x00;
		inputBit = table[ i ] - 1;
		if(input[inputBit / 8] & (0x80 >> (inputBit % 8)))
			output[i / 8] |= (0x80 >> (i % 8));
	}
	
	return;
}


/**********************************************************
*	split(uint8* input, uint8* left, uint8* right, uint8 outputSz)
*	Splits an array into two halves. Output halves do not necessarily
*	have to be byte-aligned. Output will be left-aligned.
*	 @param input an array containing the input
*	 @param left an array to place the left output into
*	 @param right an array to place the right output into
*	 @param outputSz the desired size of each output array in bits
**********************************************************/
void split(uint8* input, uint8* left, uint8* right, uint8 outputSz) {
	
	// Variables
	uint8 i, j, arrLen, shiftAmt;
	
	// Calculate position of half-array split and necessary shifts
	arrLen = outputSz / 8;
	if(outputSz % 8 != 0)
		arrLen++;
	shiftAmt = outputSz % 8;	
	
	// Walk down input and assign to each output half
	for(i = 0; i < outputSz; i+= 8){
		j = i / 8;
		left[j] = input[j];
		right[j] = (input[j + arrLen - 1] << (8 - shiftAmt)) | (input[j + arrLen] >> shiftAmt);
	}
	
	return;
}


/**********************************************************
*	shift(uint8* input, uint8* output, uint8 shiftAmt, uint8 inputSz)
*	Rotates an array left by the specified amount. Shift amount 
*	does not necessarily have to be byte-aligned. Output will
*	be left-aligned.
*	 @param input an array containing the input
*	 @param output an array to place the output into
*	 @param shiftAmt distance to left-shift
*	 @param inputSz length of input array in bits
**********************************************************/
void shift(uint8* input, uint8* output, uint8 shiftAmt, uint8 inputSz) {
	
	// Variables
	uint8 i, j;
	
	// Shift the main body over
	for(i = 0; i < inputSz; i+= 8){
		j = i / 8;
		output[j] = input[j] << shiftAmt;
		output[j] |= (input[j + 1] >> (8 - shiftAmt));
	}
	
	// Rotate the first bit(s) around to the end
	output[j] &= (0xFF << (shiftAmt + 8 - (inputSz % 8)));
	output[j] |= (input[0] >> ((inputSz % 8) - shiftAmt));
	
	return;
}


/**********************************************************
*	combine(uint8* inputLeft, uint8* inputRight, uint8* output, uint8 inputSz)
*	Merges two half-arrays into one. Input does not necessarily
*	have to be byte-aligned. Output will be left-aligned.
*	 @param inputLeft an array containing the left input
*	 @param inputRight an array containing the right input
*	 @param output an array to place the output into
*	 @param inputSz length of each input array in bits
**********************************************************/
void combine(uint8* inputLeft, uint8* inputRight, uint8* output, uint8 inputSz) {
	
	// Variables
	uint8 i, j, arrLen;
	
	// Calculate position of half-array split
	arrLen = inputSz / 8;
	if(inputSz % 8 != 0)
		arrLen++;
	
	// Copy left half over (no shifts necessary)
	for(i = 0; i < inputSz; i+= 8){
		j = i / 8;
		output[j] = inputLeft[j];
	}
	
	// If not byte-aligned, erase the excess bits
	if(inputSz % 8 != 0)
		output[j] &= (0xFF << (8 - (inputSz % 8)));
	
	// Shift and copy over right half
	for(i = 0; i < inputSz; i+= 8){
		j = i / 8;
		output[j + arrLen - 1] |= inputRight[j] >> (8 - (inputSz % 8));
		output[j + arrLen] = inputRight[j] << (inputSz % 8);
	}
	
	return;
}


/**********************************************************
*	sBoxTransform(uint8* input, uint8* output)
*	Applies S-Box transformations on an input.
*	 @param input a 6-byte array containing the input
*	 @param output a 4-byte array to place the output into
**********************************************************/
void sBoxTransform(uint8* input, uint8* output) {
	
	// Variables
	uint8 temp;
	
	// Split each 8-bit byte into 6-bit left-aligned values
	// then send to S-Box conversion		
	temp = input[0];
	output[0] = getSBoxVal(temp, sBoxes[0]) << 4;
	
	temp = (input[0] << 6) | (input[1] >> 2);
	output[0] |= getSBoxVal(temp, sBoxes[1]);
	
	temp = (input[1] << 4) | (input[2] >> 4);
	output[1] = getSBoxVal(temp, sBoxes[2]) << 4;
	
	temp = input[2] << 2;
	output[1] |= getSBoxVal(temp, sBoxes[3]);

	temp = input[3];
	output[2] = getSBoxVal(temp, sBoxes[4]) << 4;
	
	temp = (input[3] << 6) | (input[4] >> 2);
	output[2] |= getSBoxVal(temp, sBoxes[5]);
	
	temp = (input[4] << 4) | (input[5] >> 4);
	output[3] = getSBoxVal(temp, sBoxes[6]) << 4;
	
	temp = input[5] << 2;
	output[3] |= getSBoxVal(temp, sBoxes[7]);
	
	return;	
}


/**********************************************************
*	getSBoxVal(uint8 input, uint8* sBox)
*	Applies S-Box transformations. Bits 0 and 5 specify the 
*	row, while bits 1-4 specify the column in a 16x4 S-Box
*	 @param input a 6-bit left aligned value
*	 @param sBox the address of the S-Box array to use
*	 @return the 4-bit left-aligned output value
**********************************************************/
uint8 getSBoxVal(uint8 input, uint8* sBox) {
	
	// Variables
	uint8 row, column, idx;
	
	// Get first and last bits for row
	row = ((input & 0x80) >> 6) | ((input & 0x04) >> 2);
	
	// Get middle bits for column
	column = (input & 0x78) >> 3;
	
	// Convert to table index
	idx = (row * 16) + column;
	
	// Return S-Box value
	return sBox[idx];
}


void encrypt_3des(uint8* input, uint8* key, uint8* output) {
	uint8 temp[8];
	encrypt(input, key, output);
	decrypt(output, key + 7, temp);
	encrypt(temp, key + 14, output);
}


void decrypt_3des(uint8* input, uint8* key, uint8* output) {
	uint8 temp[8];
	decrypt(input, key + 14, output);
	encrypt(output, key + 7, temp);
	decrypt(temp, key, output);
}

