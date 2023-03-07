/*
 * AES_128.h
 *
 */

#ifndef AES_128_H_
#define AES_128_H_
#include "stdio.h"
#include "string.h"

// #include "xil_printf.h"

/**
 * Debug levels
 */

#define AES_PRINT_MAIN    (1<<0)	//change to 1<<0 to print
                                    //change to 0<<0 to disable printing detail
#define AES_PRINT_DETAILS (1<<1)	//change to 1<<1 to print details
                                    //change to 0<<1 to disable printing details

#define AES_PRINT (AES_PRINT_MAIN | AES_PRINT_DETAILS)

/**********************************************************************
 * Functions for key expansion
 *********************************************************************/

void ExpandKey (unsigned char Key[][4], unsigned char ExpandedKey[][4][4]);
void AddRoundKey (unsigned char Key[][4], unsigned char StateArray[][4]);

/**********************************************************************
 * Functions for AES encryption
 **********************************************************************/

void SubBytes (unsigned char StateArray[][4]);
void ShiftRows (unsigned char StateArray[][4]);
void MixColumns (unsigned char StateArray[][4]);

unsigned char SubBytesCalculated (unsigned char StateArray);

/**********************************************************************
 * Functions for AES decryption
 **********************************************************************/
 
void InvSubBytes (unsigned char StateArray[][4]);
void InvShiftRows (unsigned char StateArray[][4]);
void InvMixColumns (unsigned char StateArray[][4]);
 
/**********************************************************************
 * Miscellaneous Functions 
 **********************************************************************/

void AES_printf (unsigned char StateArray[][4]);

#endif /* AES_128_H_ */
