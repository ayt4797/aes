#include "AES_128.h"
#include "eea.c"
#include "stdint.h"
#define POLY 283
#define SHIFTARR 0xF1
#define SCONST 0x63
#define xil_printf(...) printf(__VA_ARGS__)
const unsigned char SBox[256] = {
 // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,   //0
 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,   //1
 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,   //2
 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,   //3
 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,   //4
 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,   //5
 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,   //6
 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,   //7
 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,   //8
 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,   //9
 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,   //A
 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,   //B
 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,   //C
 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,   //D
 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,   //E
 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F

//TODO: Put inverse SBox Table here
const unsigned int invMult =0x0e0b0d09;


const unsigned char RCon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

#define xTime(x) ((x<<1) ^ ((x & 0x080) ? 0x1b : 0x00))

/**********************************************************************
 * Functions for key expansion
 *********************************************************************/
void ExpandKey (unsigned char Key[][4], unsigned char ExpandedKey[][4][4])
{
	unsigned char TempKey[4][4];
	memset(TempKey, 4*4*sizeof (unsigned char),0);
	unsigned char TempKeyCol[4];
	memset(TempKeyCol, 4*sizeof (unsigned char),0);
	int i,j;

	// Encryption Key copied to Expanded Key [0]
	memcpy(ExpandedKey[0], Key, 4 * 4 * sizeof(unsigned char));

	for (i=1; i<11; i++){
		// W3 copied to TempKeyRow with rotation
		TempKeyCol[0]=ExpandedKey[i-1][1][3];
		TempKeyCol[1]=ExpandedKey[i-1][2][3];
		TempKeyCol[2]=ExpandedKey[i-1][3][3];
		TempKeyCol[3]=ExpandedKey[i-1][0][3];

		// sBox applied
		TempKeyCol[0]=SBox[ TempKeyCol[0] ];
		TempKeyCol[1]=SBox[ TempKeyCol[1] ];
		TempKeyCol[2]=SBox[ TempKeyCol[2] ];
		TempKeyCol[3]=SBox[ TempKeyCol[3] ];

		// Rcon applied
		TempKeyCol[0]^=RCon[i-1];

		// XOR
		for(j=0; j<4; j++){
			TempKeyCol[0] = TempKeyCol[0]^ExpandedKey[i-1][0][j];
			TempKeyCol[1] = TempKeyCol[1]^ExpandedKey[i-1][1][j];
			TempKeyCol[2] = TempKeyCol[2]^ExpandedKey[i-1][2][j];
			TempKeyCol[3] = TempKeyCol[3]^ExpandedKey[i-1][3][j];

			ExpandedKey[i][0][j] = TempKeyCol[0];
			ExpandedKey[i][1][j] = TempKeyCol[1];
			ExpandedKey[i][2][j] = TempKeyCol[2];
			ExpandedKey[i][3][j] = TempKeyCol[3];
		}
	}
}

void AddRoundKey (unsigned char Key[][4], unsigned char StateArray[][4])
{
	int i,j;
	for(i=0; i<4; i++)
		for(j=0; j<4; j++)
			StateArray[i][j] ^= Key[i][j];
}

/**********************************************************************
 * Functions for AES encryptoin
 **********************************************************************/
 
void SubBytes (unsigned char StateArray[][4])
{
	int i,j;
	for(i=0; i<4; i++)
		for(j=0; j<4; j++){
			//StateArray[i][j]= SBox[StateArray[i][j]];
			StateArray[i][j] = SubBytesCalculated(StateArray[i][j]);
		}
}


void ShiftRows (unsigned char StateArray[][4])
{
	unsigned char x;
	// Row#1 - rotate 1 column to the left
	x = StateArray[1][0];
	StateArray[1][0] = StateArray[1][1];
	StateArray[1][1] = StateArray[1][2];
	StateArray[1][2] = StateArray[1][3];
	StateArray[1][3] = x;
	// Row#2 - rotate 2 column to the left
	x = StateArray[2][0];
	StateArray[2][0] = StateArray[2][2];
	StateArray[2][2] = x;
	x = StateArray[2][1];
	StateArray[2][1] = StateArray[2][3];
	StateArray[2][3] = x;
	// Row#3 - rotate 3 column to the left
	x = StateArray[3][3];
	StateArray[3][3] = StateArray[3][2];
	StateArray[3][2] = StateArray[3][1];
	StateArray[3][1] = StateArray[3][0];
	StateArray[3][0] = x;
}

void MixColumns (unsigned char StateArray[][4])
{
	int i;
	unsigned char StateArrayTmp[4][4];

	for(i=0;i<4;i++){
		StateArrayTmp[0][i] =
				xTime(StateArray[0][i])^xTime(StateArray[1][i])^StateArray[1][i]^
				StateArray[2][i]^StateArray[3][i];
		StateArrayTmp[1][i] =
				StateArray[0][i]^xTime(StateArray[1][i])^xTime(StateArray[2][i])^
				StateArray[2][i]^StateArray[3][i];
		StateArrayTmp[2][i] =
				StateArray[0][i]^StateArray[1][i]^xTime(StateArray[2][i])^
				xTime(StateArray[3][i])^StateArray[3][i];
		StateArrayTmp[3][i] =
				xTime(StateArray[0][i])^StateArray[0][i]^StateArray[1][i]^
				StateArray[2][i]^xTime(StateArray[3][i]);
	}

	memcpy(StateArray, StateArrayTmp, 4 * 4 * sizeof(unsigned char));
}


/**********************************************************************
 * Functions for Sbox calculation
 **********************************************************************/

/*
        ^
 * This function calculates the SBox value on the fly rather than using the table and performing a lookup
 */
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

unsigned char circShift(unsigned char leftVal, unsigned char rightVal){
	unsigned char temp =0;
	for(int i=0;i<rightVal;i++){
		temp = (leftVal&128); //get msb
		leftVal<<=1;
		if(temp)
			leftVal+=1;
	}
	return leftVal;
}
unsigned int circShiftByte(unsigned int leftVal, unsigned int rightVal){
	unsigned int temp =0;
	for(int i=0;i<rightVal;i++){
		temp = (leftVal&0xff000000); //get MSB
	//	printf("t: %x ",temp);
		leftVal<<=8;
		if(temp)
			leftVal+=(temp>>24);
	}
	return leftVal;
}


unsigned char SubBytesCalculated (unsigned char StateArray)
{
	if(StateArray==0)
		return 0x63;
	
	unsigned int b=0;
//	eea(StateArray,POLY,&b);
	b=inverseTest(StateArray);
//	if(mult(b,StateArray,POLY)!=1){
//		printf("HMMMM");
//	}
//	int s1 = add(b,circShift (b,1));
//	int s2 = add(s1,circShift (b,2));
//	int s3 = add(s2,circShift (b,3));
//	int s4 = add(s3,circShift (b,4));
//	int s5 = add(s4,StateArray);
//	if(s5>255){
//		printf("FCK");
//		exit(-99);
//	}
	
	printf("b: %d",b);
fflush(stdout);
	unsigned char r= circShift(b,1)^circShift(b,2)^circShift(b,3)^circShift(b,4)^b^SCONST;
//	unsigned char r = StateArray^b^ROTL8(b,1)^ROTL8(b,2)^ROTL8(b,3)^ROTL8(b,4);
	return r;
//	return s5;
}


/**********************************************************************
 * Functions for AES decryption
 **********************************************************************/
 


void InvSubBytes (unsigned char StateArray[][4])
{
	
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			if(StateArray[i][j]==0x63){
				StateArray[i][j]=0x0;
				break;
			}
			unsigned char b=(StateArray[i][j]);
			StateArray[i][j] = circShift(b,1)^circShift(b,3)^circShift(b,6)^0x5;

			StateArray[i][j] =inverseTest(StateArray[i][j]);
		}
	}
}

void InvShiftRows (unsigned char StateArray[][4])
{
   	unsigned char x;
	// Row#1 - rotate 1 column to the left
	x = StateArray[1][3];
	StateArray[1][3] = StateArray[1][2];
	StateArray[1][2] = StateArray[1][1];
	StateArray[1][1] = StateArray[1][0];
	StateArray[1][0] = x;
	// Row#2 - rotate 2 column to the left
	x = StateArray[2][0];
	StateArray[2][0] = StateArray[2][2];
	StateArray[2][2] = x;
	x = StateArray[2][1];
	StateArray[2][1] = StateArray[2][3];
	StateArray[2][3] = x;
	// Row#3 - rotate 3 column to the left
	x = StateArray[3][1];
	StateArray[3][1] = StateArray[3][2];
	unsigned char y = StateArray[3][3];
	StateArray[3][3] = StateArray[3][0];
	StateArray[3][2] = y;
	StateArray[3][0] = x;


}

void InvMixColumns (unsigned char StateArray[][4])
{
	unsigned int temp = invMult;
	unsigned char StateArrayTmp[4][4];
	unsigned char invMultArray[4][4];
		    				             
	for(int i=0;i<4;i++){				     //0x090b0d09
		invMultArray[i][3] = (circShiftByte(invMult,i)&(0xff000000))>>24;
		invMultArray[i][2] = (circShiftByte(invMult,i)&(0x00ff0000))>>16;
		invMultArray[i][1] = (circShiftByte(invMult,i)&(0x0000ff00))>>8;
		invMultArray[i][0] = circShiftByte(invMult,i)&(0x000000ff);
		
	
	}
//	for (int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			StateArrayTmp[0][j]=mult(StateArray[0][j],invMultArray[0][j],POLY)^mult(StateArray[1][j],invMultArray[1][j],POLY)^mult(StateArray[2][j],invMultArray[2][j],POLY)^mult(StateArray[3][j],invMultArray[3][j],POLY);

			StateArrayTmp[1][j]=mult(StateArray[1][0],invMultArray[1][0],POLY)^mult(StateArray[1][1],invMultArray[1][1],POLY)^mult(StateArray[1][2],invMultArray[1][2],POLY)^mult(StateArray[1][3],invMultArray[1][3],POLY);

			StateArrayTmp[2][j]=mult(StateArray[2][0],invMultArray[2][0],POLY)^mult(StateArray[2][1],invMultArray[2][1],POLY)^mult(StateArray[2][2],invMultArray[2][2],POLY)^mult(StateArray[2][3],invMultArray[2][3],POLY);

			StateArrayTmp[3][j]=mult(StateArray[3][0],invMultArray[3][0],POLY)^mult(StateArray[3][1],invMultArray[3][1],POLY)^mult(StateArray[3][2],invMultArray[3][2],POLY)^mult(StateArray[3][3],invMultArray[3][3],POLY);


		}
	AES_printf(invMultArray);
	memcpy(StateArray, StateArrayTmp, 4 * 4 * sizeof(unsigned char));
	memcpy(StateArray, StateArrayTmp, 4 * 4 * sizeof(unsigned char));
}

/**********************************************************************
 * Miscellaneous Functions 
 **********************************************************************/

void AES_printf (unsigned char AES_StateArray[][4])
{
	int i;
	xil_printf("   W0  W1  W2  W3\r\n\n");
	for(i=0; i<4; i++)
		xil_printf("   %02x  %02x  %02x  %02x\r\n",
				AES_StateArray[i][0], AES_StateArray[i][1],
				AES_StateArray[i][2], AES_StateArray[i][3]);
	xil_printf("\n");
}
