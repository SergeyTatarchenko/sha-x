
 /*-----------------------------------------------------------------*/
#include <cstdint>
#include <cstring>
#include <iostream>
#include <cstdlib>
 /*-----------------------------------------------------------------*/

 /* Help macros */
#define SHA1_ROL(value, bits) (((value) << (bits)) | (((value) & 0xffffffff) >> (32 - (bits))))
#define SHA1_BLK(i) (BlockBuff[i&15] = SHA1_ROL(BlockBuff[(i+13)&15] ^ BlockBuff[(i+8)&15] ^ BlockBuff[(i+2)&15] ^ BlockBuff[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define SHA1_R0(v,w,x,y,z,i) z += ((w&(x^y))^y)     + BlockBuff[i]    + 0x5a827999 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R1(v,w,x,y,z,i) z += ((w&(x^y))^y)     + SHA1_BLK(i) + 0x5a827999 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R2(v,w,x,y,z,i) z += (w^x^y)           + SHA1_BLK(i) + 0x6ed9eba1 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R3(v,w,x,y,z,i) z += (((w|x)&y)|(w&x)) + SHA1_BLK(i) + 0x8f1bbcdc + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R4(v,w,x,y,z,i) z += (w^x^y)           + SHA1_BLK(i) + 0xca62c1d6 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);



class sha_1
{
    public:

        const int BlockSize = 64; /* (1) block size 512 bit for SHA-1*/
        unsigned char *MemPointer;/* (2) pointer to the beginning of
                                        the byte array of the message*/
        int MesLenght;            /* (3) message length in bytes     */

        const uint32_t H0 = 0x67452301; /* (4) initial hash constants*/
        const uint32_t H1 = 0xEFCDAB89;
        const uint32_t H2 = 0x98BADCFE;
        const uint32_t H3 = 0x10325476;
        const uint32_t H4 = 0xC3D2E1F0;

        uint32_t HA,HB,HC,HD,HE;

        const uint32_t Kt[4] = /* (5) */
        {
            0x5A827999,
            0x6ED9EBA1,
            0x8F1BBCDC,
            0xCA62C1D6
        };
        const uint32_t BlockBorder = 56; /*(6) if in the last block the
                                           number of bits is greater
                                           than 448, then an additional
                                           block must be created*/

        uint32_t BlockBuff[16]           = {0};
        uint32_t AdditionalBlockBuff[16] = {0};
        uint32_t ChecksumBuff[80]        = {0};
        uint32_t Checksum[5]             = {0};
        uint64_t MesBitLenght            = 0;
        uint32_t NumOfBlocks             = 0;
        uint32_t NumOfWords              = 0;
        uint32_t Balance                 = 0;
        int StopBitPosition              = 0;
 /*-----------------------------------------------------------------*/
        void ShowMesLenght( void );
        void CaclChecksum ( void );
        uint32_t CyclicShiftLeft32 (uint32_t value,int shift);
        uint32_t GetNumberOfBlocks(uint32_t NumOfSymbols);
        void ArrayTransformation( void );
        uint64_t BigEndianConvert64(uint64_t LittleEndian);
        uint32_t BigEndianConvert32(uint32_t LittleEndian);
        void reset( void );
        void sha1_file( void );
        void sha1_array( unsigned char *arr );

};



