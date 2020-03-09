#include "SHA-1.h"

using namespace std;


 void sha_1::sha1_file( void )
 {

 }

void sha_1::reset( void )
{
    HA = H0;
    HB = H1;
    HC = H2;
    HD = H3;
    HE = H4;

    this->MemPointer = NULL;
}

void sha_1::ArrayTransformation( void )
{
    uint32_t temp = 0;
    uint64_t *BitPointer = NULL;
    uint32_t *pointer;

    pointer = (uint32_t*)this->MemPointer;

    /* (1) memory array transform to big endian format*/
    for(uint32_t i = 0; i< this->NumOfWords ; i++)
        {
            *pointer = this->BigEndianConvert32(*pointer);
            pointer++;
        }

    /*(2) add 1 bit in the end of original file*/
    this->MemPointer[this->StopBitPosition] = (unsigned char)0x80;

    /*(3) add  file length in bits in the end of memory block*/
    BitPointer = (uint64_t*)(this->MemPointer + this->NumOfBlocks*this->BlockSize -8);
    *BitPointer = this->MesBitLenght;
     /*big endian bit format */
    pointer = (uint32_t*)BitPointer;
    temp = pointer[0];
    pointer[0] = pointer[1];
    pointer[1] = temp;
}

uint32_t sha_1::GetNumberOfBlocks(uint32_t NumOfSymbols)
{
    uint32_t Blocks = 0,WordBalance = 0;
    this->MesLenght = NumOfSymbols;
    this->MesBitLenght = 8 * this->MesLenght;
    this->NumOfBlocks = MesLenght/BlockSize;     /*get number of blocks*/
    this->Balance     = MesLenght%BlockSize;     /*get current balance of bytes*/

    /*determination of the number of blocks*/
    if(this->Balance <= this->BlockBorder)
        {
             NumOfBlocks++;                              /*N  blocks*/
        }
    else if((this->Balance > this->BlockBorder))
        {
             this->NumOfBlocks = this->NumOfBlocks + 2; /*N blocks +1 additional*/
        }
    Blocks = this->NumOfBlocks;
    /*determination of the number of words*/
    this->NumOfWords = NumOfSymbols/4;
    if(NumOfSymbols%4!=0)
        {
            this->NumOfWords++;
            WordBalance = NumOfSymbols%4;
            this->StopBitPosition = (NumOfWords*4 - 1) - WordBalance;
        }
     else
        {
            this->StopBitPosition = (NumOfWords*4 + 3);
        }
    cout<<"***********file info***********"<<endl;
    cout<<"bits   : "<<this->MesBitLenght<<endl;
    cout<<"symbols: "<<this->MesLenght<<endl;
    cout<<"words:   "<<this->NumOfWords<<endl;
    cout<<"LastWord:"<<WordBalance<<endl;
    cout<<"blocks : " <<this->NumOfBlocks<<endl;
    cout<<"balance: "<<this->Balance<<endl;
    cout<<"*******************************"<<endl;
    return Blocks;
}

uint32_t sha_1::CyclicShiftLeft32 (uint32_t value,int shift)
{
    uint32_t bit_mask = 0xFFFFFFFF;
    uint32_t buffer = 0;
    bit_mask = bit_mask<<(32 - shift);
    buffer = value & bit_mask;
    value  = value<<shift;
    buffer = buffer>>(32 - shift);
    value |= buffer;
    return value;
}

uint64_t sha_1::BigEndianConvert64(uint64_t LittleEndian)
{
    uint64_t BD = 0;
    unsigned char *pointer,temp;

    pointer = (unsigned char*)&LittleEndian;
    for(int i = 0; i <= 3; i++ )
        {
            temp = pointer[i];
            pointer[i] = pointer[7-i];
            pointer[7-i] = temp;
        }
    BD = *(uint64_t*)pointer;
    return BD;
}

uint32_t sha_1::BigEndianConvert32(uint32_t LittleEndian)
{
    uint32_t BD = 0;
    unsigned char *pointer,temp;

    pointer = (unsigned char*)&LittleEndian;

    temp = pointer[3];
    pointer[3] = pointer[0];
    pointer[0] = temp;

    temp = pointer[2];
    pointer[2] = pointer[1];
    pointer[1] = temp;

    BD = *(uint32_t*)pointer;
    return BD;
}

void sha_1::CaclChecksum( void )
{
    uint32_t a,b,c,d,e;
    unsigned char *pointer;
    uint32_t temp;

    /*first init with constants*/
    HA = H0;
    HB = H1;
    HC = H2;
    HD = H3;
    HE = H4;

    pointer = (unsigned char*)BlockBuff;

    for(int i = 0; i < this->BlockSize; i++ )
        {
            temp = pointer[i];
            cout<<i<<"   "<<pointer[i]<<"   ";
            cout<<hex<<temp<<endl;
        }


    for(uint32_t BlockCounter = 0;BlockCounter < this->NumOfBlocks; BlockCounter++ )
    {
        memcpy(BlockBuff,MemPointer,BlockSize);
        /*internal loop*/

        /* (1) initializing hash values for the current block */
        a = HA;
        b = HB;
        c = HC;
        d = HD;
        e = HE;
        /* (3) internal coding cycle */
        SHA1_R0(a,b,c,d,e, 0);
        SHA1_R0(e,a,b,c,d, 1);
        SHA1_R0(d,e,a,b,c, 2);
        SHA1_R0(c,d,e,a,b, 3);
        SHA1_R0(b,c,d,e,a, 4);
        SHA1_R0(a,b,c,d,e, 5);
        SHA1_R0(e,a,b,c,d, 6);
        SHA1_R0(d,e,a,b,c, 7);
        SHA1_R0(c,d,e,a,b, 8);
        SHA1_R0(b,c,d,e,a, 9);
        SHA1_R0(a,b,c,d,e,10);
        SHA1_R0(e,a,b,c,d,11);
        SHA1_R0(d,e,a,b,c,12);
        SHA1_R0(c,d,e,a,b,13);
        SHA1_R0(b,c,d,e,a,14);
        SHA1_R0(a,b,c,d,e,15);
        SHA1_R1(e,a,b,c,d,16);
        SHA1_R1(d,e,a,b,c,17);
        SHA1_R1(c,d,e,a,b,18);
        SHA1_R1(b,c,d,e,a,19);
        SHA1_R2(a,b,c,d,e,20);
        SHA1_R2(e,a,b,c,d,21);
        SHA1_R2(d,e,a,b,c,22);
        SHA1_R2(c,d,e,a,b,23);
        SHA1_R2(b,c,d,e,a,24);
        SHA1_R2(a,b,c,d,e,25);
        SHA1_R2(e,a,b,c,d,26);
        SHA1_R2(d,e,a,b,c,27);
        SHA1_R2(c,d,e,a,b,28);
        SHA1_R2(b,c,d,e,a,29);
        SHA1_R2(a,b,c,d,e,30);
        SHA1_R2(e,a,b,c,d,31);
        SHA1_R2(d,e,a,b,c,32);
        SHA1_R2(c,d,e,a,b,33);
        SHA1_R2(b,c,d,e,a,34);
        SHA1_R2(a,b,c,d,e,35);
        SHA1_R2(e,a,b,c,d,36);
        SHA1_R2(d,e,a,b,c,37);
        SHA1_R2(c,d,e,a,b,38);
        SHA1_R2(b,c,d,e,a,39);
        SHA1_R3(a,b,c,d,e,40);
        SHA1_R3(e,a,b,c,d,41);
        SHA1_R3(d,e,a,b,c,42);
        SHA1_R3(c,d,e,a,b,43);
        SHA1_R3(b,c,d,e,a,44);
        SHA1_R3(a,b,c,d,e,45);
        SHA1_R3(e,a,b,c,d,46);
        SHA1_R3(d,e,a,b,c,47);
        SHA1_R3(c,d,e,a,b,48);
        SHA1_R3(b,c,d,e,a,49);
        SHA1_R3(a,b,c,d,e,50);
        SHA1_R3(e,a,b,c,d,51);
        SHA1_R3(d,e,a,b,c,52);
        SHA1_R3(c,d,e,a,b,53);
        SHA1_R3(b,c,d,e,a,54);
        SHA1_R3(a,b,c,d,e,55);
        SHA1_R3(e,a,b,c,d,56);
        SHA1_R3(d,e,a,b,c,57);
        SHA1_R3(c,d,e,a,b,58);
        SHA1_R3(b,c,d,e,a,59);
        SHA1_R4(a,b,c,d,e,60);
        SHA1_R4(e,a,b,c,d,61);
        SHA1_R4(d,e,a,b,c,62);
        SHA1_R4(c,d,e,a,b,63);
        SHA1_R4(b,c,d,e,a,64);
        SHA1_R4(a,b,c,d,e,65);
        SHA1_R4(e,a,b,c,d,66);
        SHA1_R4(d,e,a,b,c,67);
        SHA1_R4(c,d,e,a,b,68);
        SHA1_R4(b,c,d,e,a,69);
        SHA1_R4(a,b,c,d,e,70);
        SHA1_R4(e,a,b,c,d,71);
        SHA1_R4(d,e,a,b,c,72);
        SHA1_R4(c,d,e,a,b,73);
        SHA1_R4(b,c,d,e,a,74);
        SHA1_R4(a,b,c,d,e,75);
        SHA1_R4(e,a,b,c,d,76);
        SHA1_R4(d,e,a,b,c,77);
        SHA1_R4(c,d,e,a,b,78);
        SHA1_R4(b,c,d,e,a,79);

        HA = HA + a;
        HB = HB + b;
        HC = HC + c;
        HD = HD + d;
        HE = HE + e;
        MemPointer+=BlockSize;
    }


    cout<<"*******************************"<<endl;
    cout<<"Hash 0 : "<<hex<<HA<<endl;
    cout<<"Hash 1 : "<<hex<<HB<<endl;
    cout<<"Hash 2 : "<<hex<<HC<<endl;
    cout<<"Hash 3 : "<<hex<<HD<<endl;
    cout<<"Hash 4 : "<<hex<<HE<<endl;
}
