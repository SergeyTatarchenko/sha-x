#include <iostream>
#include <fstream>

#include "SHA-1.h"
/*-----------------------------------------------------------------*/
using namespace std;
/*-----------------------------------------------------------------*/

ofstream  FileWritter;
ifstream  FileReader;

int main(int argc, char *argv[])
{
    /*the number of lines and characters in the file*/
    int NumOfSymbols = 0,counter = 0;
    sha_1 SHA_1; /*checksum instance */

    if(argc = 2)
        {
            /*open stream for reading hash file*/
            FileReader.open(argv[1]);
            if(!FileReader)
                {
                    cout<<"no such file!"<<endl;
                    return 0;
                }
            do
                {
                    FileReader.get();
                    NumOfSymbols++;
                }
            while(!FileReader.eof());
            FileReader.close();
            NumOfSymbols--; /*subtract EOF character*/

            SHA_1.GetNumberOfBlocks(NumOfSymbols);
            SHA_1.MemPointer = new unsigned char [SHA_1.NumOfBlocks * SHA_1.BlockSize];
            memset(SHA_1.MemPointer,0,SHA_1.NumOfBlocks * SHA_1.BlockSize);

            FileReader.open(argv[1]);
            do
                {
                    SHA_1.MemPointer[counter] = FileReader.get();
                    counter++;
                }
            while(counter < NumOfSymbols);
            FileReader.close();

            SHA_1.ArrayTransformation();
            SHA_1.CaclChecksum();
            FileWritter.open(argv[2]);
            FileWritter<<"Calculated checksum :"<<endl;
            FileWritter<<hex<<SHA_1.HA;
            FileWritter<<hex<<SHA_1.HB;
            FileWritter<<hex<<SHA_1.HC;
            FileWritter<<hex<<SHA_1.HD;
            FileWritter<<hex<<SHA_1.HE;

            FileWritter.close();
            delete[] SHA_1.MemPointer;
        }
        else
            {
                cout<<"error"<<endl;
            }

    return 0;
}
