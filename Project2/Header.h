//#include "main.h"
#pragma comment(lib, "crypt32.lib")
// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")


#include <stdio.h>
#include <Windows.h>
#include <WinCrypt.h>
#include <stdlib.h> 
#include <WTypes.h>
#include <iostream>
#include <fstream>
#include <tchar.h>
#include <conio.h>

using namespace std;

#define MY_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

	// Наименование персонального хранилища
#define CERT_STORE_NAME  L"MY"

// Наименование сертификата, установленного в это хранилище
#define SIGNER_NAME  L"opu.ua"

#define KEYLENGTH  0x00800000
#define ENCRYPT_BLOCK_SIZE 20 
	//int encrypt();
    //int decrypt();
