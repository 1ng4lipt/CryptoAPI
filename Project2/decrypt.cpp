#include "Header.h"

int decrypt() 
{

	HCRYPTPROV	hProv = NULL;
	LPTSTR      pszName = NULL;

	DWORD       dwIndex = 0;

	BYTE* pCryptBuf = 0;
	DWORD	 buflen;
	BOOL	 bRes;
	DWORD	 datalen=0;

	setlocale(LC_ALL, "ru");

	// 1. ���������� ��������������� �� ��������� (PROV_RSA_FULL)

	if (!CryptAcquireContextW(&hProv, NULL, 0, PROV_RSA_FULL, 0) &&
		!CryptAcquireContextW(&hProv, NULL, 0, PROV_RSA_FULL, CRYPT_NEWKEYSET))
	{
		puts("NO create keyset\n");
		return 1;
	}
	else
		puts("YES, create keyset\n");

	HCERTSTORE hStoreHandle;

	if (!(hStoreHandle = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
		CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_NAME)))
		printf("���������� ������� ���������");
	else
		printf("������� ��������� ��������, ���������...\n");

	// 2. ��������� ��������� ������������
	HCERTSTORE hStore;


	if (!(hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
		CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_NAME)))

		printf("������ ������� ���������");

	// 2.1 �������� ��������� �� ��� ����������

	PCCERT_CONTEXT pSignerCert = 0;

	if (pSignerCert = CertFindCertificateInStore(hStore, MY_TYPE, 0, CERT_FIND_SUBJECT_STR,
		SIGNER_NAME, NULL))

		printf("���������� ������!!!\n");
	else
		printf("���������� �� ������!\n.");


	// ========== � � � � � � � � � � =========

	// 7. ��������� private key ��� ����������

	HCRYPTKEY hPrivateKey = 0;
	DWORD keySpec = 0;

	// ��������� �� ����������� �������� ���������� �����
	if (!CryptAcquireCertificatePrivateKey(pSignerCert, 0, NULL, &hProv, &keySpec, NULL))
	{
		cout << "Error getting private context\n";
		getchar();
		return -1;
	}

	// ��������� �������� ����
	if (!CryptGetUserKey(hProv, keySpec, &hPrivateKey))
	{
		cout << "Error getting private key\n";
		getchar();
		return -1;
	}

	//��������� ������ ����� � ����
	FILE* outBlobLength;
	const char* outBlobLength_name = "out_length.txt";
	fopen_s(&outBlobLength, outBlobLength_name, "rb");
	DWORD dwBlobLenght = 0;
	fread(&dwBlobLenght, sizeof(DWORD), 1, outBlobLength);
	fclose(outBlobLength);

	// 7.1 ��������� ���� � ������������� ���������� ������ � ��� ������

	FILE* info_file;
	const char* info_file_name = "info_test.txt";
	fopen_s(&info_file, info_file_name, "rb");

	// 8. ������ ����������� �����

	 BYTE *ppbKeyBlob; 
	ppbKeyBlob = NULL;
	
	if (ppbKeyBlob = (LPBYTE)malloc(dwBlobLenght))
		printf("memory has been allocated for the Blob\n");

	else
	{
		printf("Error memory for key length!!!");
		getchar();
		return -1;
	}

	// ��������� ���������� ���� �� ����� in.
	if (fread(ppbKeyBlob, sizeof byte, dwBlobLenght, info_file))
	{
		printf("the session key has been read to the file\n");
	}

	else
	{
		printf("the session key could not be read from the file\n");
		getchar();
		return -1;
	}

	// ����������� ���������� ���� � ������� ��������� ����� �������������� ���������
	HCRYPTKEY hKey = 0;
	if (CryptImportKey(hProv, ppbKeyBlob, dwBlobLenght, hPrivateKey, 0,
		&hKey))
	{
		printf("the key has been imported.\n");
		CryptDestroyKey(hPrivateKey); //������� �������
		free(ppbKeyBlob);
		fclose(info_file);
	}
	else
	{
		printf("the session key import failed.\n");
		getchar();
		return -1;
	}

	// 8.1 ��������� ���� � ������������� �������
	FILE* out_file;
	const char* out_file_name = "out_test.txt";
	fopen_s(&out_file, out_file_name, "rb");

	// 8.2 ������� � ��������� ���� ��� ������ ��������������� ������

	FILE* out_decr_file;
	const char* out_decr_file_name = "out_decr_test.txt";
	fopen_s(&out_decr_file, out_decr_file_name, "wb");

	// 9. ������������� ������
	
	buflen = ENCRYPT_BLOCK_SIZE;
	bRes = CryptEncrypt(hKey, 0, TRUE, 0, NULL, &buflen, 0);
	pCryptBuf = (BYTE*)malloc(buflen);
	//int t = 0;
	// �������������� ����

	int blockSize = 32;
	///BYTE* pCryptBuf = 0;
	DWORD bufLen, dataLen;
	//DWORD dwBlobLenght = 0;
	//bool bRes;
	bufLen = blockSize;

	pCryptBuf = (BYTE*)malloc(bufLen);

	unsigned int t = 0;
	int willRead = bufLen;
	int countOfReadBytes = 0;

	int i = 0;
	while (!feof(out_file))
	{
		t = fread(pCryptBuf, sizeof(BYTE), bufLen, out_file);
		countOfReadBytes += t;
		if (t <= 0) break;
		dataLen = t;
		bool flag = false;
		flag = t < bufLen;

		if (!CryptDecrypt(hKey, 0, flag, 0, pCryptBuf, &dataLen))
		{
			printf("Error CryptDecrypt\n");
			return 1;
		}
		std::cout << "Decryption #" << i << " completed" << std::endl;
		fwrite(pCryptBuf, sizeof(BYTE), dataLen, out_decr_file);
		i++;
	}

		cout << "File decryption completed successfully" << endl;

	fclose(out_file);
	fclose(out_decr_file);
	free(pCryptBuf);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
	_getch();

	return 0;


}