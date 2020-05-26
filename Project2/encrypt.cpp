#include "Header.h"

int encrypt() {

	HCRYPTPROV	hProv = NULL;
	LPTSTR      pszName = NULL;

	DWORD       dwIndex = 0;

	BYTE* pCryptBuf = 0;
	DWORD	 buflen;
	BOOL	 bRes;
	DWORD	 datalen;

	setlocale(LC_ALL, "ru");

	// 1. Подключаем криптопровайдер по умолчанию (PROV_RSA_FULL)

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
		printf("Невозможно открыть хранилище");
	else
		printf("Открыть хранилище возможно, подождите...\n");

	// 2. Открываем хранилище сертификатов
	HCERTSTORE hStore;


	if (!(hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
		CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_NAME)))

		printf("Нельзя открыть хранилище");

	// 2.1 Получаем указатель на наш сертификат

	PCCERT_CONTEXT pSignerCert=0;

	if (pSignerCert = CertFindCertificateInStore(
		hStore, 
		MY_TYPE, 0, CERT_FIND_SUBJECT_STR,
		SIGNER_NAME, NULL))

		printf("Сертификат найден!!!\n");
	else
		printf("Сертификат НЕ найден!\n.");

	// 3. Импортируем public key для последующей верификации подписи или шифрования сеансового ключа

	HCRYPTKEY hPublicKey=0;
	if (CryptImportPublicKeyInfo(
		hProv,
		MY_TYPE, 
		&(pSignerCert->pCertInfo->SubjectPublicKeyInfo),
		&hPublicKey))

		printf("Импортируем публичный ключ...\n");
	else
		printf("Ошибка CryptAcquireContext.");


	// 4. Генерируем сессионный ключ

	HCRYPTKEY hKey;
	if (!CryptGenKey(hProv, CALG_DES, CRYPT_EXPORTABLE | CRYPT_ENCRYPT, &hKey))
	{
		puts("Не удается создать ключ DES\n");
		return -1;
	}

	else
		std::cout << "Session key generated\n" << std::endl;


	// ====== Устанавливаем режим шифрование RC2_OFB согласно Варианту 8 ======

	/*DWORD dwMode = CRYPT_MODE_OFB;
	if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0))
	{
		puts("Error CryptSetKeyParam!\n");
		return -1;
	}*/


	// Создадим и откроем для чтения файл с исходным текстом для шифрования

	FILE* in_file;
	const char* in_file_name = "in_test.txt";
	fopen_s(&in_file, in_file_name, "rb");

	// Создадим и откроем для записи файл куда будем сохранять шифртекст

	FILE* out_file;
	const char* out_file_name = "out_test.txt";
	fopen_s(&out_file, out_file_name, "wb");

	// Создадим и откроем для записи файл куда будем сохранять зашифрованый ключ и длину

	FILE* info_file;
	const char* info_file_name = "info_test.txt";
	fopen_s(&info_file, info_file_name, "wb");

	// 5. Зашифруем текст файла in_test.txt и получим на выходе файл out_test.txt

	buflen = ENCRYPT_BLOCK_SIZE;
	if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &buflen, 0))
	{
		cout << "Crypt Encrypt (bufSize) failed." << endl;
		getchar();
		return -1;
	}

	// Выделим память под буфер
	pCryptBuf = (BYTE*)malloc(buflen);
	int t = 0;

	// Шифруем файл in
	while ((t = fread(pCryptBuf, sizeof byte, ENCRYPT_BLOCK_SIZE, in_file)))
	{
		datalen = t;
		bRes = CryptEncrypt(hKey, 0, TRUE, 0, pCryptBuf, &datalen, buflen);
		if (!bRes)
		{
			cout << "CryptEncrypt (encryption) failed,\n " << endl;
			getchar(); return -1;
		}

		fwrite(pCryptBuf, sizeof byte, datalen, out_file);
	}
	cout << "File encryption completed successfully\n" << endl;

	// Закрываем файлы и очищаем память от ключей
	fclose(in_file);
	fclose(out_file);


	// 6. Выполним экспорт сессионного ключа в файл

	DWORD dwBlobLenght = 0;

	if (CryptExportKey(hKey, hPublicKey, SIMPLEBLOB, 0, 0, &dwBlobLenght))
		printf("size of the Blob\n");

	else
	{
		printf("error computing Blob length\n");
		getchar();
		return -1;
	}

	// Распределяем память для сессионного ключа
	BYTE* ppbKeyBlob;
	ppbKeyBlob = NULL;

	if (ppbKeyBlob = (LPBYTE)malloc(dwBlobLenght))
		printf("memory has been allocated for the Blob\n");

	else
	{
		printf("Error memory for key length!!!\n");
		getchar();
		return -1;
	}

	// Зашифруем сессионный ключ hKey открытым ключом hPublicKey
	if (CryptExportKey(hKey, hPublicKey, SIMPLEBLOB, 0, ppbKeyBlob,
		&dwBlobLenght))

		printf("contents have been written to the Blob\n");

	else
	{
		printf("Could not get exporting key.");
		free(ppbKeyBlob);
		ppbKeyBlob = NULL;
		getchar();
		return -1;
	}
	//записіваем размер блоба в файл
	FILE* outBlobLength;
	const char* outBlobLength_name = "out_length.txt";
	fopen_s(&outBlobLength, outBlobLength_name, "wb");
	int rwBuf1 = fwrite(&dwBlobLenght, sizeof(DWORD), 1, outBlobLength);
	fclose(outBlobLength);

	// Записываем экспортированный ключ в файл out.
	if (fwrite(ppbKeyBlob, sizeof byte, dwBlobLenght, info_file))
	{
		printf("the session key has been written to the file\n");
		free(ppbKeyBlob);

	}

	else
	{
		printf("the session key could not be written to the file\n");
		getchar();
		return -1;
	}
	fclose(info_file);

	free(pCryptBuf);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
	_getch();

	return 0;

}