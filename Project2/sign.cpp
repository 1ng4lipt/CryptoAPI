#include "Header.h"

int sign()
{
	HCRYPTPROV	hProv = NULL;
	LPTSTR      pszName = NULL;

	DWORD       dwIndex = 0;

	BYTE* pCryptBuf = 0;
	//	DWORD	 buflen;
	//	BOOL	 bRes;
	DWORD	 datalen = 0;

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

	PCCERT_CONTEXT pSignerCert = 0;

	if (pSignerCert = CertFindCertificateInStore(hStore, MY_TYPE, 0, CERT_FIND_SUBJECT_STR,
												 SIGNER_NAME, NULL))

		printf("Сертификат найден!!!\n");
	else
		printf("Сертификат НЕ найден!\n.");


	HCRYPTKEY hPrivateKey = 0;
	DWORD keySpec = 0;

	// 3. Извлекаем из сертификата контекст приватного ключа
	if (!CryptAcquireCertificatePrivateKey(pSignerCert, 0, NULL, &hProv, &keySpec, NULL))
	{
		cout << "Error getting private context\n";
		getchar();
		return -1;
	}

	// Извлекаем закрытый ключ
	if (!CryptGetUserKey(hProv, keySpec, &hPrivateKey))
	{
		cout << "Error getting private key\n";
		getchar();
		return -1;
	}

	// 4. Открываем файл, содержимое которого подписываем и дальше создаем дайджест

	FILE* in_file;
	errno_t intext;
	const char* in_file_name = "in_test.txt";
	intext = fopen_s(&in_file, in_file_name, "rb");
	if (intext == 0)
	{
		printf("The file  was opened\n");
	}
	else
	{
		printf("The file  was not opened\n");
	}
	HCRYPTHASH hHash;
	DWORD dwLen;
	DWORD fSize = GetFileSize(in_file, &fSize);

	// Cоздаем хеш-объект (SHA-1, согласно Варианту 8)
	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
	{
		cout << "Error CryptCreateHash\n";
		return 0;
	}

	// Чтение файла
	BYTE* read = new BYTE[fSize + 8];
	if (::ReadFile(in_file, read, fSize, &dwLen, NULL))
	{
		puts("Error reading file\n");
		return -1;
	}

	// Передача хешируемых данных хэш-объекту.
	if (!CryptHashData(hHash, read, dwLen, 0))
	{
		cout << "ErrorCryptHashData";
		return 0;
	}
	std::cout << "Hash data loaded" << std::endl;

	// Получение хеш-значения
	DWORD count = 0;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &count, 0))
	{
		cout << "ErrorCryptGetHashParam";
		return 0;
	}

	char* hash_value = static_cast<char*>(malloc(count + 1));
	ZeroMemory(hash_value, count + 1);

	if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hash_value,
						   &count, 0))
	{
		cout << "ErrorCryptGetHashParam";
		return 0;
	}
	std::cout << "Hash value is received" << std::endl;

	// Создаем подпись хеш-значения

	// DWORD count = 0;
	if (!CryptSignHash(hHash, 1, NULL, 0, NULL, &count))
	{
		cout << "ErrorCryptSignHash";
		return 0;
	}

	char* sign_hash = static_cast<char*>(malloc(count + 1));

	ZeroMemory(sign_hash, count + 1);
	if (!CryptSignHashW(hHash, 1, NULL, 0, (BYTE*)sign_hash,
						&count))
	{
		cout << "ErrorCryptSignHash";
		return 0;
	}
	std::cout << "Signature created" << std::endl;


	fclose(in_file);

	CryptReleaseContext(hProv, 0);

	_getch();
	return 0;
}