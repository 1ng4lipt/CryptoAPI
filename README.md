# CryptoAPI
Inspecting MS CryptoAPI 2.0 features (study project)

This application encrypting the in_test.txt file and creating out_test.txt file with some extra files (file with session key length, 
file with encrypted public key).

If you want to test it yourself, delete all files except in_test.txt (you can change a data inside the file).

Also you should create a certificate and sign it by local signature centre. 
In Header.h file you can specify SIGNER_NAME value (by default, certificate storage name is "MY").
