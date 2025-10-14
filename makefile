link: CryptoPrimitivesV1.o VNet1.o
	gcc -g -O3 CryptoPrimitivesV1.o VNet1.o -o programName -ltomcrypt -lgmp -lpbc -lssl -lcrypto

VNet1.o:
	gcc -g -O3 -c  VNet1.c

CryptoPrimitivesV1.o:
	gcc -g -O3 -c CryptoPrimitivesV1.c

clear:
	rm -f CryptoPrimitivesV1.o VNet1.o programName