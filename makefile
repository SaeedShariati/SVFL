CC = gcc
CFLAGS = -g -O0 #-fsanitize=address -fsanitize=undefined
link: CryptoPrimitivesV1.o VNet1.o
	$(CC) $(CFLAGS) CryptoPrimitivesV1.o VNet1.o -o programName -ltomcrypt -lgmp -lpbc -lssl -lcrypto

VNet1.o:
	$(CC) $(CFLAGS) -c  VNet1.c

CryptoPrimitivesV1.o:
	$(CC) $(CFLAGS) -c CryptoPrimitivesV1.c

clear:
	rm -f CryptoPrimitivesV1.o VNet1.o programName