#ifndef CryptoPrimitivesV1
#define CryptoPrimitivesV1
#include <gmp.h>
#include <pbc/pbc.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

//turns mpz_t into an array of bytes and returns the number of bytes
uint32_t mpz_to_byteArray(char** rop, mpz_ptr integer);
void byteArray_to_mpz(mpz_ptr rop, char *byteArray, uint32_t size);
//=========================================== STRUCTURE DEFINITION =================================
/*========================= Hash Struct =====================================================*/

typedef struct Polynomial{
    uint8_t degree;
    mpz_t* coeffs;
} Polynomial;

/*===========================================================================================*/
/*========================= GroupGen Struct =================================================*/
typedef struct DscGrp
{
    int secparam; //This paramter is determined by number of bits.
    mpz_t p; //prime has secparam +1 bits atleast
    mpz_t q; //prime has secparam bits atleast
    mpz_t generator; //generator of Zq*
    mpz_t order; //order of Zq*
    gmp_randstate_t state;
}DscGrp;


void commit(mpz_ptr skey,mpz_ptr value,char** commitment);
void open_commitment(mpz_ptr skey, mpz_ptr value, char* commitment);
/*===========================================================================================*/

/*Structure Definition For Measuring Time (in terms of seconds, miliseconds, microseconds and nanoseconds)*/
typedef struct{ 
    struct timespec start;
    struct timespec end;
    long seconds;
    long milliseconds;
    long microseconds;
    int64_t nanoseconds;
}DscTimeMeasure;
/*===========================================================================================*/

/*Structure Definition For Threshold Secret Sharing Scheme (Shamir Secret Sharing)*/
typedef struct{
    int num_shares;
    int threshold;
    int num_bits;
    
    DscGrp* grp;
    mpz_t secret;
    mpz_t* shares_x;
    mpz_t* shares_y;
    mpz_t recovered_secret;
    mpz_t* coeffs;

    mpz_t* commitments;
}DscThssFeldman;

typedef struct{
    mpz_t* output1; // output [part1] in format a point on curve
    mpz_t* output2; // output [part2] in format a point on curve
    uint32_t blocks; //number of elements for output1 and output2
}DscCipher; //ciphertext for ThrCrypt

/*Structure Definition For Threshold Cryptosystem Scheme (Shamir Secret Sharing+Elgamal)*/
typedef struct {
    int secparam_bits;
    mpz_t skey; /* secret key */
    mpz_t pkey; //public key
    DscGrp grp;     // group
    DscCipher cipher;
    char *plaintextInput; // plaintext (befor encryption) in format string
    uint16_t maximumBlockSize; //maximum size of a block in bytes
    char *plaintextOutput; // plaintext (after decryption) in format string
    uint32_t sizeOfPlaintext; //in bytes
    DscThssFeldman thss;// Threshold Secret Sharing

    DscThssFeldman* ai; //each user has their own polynomial
    mpz_t* gsi;
    char** commits;
    mpz_t* u;
    mpz_t* xi;
    mpz_t* hi;
    mpz_t* di;

    uint16_t total;
    uint8_t threshold;
} DscThrCrypt; //Threshold Elgamal CryptoSystem


//############## Time Measurement #############################################
void Time_Measure(DscTimeMeasure *time);

//############ PRG=(SeedGen,Eval) #############################################
void PRG(uint8_t *out, size_t outlen, const uint8_t *seed32);
void PRF(uint8_t out[32],const uint8_t *key, size_t keylen,const uint8_t *input, size_t inputlen);
//#############################################################################


//############ GroupGen (GMP) ##################################################
void GroupGen_Config(DscGrp *grp, uint32_t secparam);
void GroupGen(DscGrp *grp);
void GroupGen_Free(DscGrp *grp);
/*++++++++++ Test Program - GroupGen +++++++++++ 
    DscGrp grp;
    GroupGen_Config(&grp);

    GroupGen(&grp);
    printf("\n-------------------------------------------------------------");
    gmp_printf("\nGroup Generator is:  %B\n", grp.generator);
    gmp_printf("\nGroupt Order is: %Zd\n", grp.order);
    printf("-------------------------------------------------------------\n\n");
+++++++++++++++++++++++++++++++++++++++++++++++++*/
//###### Thrss=(Share,ReConst) (Shamir Secret Sharing) ########################
void Thss_Verify_Share(DscThssFeldman* thss, uint32_t i);
void generate_random_mpz(mpz_ptr prime, mpz_ptr rndelement);
void Thss_Config(DscThssFeldman *thss,DscGrp* grp, int secparam_bits, int total, int threshold);
void Thss_Share(DscThssFeldman *thss, mpz_ptr secret);
void Thss_ReCons(DscThssFeldman *thss); 
void Thss_Free(DscThssFeldman *thss);
/* Example:
  DscThssFeldman thss;
  DscGrp grp;
  mpz_t secret;
  mpz_init(secret);
  mpz_set_ui(secret, 16*16*4+16*2+4);
  int total =140;
  int threshold =40;
  GroupGen_Config(&grp,256);
  GroupGen(&grp);
  Thss_Config(&thss, &grp, 256, total,threshold);
  Thss_Share(&thss, secret);
  mpz_clear(secret);
  for(int i =0;i<total;i++)
    Thss_Verify_Share(&thss,i);
  Thss_ReCons(&thss);
  gmp_printf("%#Zx recovered secret\n",thss.recovered_secret);
  Thss_Free(&thss);
  GroupGen_Free(&grp);
*/


//###### ThrCrypt=(DKeyGen,Enc,Dec) (Shamir Secret Sharing)####################
void ThrCrypt_Config(DscThrCrypt *thrcrypt,uint16_t secparam_bits,uint16_t total, uint16_t threshold);
void ThrCrypt_DKeyGen(DscThrCrypt *thrcrypt);
void ThrCrypt_Enc(DscThrCrypt *thrcrypt,char* plaintext, uint32_t size);
void ThrCrypt_Dec(DscThrCrypt *thrcrypt);
void ThrCrypt_Free(DscThrCrypt *thrcrypt);
void Cipher_Free(DscCipher* cipher);
/*++++++++++++++ Test Program - DscThrCrypt +++++ 

  DscThrCrypt thrcrypt;
  char secret1[] = ";dfk;aswk;aswk;asw\0\0\0\0sdfsdfjasof398rj34jff9j9*FEH(*"
                   "PHJRFEWIPUFH(*WEhfniukjesnhfdkjsdkf394\0";
  char secret2[] = ";dfk;aswk;aswk;asw\0\0*WEhfniukjesnhfdkjsdkf394\0";

  ThrCrypt_Config(&thrcrypt, 256, 5, 3);
  ThrCrypt_DKeyGen(&thrcrypt, NULL);
  ThrCrypt_Enc(&thrcrypt, secret1, sizeof(secret1));
  DscCipher cipher1 = thrcrypt.cipher;
  ThrCrypt_Enc(&thrcrypt, secret2, sizeof(secret2));
  DscCipher cipher2 = thrcrypt.cipher;

  thrcrypt.cipher = cipher1;
  ThrCrypt_Dec(&thrcrypt);
  printf("\n\ndecrypted output for secret1 hex code: \n");
  for (int i = 0; i < thrcrypt.sizeOfPlaintext; i++) {
    printf("%02x", (unsigned char)thrcrypt.plaintextOutput[i]);
  }
  printf("\n");
  printf("secret1 hex code: \n");
  for (int i = 0; i < sizeof(secret1); i++) {
    printf("%02x", (unsigned char)secret1[i]);
  }
  printf("\n");

  thrcrypt.cipher = cipher2;
  ThrCrypt_Dec(&thrcrypt);
  printf("\n\ndecrypted output for secret2 hex code: \n");
  for (int i = 0; i < thrcrypt.sizeOfPlaintext; i++) {
    printf("%02x", (unsigned char)thrcrypt.plaintextOutput[i]);
  }
  printf("\n");
  printf("secret2 hex code: \n");
  for (int i = 0; i < sizeof(secret2); i++) {
    printf("%02x", (unsigned char)secret2[i]);
  }
  printf("\n");
  ThrCrypt_Free(&(thrcrypt));

+++++++++++++++++++++++++++++++++++++++++++++++++*/
//#############################################################################
void generatePrime(mpz_ptr rop, uint32_t sizeInBits);
#endif 