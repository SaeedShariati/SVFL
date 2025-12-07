#include <pbc/pbc.h>
#include <pbc/pbc_curve.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include<inttypes.h>
#include <sys/types.h>
// #include <pbc/pbc_test.h>
#include <gmp.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <tomcrypt.h>
#include <openssl/rand.h>
#include "CryptoPrimitivesV1.h"

/********** Command for compile (FAIRSHARE (.c) + CryptoPrimitives (.c and .h))
*************************************************************

gcc VNet.c VNet.c -o VNet -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -lssl -lcrypto
   -lgmp -l tomcrypt -l m

*********************************************************************************************************************************************/
#define GRAD_SIZE 10000
#define USERS_SIZE 1000
#define SEC_PARAM 32  //in bytes
#define Threshold 10
#define DropOut 0.1 //what rate of users dropout at every step
#define ITERATIONS 1
typedef struct{
   uint8_t val[32];
} Seed;

typedef struct {
   int Uid; // Unique ID for the user

   mpz_t skey;
   mpz_t pkey;
   mpz_t shares_x;      // id related to thss
   mpz_t shares_y;      // secret share related to thss

   uint32_t *plainLocalVector;

   mpz_t *maskedLocalVector;
   mpz_t *maskTag;

   mpz_t betaMasked; //beta_i,j
   mpz_t betaVerify;  //betahat_i,j
   uint32_t betaMaskedSize,betaVerifySize;

   Seed sdata[USERS_SIZE];//s_i,j ,32 bytes each
   Seed sverify[USERS_SIZE]; //s_i,j hat ,32 bytes each

   // output thrcrypt
   DscCipher P;
   DscCipher B;

   // for using in tag
   mpz_t k_p[GRAD_SIZE];
   mpz_t k_s_i[GRAD_SIZE];

} DscClient;

////////////////////////////////////
typedef struct {
   DscGrp grp;

   DscThrCrypt thrcrypt;

   uint32_t secparam;   // Security parameter
   uint32_t numClients; // Number of clients
   uint32_t thrshld;    // Threshold
   uint32_t grdSize;
   uint32_t rndlbl;

   uint8_t Uact1[USERS_SIZE], Uact2[USERS_SIZE], Uact3[USERS_SIZE];

   uint16_t Uact1Active, Uact2Active, Uact3Active; 
   mpz_t *gradGlobalVector;
   mpz_t *tagGlobalVector;

   DscClient *Users; // Array of users (clients)
   unsigned char vk[32];

} DscVNet;
typedef struct quantity_overhead {
  double usual;
  double overhead;
} quantity_overhead;
typedef struct Time_Performance {
  double keyshare_client;
  double keyshare_server;
  quantity_overhead mask_client;
  double mask_server;
  double unmask_client;
  quantity_overhead unmask_server;
  double verification_client;
  double verification_server;
} Time_Performance;

Time_Performance time_measured;
DscTimeMeasure global_timemeasure;
static inline void generate_random_mpz_vnet(DscVNet *vnet, mpz_ptr rndelement)
{
   mpz_urandomm(rndelement, vnet->grp.state, vnet->grp.prime);
}
//prints hex code
void print(char* a, uint32_t size)
{
   for(int i =0;i<size;i++){
      printf(" %02x",(unsigned char)a[i]);
   }
   printf("\n");
}
//prints hex code
void printIndex(char* a, uint32_t size, char* name,uint32_t index)
{
   printf("\n******* Debug *********");
   printf("\n%s[%d] :\n",name,index);
   for(int i =0;i<size;i++){
      printf("%02x",(unsigned char)a[i]);
   }
   printf("\n**********************\n");
}
void printmpz(mpz_t a,char* name){
   printf("\n******* Debug *********");
   printf("\n%s :\n",name);
   gmp_printf("%Zx",a);
   printf("\n**********************\n");
}

static inline void print_timemeasure_header() {
  printf("                                             "
         " | Seconds | Miliseconds | Microseconds |  Nanoseconds  |\n"
         "                                             "
         " --------------------------------------------------------\n");
}
static inline void print_timemeasure(DscTimeMeasure *timemeasure, uint16_t iter,
                                     char *function_name) {

  printf("[iter %3d] Elapsed Time for %-15s : |%9ld|%13ld|%14ld|%15ld|\n", iter,
         function_name, timemeasure->seconds, timemeasure->milliseconds,
         timemeasure->microseconds, timemeasure->nanoseconds);
}
//not secure, used to give random inputs for local gra
uint64_t rand_uint64() {

    static uint64_t state = 88172645463325252ull; // seed
    state = state * 6364136223846793005ULL + 1;
    return state;
}

//turns mpz_t into an array of bytes and returns the number of bytes
uint32_t mpz_to_byteArray(char** rop, mpz_ptr integer){
    size_t count = 0;
    size_t size_in_bytes = (mpz_sizeinbase(integer, 2) + 7) / 8;
    
    *rop = (char*)malloc(size_in_bytes);
    if (!*rop) return 0;  // malloc failed
    mpz_export(*rop, &count, 1, sizeof(char), 1, 0, integer);

    return (uint32_t)count;
}
static inline void byteArray_to_mpz(mpz_ptr rop, char *byteArray, uint32_t size) {
  mpz_import(rop, size, 1, sizeof(char), 0, 0,
              byteArray);
}
//if originalSize<newSize then adds zeros to the end until the size of bytes* becomes newSize
static inline void padWithZero(char** bytes,size_t originalSize,size_t newSize){
   if(originalSize<newSize){

      char* temp = realloc(*bytes,newSize);
      if (!temp) {
         // realloc failed, original arr is still valid
         free(bytes);
         perror("realloc");
         exit(1);
      }
      *bytes = temp;
      memset(*bytes+originalSize,0,newSize-originalSize);
   }
}
void Config(DscVNet *vnet)
{

   vnet->secparam = SEC_PARAM;
   vnet->thrshld = Threshold;
   vnet->numClients = USERS_SIZE;
   vnet->grdSize = GRAD_SIZE;
   vnet->rndlbl = 1;
   memset(vnet->Uact1,1,sizeof(vnet->Uact1));
   memset(vnet->Uact2,0,sizeof(vnet->Uact2));
   memset(vnet->Uact3,0,sizeof(vnet->Uact3));

   vnet->gradGlobalVector = malloc(vnet->grdSize * sizeof(mpz_t));
   vnet->tagGlobalVector = malloc(vnet->grdSize * sizeof(mpz_t));

   GroupGen_Config(&(vnet->grp),vnet->secparam*8 +1);
   // Allocate memory for the array of users

   vnet->Users = malloc(vnet->numClients * sizeof(DscClient));

   // THRCRYPT
   ThrCrypt_Config(&(vnet->thrcrypt), 256, vnet->numClients,
                   vnet->thrshld);
                   
   // Initialize each user's UID and random gradients
   for (int i = 0; i < vnet->numClients; i++) {
      vnet->Users[i].Uid = i; // Example: Assign UIDs from 0 to numClients-1
      mpz_init2(vnet->Users[i].skey,SEC_PARAM*8 + GMP_LIMB_BITS);
      mpz_init2(vnet->Users[i].pkey,SEC_PARAM*8 + GMP_LIMB_BITS);
      mpz_inits(vnet->Users[i].shares_x,vnet->Users[i].shares_y,NULL);
      mpz_inits(vnet->Users[i].betaMasked,vnet->Users[i].betaVerify,NULL);


      // To initialize local data vector for each user
      srand(time(NULL));
      vnet->Users[i].plainLocalVector = calloc(vnet->grdSize, sizeof(uint32_t));

      for (int j = 0; j < vnet->grdSize; j++) {
         vnet->Users[i].plainLocalVector[j]= rand_uint64();
      }

   }
  
  vnet->Uact1Active = 0;
  vnet->Uact2Active = 0;
  vnet->Uact3Active = 0;
}

void Init(DscVNet *vnet)
{
   GroupGen(&(vnet->grp));
   ThrCrypt_DKeyGen(&(vnet->thrcrypt));
   RAND_bytes(vnet->vk, sizeof(vnet->vk));

   for (int i = 0; i < vnet->numClients; i++) {

      generate_random_mpz_vnet(vnet, vnet->Users[i].skey);

      mpz_powm(vnet->Users[i].pkey, (vnet->grp).generator, vnet->Users[i].skey, vnet->grp.prime);
      mpz_set(vnet->Users[i].shares_x,vnet->thrcrypt.thss.shares_x[i]);
      mpz_set(vnet->Users[i].shares_y,vnet->thrcrypt.thss.shares_y[i]); // sk_i^t = (shares_x[i],shares_y[i])
   }
}

void KeyShare(DscVNet *vnet)
{
  vnet->Uact1Active = 0;
  for (int i = 0; i < vnet->numClients; i++) {
     if (vnet->Uact1[i] == 0)
        continue;


    clock_gettime(
        CLOCK_MONOTONIC,
        (&(global_timemeasure.start))); // measuring time takes by users
    ++(vnet->Uact1Active);

 
     generate_random_mpz_vnet(vnet, vnet->Users[i].betaMasked);
     generate_random_mpz_vnet(vnet, vnet->Users[i].betaVerify);
  
     unsigned char str1[5];
  
     for (int z = 0; z < vnet->numClients; z++) {
        if(z==i){
           memset(vnet->Users[i].sdata[z].val,1,sizeof(vnet->Users[i].sdata[z].val));
           memset(vnet->Users[i].sverify[z].val,1,sizeof(vnet->Users[i].sverify[z].val));
           continue;
        }
        mpz_t k;
        mpz_init(k);
        char* sharedSecret; 
        mpz_powm(k, vnet->Users[i].pkey,
           vnet->Users[z].skey, vnet->grp.prime);
        size_t size = mpz_to_byteArray(&sharedSecret, k);
        if(size<vnet->secparam)
           padWithZero(&sharedSecret, size, vnet->secparam);
        mpz_clear(k);
  
        str1[0] = (vnet->rndlbl >> 24) & 0xFF;
        str1[1] = (vnet->rndlbl >> 16) & 0xFF;
        str1[2] = (vnet->rndlbl >> 8) & 0xFF;
        str1[3] = vnet->rndlbl & 0xFF;
        str1[4] = 0;
        
        
        //initialize s_i,j
        PRF(vnet->Users[i].sdata[z].val,(uint8_t*)sharedSecret,vnet->secparam,str1,5);
        
        
        //initialize s_i,j'
        str1[4]=1;
        PRF(vnet->Users[i].sverify[z].val,(uint8_t*)sharedSecret,vnet->secparam,str1,5);
  
        free(sharedSecret);
     }
  
     char* betaMasked;
     char* betaVerify;
     size_t size1 = mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
     vnet->Users[i].betaMaskedSize = size1;
     size_t size2 = mpz_to_byteArray(&betaVerify, vnet->Users[i].betaVerify);
     vnet->Users[i].betaVerifySize = size2;
     char* B = malloc(size1+size2);
     memcpy(B,betaMasked,size1);
     memcpy(B+size1,betaVerify,size2);
     ThrCrypt_Enc(&(vnet->thrcrypt),B,size1+size2);
     vnet->Users[i].B = vnet->thrcrypt.cipher;
     free(betaMasked);free(betaVerify);free(B);
  
     char* P = malloc(2*USERS_SIZE*sizeof(Seed));
     memcpy(P,vnet->Users[i].sdata,USERS_SIZE*sizeof(Seed));
     memcpy(P+USERS_SIZE*sizeof(Seed),vnet->Users[i].sverify,USERS_SIZE*sizeof(Seed));
     ThrCrypt_Enc(&(vnet->thrcrypt), P, 2*USERS_SIZE*sizeof(Seed));
     vnet->Users[i].P = vnet->thrcrypt.cipher;   
     free(P);

    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
    Time_Measure(&global_timemeasure);
    time_measured.keyshare_client += global_timemeasure.milliseconds;
    
  }
}
void Mask(DscVNet *vnet) {
  vnet->Uact2Active = 0;
  if (vnet->Uact1Active < vnet->thrshld) {
    printf("\nMASK: Not enough active members to continue.\n");
    exit(1);
  }
  for (int i = 0; i < vnet->numClients; i++) {
    if (vnet->Uact2[i] == 0) {

      free(vnet->Users[i].plainLocalVector);
      continue;
    }
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
    (vnet->Uact2Active)++;

    // Computations for taghat_i
    uint32_t *prgArrayTag = malloc(vnet->grdSize * sizeof(uint32_t));
    vnet->Users[i].maskTag = malloc(vnet->grdSize * sizeof(mpz_t));
    // generate k_p
    uint8_t str1[6] = {0};
    str1[0] = (vnet->rndlbl >> 24) & 0xFF;
    str1[1] = (vnet->rndlbl >> 16) & 0xFF;
    str1[2] = (vnet->rndlbl >> 8) & 0xFF;
    str1[3] = vnet->rndlbl & 0xFF;

    size_t bytes = (mpz_sizeinbase(vnet->grp.prime, 2) + 7) /
                   8; // number of bytes of prime q
    char *randomOutput =
        malloc(GRAD_SIZE * bytes); // used for generating k_p and k_s_i
    uint8_t t[32];
    PRF(t, vnet->vk, sizeof(vnet->vk), str1, sizeof(str1));
    PRG((uint8_t *)randomOutput, bytes * GRAD_SIZE, t);
    for (int j = 0; j < GRAD_SIZE; j++) {
      mpz_init(vnet->Users[i].k_p[j]);
      mpz_inits( vnet->Users[i].maskTag[j],
                NULL);
      byteArray_to_mpz(vnet->Users[i].k_p[j], randomOutput + bytes * j, bytes);
      mpz_mod(vnet->Users[i].k_p[j], vnet->Users[i].k_p[j], vnet->grp.prime);
    }
    // generate k_s_i
    str1[4] = (i >> 8) & 0xFF;
    str1[5] = i & 0xFF;
    PRF(t, vnet->vk, sizeof(vnet->vk), str1, sizeof(str1));
    PRG((uint8_t *)randomOutput, GRAD_SIZE * bytes, t);
    for (int j = 0; j < GRAD_SIZE; j++) {
      mpz_init(vnet->Users[i].k_s_i[j]);
      byteArray_to_mpz(vnet->Users[i].k_s_i[j], randomOutput + bytes * j,
                       bytes);
      mpz_mod(vnet->Users[i].k_s_i[j], vnet->Users[i].k_s_i[j],
              vnet->grp.prime);
    }
    free(randomOutput);
    // add G(shat_i,z)
    for (int z = 0; z < vnet->numClients; z++) {
      if (z == i || vnet->Uact1[z] == 0)
        continue;
      // Mask Tag prgArrayTag = G(s hat_i,z)
      PRG((uint8_t *)prgArrayTag, GRAD_SIZE * sizeof(uint32_t),
          vnet->Users[i].sverify[z].val);

      if (z > i) {
        for (int j = 0; j < vnet->grdSize; j++) {
          mpz_add_ui(vnet->Users[i].maskTag[j], vnet->Users[i].maskTag[j],
                     prgArrayTag[j]);
        }
      } else {
        for (int j = 0; j < vnet->grdSize; j++) {
          mpz_sub_ui(vnet->Users[i].maskTag[j], vnet->Users[i].maskTag[j],
                     prgArrayTag[j]);
        }
      }
    }

    // generate G( prgArrayTag = beta hat_i)
    char *betatag;
    size_t betatagSize = mpz_to_byteArray(&betatag, vnet->Users[i].betaVerify);
    padWithZero(&betatag, betatagSize, 32);
    PRG((uint8_t *)prgArrayTag, GRAD_SIZE * sizeof(uint32_t),
        (uint8_t *)betatag);
    free(betatag);
    // add G(betahat_i) to masked local tag
    for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskTag[j], vnet->Users[i].maskTag[j],
                 prgArrayTag[j]);
      mpz_add(vnet->Users[i].maskTag[j], vnet->Users[i].maskTag[j],
              vnet->Users[i].k_s_i[j]);
      mpz_addmul_ui(vnet->Users[i].maskTag[j], vnet->Users[i].k_p[j],
                    vnet->Users[i].plainLocalVector[j]);
      mpz_mod(vnet->Users[i].maskTag[j], vnet->Users[i].maskTag[j],
              vnet->grp.prime);
      mpz_clears(vnet->Users[i].k_p[j], vnet->Users[i].k_s_i[j], NULL);
    }
    free(prgArrayTag);

    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
    Time_Measure(&global_timemeasure);
    time_measured.mask_client.overhead += global_timemeasure.milliseconds;

    // ##### for masking local gradients #######################
    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));

    vnet->Users[i].maskedLocalVector = malloc(vnet->grdSize * sizeof(mpz_t));
    for(int j =0;j<GRAD_SIZE;j++){
      mpz_init(vnet->Users[i].maskedLocalVector[j]);
    }
    uint32_t *prgArray = malloc(vnet->grdSize * sizeof(uint32_t));

    // add G(s_i,z) to local gradient mask
    for (int z = 0; z < vnet->numClients; z++) {
      if (z == i || vnet->Uact1[z] == 0)
        continue;
      // Mask Gradient prgArray = G(s_i,z)
      PRG((uint8_t *)prgArray, GRAD_SIZE * sizeof(uint32_t),
          vnet->Users[i].sdata[z].val);

      if (z > i) {
        for (int j = 0; j < vnet->grdSize; j++) {
          mpz_add_ui(vnet->Users[i].maskedLocalVector[j],
                     vnet->Users[i].maskedLocalVector[j], prgArray[j]);
        }
      } else {
        for (int j = 0; j < vnet->grdSize; j++) {
          mpz_sub_ui(vnet->Users[i].maskedLocalVector[j],
                     vnet->Users[i].maskedLocalVector[j], prgArray[j]);
        }
      }
    }
    // add local gradients to local gradient mask
    for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskedLocalVector[j],
                 vnet->Users[i].maskedLocalVector[j],
                 vnet->Users[i].plainLocalVector[j]);
    }

    // generate prgArray G(beta_i)
    char *betaMasked;
    size_t betaMaskedSize =
        mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
    padWithZero(&betaMasked, betaMaskedSize, 32);
    PRG((uint8_t *)prgArray, GRAD_SIZE * sizeof(uint32_t),
        (uint8_t *)betaMasked);
    free(betaMasked);
    // add G(beta_i) to masked local vector
    for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskedLocalVector[j],
                 vnet->Users[i].maskedLocalVector[j], prgArray[j]);
      mpz_mod(vnet->Users[i].maskedLocalVector[j],
              vnet->Users[i].maskedLocalVector[j], vnet->grp.prime);
    }

    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
    Time_Measure(&global_timemeasure);
    time_measured.mask_client.usual += global_timemeasure.milliseconds;

    free(prgArray);
    free(vnet->Users[i].plainLocalVector);
  } // end for loop for users
}

void UnMask(DscVNet *vnet) {

  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
  vnet->Uact3Active = 0;
  for (int k = 0; k < vnet->numClients; k++) {
    vnet->Uact3Active += vnet->Uact3[k];
  }

  if (vnet->Uact2Active < vnet->thrshld || vnet->Uact3Active < vnet->thrshld) {
    printf("\nUNMAsk: Not enough active users to continue\n");
    exit(1);
  }
  int t = 0;
  for (int j = 0; j < vnet->numClients; j++) {
    if (vnet->Uact3[j] == 1) {
      // server gets the Uact3's sharess
      mpz_set(vnet->thrcrypt.thss.shares_x[t], vnet->Users[j].shares_x);
      mpz_set(vnet->thrcrypt.thss.shares_y[t], vnet->Users[j].shares_y);
      t += 1;
    }
    mpz_clears(vnet->Users[j].shares_x, vnet->Users[j].shares_y, NULL);
  }
  for (int i = 0; i < vnet->numClients; i++) {
    if (vnet->Uact2[i] == 1 && vnet->Uact3[i] == 0) {
      // Decrypts B_i for Uact2 that have gone offline
      vnet->thrcrypt.cipher = vnet->Users[i].B;
      ThrCrypt_Dec(&(vnet->thrcrypt));
      char *betaMasked = malloc(vnet->Users[i].betaMaskedSize);
      char *betaVerify = malloc(vnet->Users[i].betaVerifySize);
      memcpy(betaMasked, vnet->thrcrypt.plaintextOutput,
             vnet->Users[i].betaMaskedSize);
      memcpy(betaVerify,
             vnet->thrcrypt.plaintextOutput + vnet->Users[i].betaMaskedSize,
             vnet->Users[i].betaVerifySize);
      byteArray_to_mpz(vnet->Users[i].betaMasked, betaMasked,
                       vnet->Users[i].betaMaskedSize);
      byteArray_to_mpz(vnet->Users[i].betaVerify, betaVerify,
                       vnet->Users[i].betaVerifySize);
      free(betaMasked);
      free(betaVerify);
      free(vnet->thrcrypt.plaintextOutput);
    }
    if (vnet->Uact1[i] == 1 && vnet->Uact2[i] == 0) {
      // decrypts P_i for users whose G(s_i,j) is not included in the sum
      vnet->thrcrypt.cipher = vnet->Users[i].P;
      ThrCrypt_Dec(&(vnet->thrcrypt));
      vnet->Users[i].P = vnet->thrcrypt.cipher;
      memcpy(vnet->Users[i].sdata, vnet->thrcrypt.plaintextOutput,
             sizeof(Seed) * USERS_SIZE);
      memcpy(vnet->Users[i].sverify,
             vnet->thrcrypt.plaintextOutput + USERS_SIZE * sizeof(Seed),
             sizeof(Seed) * USERS_SIZE);
      free(vnet->thrcrypt.plaintextOutput);
    }
    if (vnet->Uact1[i] == 1) {
      Cipher_Free(&(vnet->Users[i].B));
      Cipher_Free(&(vnet->Users[i].P));
    }
  }

  t = 0;
  for (int j = 0; j < vnet->numClients; j++) {
    if (vnet->Uact3[j] == 0)
      continue;
    // server gets the Uact3's sharess
    mpz_set_ui(vnet->thrcrypt.thss.shares_x[t], 0);
    mpz_set_ui(vnet->thrcrypt.thss.shares_y[t], 0);
    t += 1;
  }
  uint32_t *prgArray = malloc(vnet->grdSize * sizeof(uint32_t));
  uint32_t *prgArrayTag = malloc(vnet->grdSize * sizeof(uint32_t));

  for (int k = 0; k < vnet->grdSize; k++) {
    mpz_init(vnet->tagGlobalVector[k]);
    mpz_init(vnet->gradGlobalVector[k]);
  }
  for (int i = 0; i < vnet->numClients; i++) {
    if (vnet->Uact2[i] == 1) {

      // generate prgArray G(beta_i)
      char *betaMasked;
      size_t betaMaskedSize =
          mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
      padWithZero(&betaMasked, betaMaskedSize, 32);
      PRG((uint8_t *)prgArray, GRAD_SIZE * sizeof(uint32_t),
          (uint8_t *)betaMasked);
      free(betaMasked);

      // generate G( prgArrayTag = beta hat_i)
      char *betatag;
      size_t betatagSize =
          mpz_to_byteArray(&betatag, vnet->Users[i].betaVerify);
      padWithZero(&betatag, betatagSize, 32);
      PRG((uint8_t *)prgArrayTag, GRAD_SIZE * sizeof(uint32_t),
          (uint8_t *)betatag);
      free(betatag);

      for (int j = 0; j < vnet->grdSize; j++) {
        mpz_add(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
                vnet->Users[i].maskedLocalVector[j]);
        mpz_clear(vnet->Users[i].maskedLocalVector[j]);
        mpz_sub_ui(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
                   prgArray[j]);

        mpz_add(vnet->tagGlobalVector[j], vnet->tagGlobalVector[j],
                vnet->Users[i].maskTag[j]);
        mpz_clear(vnet->Users[i].maskTag[j]);
        mpz_sub_ui(vnet->tagGlobalVector[j], vnet->tagGlobalVector[j],
                   prgArrayTag[j]);
      }
    }
    mpz_clears(vnet->Users[i].betaMasked, vnet->Users[i].betaVerify, NULL);
  }

  for (int i = 0; i < vnet->numClients; i++) {
    if (vnet->Uact2[i] == 1) {

      free(vnet->Users[i].maskedLocalVector);
      free(vnet->Users[i].maskTag);
    }
    if (vnet->Uact1[i] == 0 || vnet->Uact2[i] == 1)
      continue;
    for (int z = 0; z < vnet->numClients; z++) {
      if (z == i || vnet->Uact1[z] == 0)
        continue;
      // Mask Gradient prgArray = G(s_i,z)
      PRG((uint8_t *)prgArray, GRAD_SIZE * sizeof(uint32_t),
          vnet->Users[i].sdata[z].val);

      // Mask Tag prgArrayTag = G(s hat_i,z)
      PRG((uint8_t *)prgArrayTag, GRAD_SIZE * sizeof(uint32_t),
          vnet->Users[i].sverify[z].val);

      if (z > i) {
        for (int j = 0; j < vnet->grdSize; j++) {
          mpz_add_ui(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
                     prgArray[j]);
          mpz_add_ui(vnet->tagGlobalVector[j], vnet->tagGlobalVector[j],
                     prgArrayTag[j]);
        }
      } else {
        for (int j = 0; j < vnet->grdSize; j++) {
          mpz_sub_ui(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
                     prgArray[j]);
          mpz_sub_ui(vnet->tagGlobalVector[j], vnet->tagGlobalVector[j],
                     prgArrayTag[j]);
        }
      }
    }
  }
  for (int j = 0; j < vnet->grdSize; j++) {
    mpz_mod(vnet->gradGlobalVector[j], vnet->gradGlobalVector[j],
            vnet->grp.prime);
    mpz_mod(vnet->tagGlobalVector[j], vnet->tagGlobalVector[j],
            vnet->grp.prime);
  }
  free(prgArray);
  free(prgArrayTag);

  clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
  Time_Measure(&global_timemeasure);
  time_measured.unmask_server.usual += global_timemeasure.milliseconds;
}

void Verify(DscVNet *vnet)
{
  for(int ii =0;ii<USERS_SIZE;ii++)
  {
    if(vnet->Uact3[ii]==0)
      continue;
  

    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.start)));
  
    bool vrfy = true;
    
    uint8_t str1 [6]={0};
    str1[0] = (vnet->rndlbl >> 24) & 0xFF;
    str1[1] = (vnet->rndlbl >> 16) & 0xFF;
    str1[2] = (vnet->rndlbl >> 8) & 0xFF;
    str1[3] = vnet->rndlbl & 0xFF;
    mpz_t *k_p = malloc(GRAD_SIZE*sizeof(mpz_t));
    size_t bytes = (mpz_sizeinbase(vnet->grp.prime, 2) + 7) / 8; //number of bytes of prime q
    char* randomOutput = malloc(GRAD_SIZE*bytes);

    uint8_t t[32];
    PRF(t,vnet->vk,sizeof(vnet->vk),str1,sizeof(str1));
    PRG((uint8_t*)randomOutput,GRAD_SIZE*bytes,t);
    for(int j=0;j<GRAD_SIZE;j++){
       mpz_init(k_p[j]);
       byteArray_to_mpz(k_p[j], randomOutput+j*bytes, bytes);
       mpz_mod(k_p[j],k_p[j],vnet->grp.prime);
    }
    mpz_t* k_s = malloc(GRAD_SIZE*sizeof(mpz_t));
    for(int j=0;j<GRAD_SIZE;j++){
       mpz_init(k_s[j]);
    }
    mpz_t k_s_i;
    mpz_init(k_s_i);
    for(uint16_t user=0;user<vnet->numClients;user++){
       if(vnet->Uact2[user]==0)
          continue;
       str1[4] = (user>>8)&0xFF;
       str1[5] = user & 0xFF;

       PRF(t,vnet->vk,sizeof(vnet->vk),str1,sizeof(str1));
       PRG((uint8_t*) randomOutput,GRAD_SIZE*bytes,t);
       for(int j=0;j<GRAD_SIZE;j++){
          byteArray_to_mpz(k_s_i, randomOutput+bytes*j, bytes);
          mpz_add(k_s[j],k_s[j],k_s_i);
       }
    }
    free(randomOutput);
    mpz_clear(k_s_i);

    mpz_t *tagPrime = malloc(vnet->grdSize * sizeof(mpz_t));
    
    for(int j =0;j<vnet->grdSize;j++){
       mpz_init(tagPrime[j]);
       mpz_addmul(tagPrime[j],k_p[j],vnet->gradGlobalVector[j]);
       mpz_add(tagPrime[j],tagPrime[j],k_s[j]);
       mpz_clear(k_s[j]);
       mpz_clear(k_p[j]);
    }
    free(k_s);
    free(k_p);
    for(int k=0;k<vnet->grdSize;k++){
       //gmp_printf("tagPrime[%d] = %Zd\n",k,tagPrime[k]);
       //gmp_printf("tagGlobal[%d] = %Zd\n",k,vnet->tagGlobalVector[k]);

       mpz_mod(tagPrime[k],tagPrime[k],vnet->grp.prime);
       int result = mpz_cmp(vnet->tagGlobalVector[k],tagPrime[k]);
       mpz_clear(tagPrime[k]);
       if(result != 0){
          printf("\ninvalid\n");
          exit(1);
       }
    }
    free(tagPrime);


    clock_gettime(CLOCK_MONOTONIC, (&(global_timemeasure.end)));
    Time_Measure(&global_timemeasure);
    time_measured.verification_client += global_timemeasure.milliseconds;
  }
}

void randomly_zero_out(uint8_t *dest, uint8_t *src, size_t size,
                       double percentage) {
  size_t count = (size_t)(size * percentage); // Number of elements to set to 0
  size_t i, selected;

  // Copy src to dest
  for (i = 0; i < USERS_SIZE; i++) {
    dest[i] = src[i]; // Copy previous array
  }

  // Randomly select 'count' indices where src[i] is 1
  srand(time(NULL));
  for (i = 0; i < count; i++) {
    do {
      selected = rand() % size; // Pick a random index
    } while (dest[selected] == 0); // Ensure we only zero out once
    dest[selected] = 0;
  }
}

int main()
{
  
  DscVNet *vnet;
  DscTimeMeasure timemeasure;
  vnet = malloc(sizeof(DscVNet));
  uint32_t size = GRAD_SIZE * sizeof(uint32_t);

  printf("\n** Dropout = %f, n = %d, gradient size: %d, iterations: %d**\n",
         (float)DropOut, USERS_SIZE, GRAD_SIZE, ITERATIONS);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  Config(vnet);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  print_timemeasure_header();
  print_timemeasure(&timemeasure, 0, "Config");

  randomly_zero_out(vnet->Uact1, vnet->Uact1, vnet->numClients, DropOut);
  randomly_zero_out(vnet->Uact2, vnet->Uact1, (1 - DropOut) * USERS_SIZE,
                    DropOut);
  randomly_zero_out(vnet->Uact3, vnet->Uact2,
                    (1 - DropOut) * (1 - DropOut) * USERS_SIZE, DropOut);

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  Init(vnet);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  print_timemeasure(&timemeasure, 0, "Init");
  const int show_iteration = 5; // how many iterations to show
  for (int iter = 0; iter < ITERATIONS; iter++) {

    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
    KeyShare(vnet);
    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
    Time_Measure(&timemeasure);
    if (iter < show_iteration)
      print_timemeasure(&timemeasure, iter, "KeyShare");

    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
    Mask(vnet);
    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
    Time_Measure(&timemeasure);
    if (iter < show_iteration)
      print_timemeasure(&timemeasure, iter, "Mask");

    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
    UnMask(vnet);
    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
    Time_Measure(&timemeasure);
    if (iter < show_iteration)
      print_timemeasure(&timemeasure, iter, "UnMask");

    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
    Verify(vnet);
    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
    Time_Measure(&timemeasure);
    if (iter < show_iteration) {
      print_timemeasure(&timemeasure, iter, "Verify");
      printf("\n*************************************************************"
             "****"
             "**********************\n");
    }
    if (iter >= show_iteration)
      printf("\r[iter:%d]calculating the rest", iter);
    if ((iter >= show_iteration) && ((iter % 2) == 1)) {
      switch ((iter / 2) % 5) {
      case 0:
        printf(" #     ");
        fflush(stdout);
        break;
      case 1:
        printf(" ##    ");
        fflush(stdout);
        break;
      case 2:
        printf(" ###   ");
        fflush(stdout);
        break;
      case 3:
        printf(" ####  ");
        fflush(stdout);
        break;
      case 4:
        printf(" ##### ");
        fflush(stdout);
        break;
      }
    }

    if ((iter < (ITERATIONS - 1)) && iter < (show_iteration - 1))
      print_timemeasure_header();
  }
  printf("\r***Verification Successful for all users and iterations***\n");
  //print time result
  // take the average
  time_measured.keyshare_client = time_measured.keyshare_client / (ITERATIONS*(vnet->Uact1Active));
  time_measured.keyshare_server = time_measured.keyshare_server / ITERATIONS;

  time_measured.mask_client.usual =
      time_measured.mask_client.usual / (ITERATIONS*(vnet->Uact2Active));
  time_measured.mask_client.overhead =
      time_measured.mask_client.overhead / (ITERATIONS*(vnet->Uact2Active));
  time_measured.mask_server = time_measured.mask_server / ITERATIONS;

  time_measured.unmask_client = time_measured.unmask_client / (ITERATIONS*(vnet->Uact3Active));
  time_measured.unmask_server.usual =
      time_measured.unmask_server.usual / (ITERATIONS*(vnet->Uact3Active));
  time_measured.unmask_server.overhead =
      time_measured.unmask_server.overhead / ITERATIONS;

  time_measured.verification_client =
      time_measured.verification_client / (ITERATIONS*(vnet->Uact3Active));
  time_measured.verification_server =
      time_measured.verification_server / ITERATIONS;

  double total_client = time_measured.keyshare_client+
      time_measured.mask_client.usual+time_measured.mask_client.overhead+time_measured.unmask_client
      +time_measured.verification_client;
  double total_server = time_measured.keyshare_server+time_measured.mask_server
      +time_measured.unmask_server.usual+time_measured.unmask_server.overhead+
      time_measured.verification_server;
  // print the result
  printf("\nDropout = %3.2f, n = %4d, gradient size: %4d, iterations: %4d, threshold: %4d\n",
         (float)DropOut, USERS_SIZE, GRAD_SIZE, ITERATIONS,Threshold);
  printf("\n");
  printf("================================ Time Result In Miliseconds ================== \n");
  printf("|              |            Client            |            Server            |\n");
  printf("------------------------------------------------------------------------------\n");
  printf("|   KeyShare   |  %26.2f  |  %26.2f  |\n", time_measured.keyshare_client,time_measured.keyshare_server);
  printf("------------------------------------------------------------------------------\n");
  printf("|     Mask     |  %12.2f+%-13.2f  |  %26.2f  |\n", time_measured.mask_client.usual,time_measured.mask_client.overhead,time_measured.mask_server);
  printf("------------------------------------------------------------------------------\n");
  printf("|    Unmask    |  %26.2f  |  %12.2f+%-13.2f  |\n", time_measured.unmask_client,time_measured.unmask_server.usual,time_measured.unmask_server.overhead);
  printf("------------------------------------------------------------------------------\n");
  printf("|    Verify    |  %26.2f  |  %26.2f  |\n", time_measured.verification_client,time_measured.verification_server);
  printf("------------------------------------------------------------------------------\n");
  printf("|    Total     |  %26.2f  |  %26.2f  |\n", total_client,total_server);
  printf("------------------------------------------------------------------------------\n");


  for(int i =0;i<GRAD_SIZE;i++){
   mpz_clears(vnet->gradGlobalVector[i],vnet->tagGlobalVector[i],NULL);
  }
  for(int i=0;i<USERS_SIZE;i++){
   mpz_clears(vnet->Users[i].skey,vnet->Users[i].pkey,NULL);
  }
  free(vnet->gradGlobalVector);
  free(vnet->tagGlobalVector);
  free(vnet->Users);
  ThrCrypt_Free(&(vnet->thrcrypt));
  GroupGen_Free(&(vnet->grp));
  free(vnet);
  return 0;
}
