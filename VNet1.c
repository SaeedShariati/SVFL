#include <pbc/pbc.h>
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

#include "CryptoPrimitivesV1.h"

/********** Command for compile (FAIRSHARE (.c) + CryptoPrimitives (.c and .h))
*************************************************************

gcc VNet.c VNet.c -o VNet -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc 
   -lgmp -l tomcrypt -l m

*********************************************************************************************************************************************/
#define GRAD_SIZE 3
#define USERS_SIZE 2
#define SEC_PARAM  16
#define Threshold 5
typedef struct {
   int Uid; // Unique ID for the user
   //unsigned char *vk;
   mpz_t skey;
   mpz_t pkey;
   mpz_t shares_x;      // id related to thss
   mpz_t shares_y;      // secret share related to thss
   //mpz_t *sharedSecret; // shared secret of this user with other users(same thing as k in the paper)
   int *plainLocalVector;
   int32_t *maskedLocalVector;
   int32_t *maskTag;

   mpz_t betaMasked, betaVerify;
   u_int32_t betaMaskedSize,betaVerifySize;

   DscPRF prf;
   DscHash hash;

   char **sdata; //s_i,j ,16 bytes each
   char **sverify; //s_i,j hat ,16 bytes each

   // output thrcrypt
   DscCipher P;
   DscCipher B;

   // for using in tag
   int *k_p;
   int *k_s_i;

} DscClient;

////////////////////////////////////
typedef struct {
   // DscPRG prg;
   DscGrp grp;

   DscThrCrypt thrcrypt;

   int secparam;   // Security parameter
   int numClients; // Number of clients
   int thrshld;    // Threshold
   int grdSize;
   int rndlbl;

   u_int8_t *Uact1, *Uact2, *Uact3;

   int32_t *gradGlobalVector;
   int32_t *tagGlobalVector;

   DscClient *Users; // Array of users (clients)
   mpz_t vk;

} DscVNet;

void generate_random_mpz_vnet(DscVNet *vnet, mpz_ptr rndelement)
{

   mpz_urandomm(rndelement, vnet->grp.state, vnet->grp.prime);
}
//turns mpz_t into an array of bytes and returns the number of bytes
u_int32_t mpz_to_byteArray(char** rop, mpz_ptr integer){
    size_t count = 0;
    size_t size_in_bytes = (mpz_sizeinbase(integer, 2) + 7) / 8;
    *rop = (char*)malloc(size_in_bytes);
    if (!*rop) return 0;  // malloc failed
    mpz_export(*rop, &count, 1, sizeof(char), 1, 0, integer);

    return (uint32_t)count;
}
void byteArray_to_mpz(mpz_ptr rop, char *byteArray, u_int32_t size) {
  mpz_import(rop, size, 1, sizeof(char), 0, 0,
              byteArray);
}
void VNET_Config(DscVNet *vnet)
{

   vnet->secparam = SEC_PARAM;
   vnet->thrshld = Threshold;
   vnet->numClients = USERS_SIZE;
   vnet->grdSize = GRAD_SIZE;
   vnet->rndlbl = 1;

   vnet->Uact1 = calloc(vnet->numClients ,sizeof(uint8_t));
   vnet->Uact2 = calloc(vnet->numClients , sizeof(uint8_t));
   vnet->Uact3 = calloc(vnet->numClients , sizeof(uint8_t));

   vnet->gradGlobalVector = malloc(vnet->grdSize * sizeof(int32_t));
   vnet->tagGlobalVector = malloc(vnet->grdSize * sizeof(int32_t));

   GroupGen_Config(&(vnet->grp),512);
   // Allocate memory for the array of users

   vnet->Users = malloc(vnet->numClients * sizeof(DscClient));

   // THRCRYPT
   ThrCrypt_Config(&(vnet->thrcrypt), 512, vnet->numClients,
                   vnet->thrshld);
                   
   mpz_init(vnet->vk);
   // Initialize each user's UID and random gradients
   for (int i = 0; i < vnet->numClients; i++) {
      vnet->Users[i].Uid = i; // Example: Assign UIDs from 0 to numClients-1

      // Phase 1: All users active (100%)
      vnet->Uact1[i] = 1;

      mpz_init(vnet->Users[i].skey);
      mpz_init(vnet->Users[i].pkey);
      mpz_inits(vnet->Users[i].shares_x,vnet->Users[i].shares_y,NULL);
      mpz_inits(vnet->Users[i].betaMasked,vnet->Users[i].betaVerify,NULL);


      // To initialize local data vector for each user
      srand(time(NULL));
      vnet->Users[i].plainLocalVector = calloc(vnet->grdSize, sizeof(int32_t));
      vnet->Users[i].maskedLocalVector = calloc(vnet->grdSize, sizeof(int32_t));
      vnet->Users[i].maskTag = calloc(vnet->grdSize, sizeof(int32_t));

      for (int j = 0; j < vnet->grdSize; j++) {
         vnet->Users[i].plainLocalVector[j] = i;
      }

      // To initialize PRF for each user
      PRF_Config(&(vnet->Users[i].prf), 16);
      PRF_KeyGen(&(vnet->Users[i].prf));

      // To initialize HASH for each user
      Hash_Config(&(vnet->Users[i].hash), 32);
      vnet->Users[i].sdata = malloc((vnet->numClients-1) * sizeof(char *));
      vnet->Users[i].sverify = malloc((vnet->numClients-1) * sizeof(char *));

      vnet->Users[i].k_p = malloc(sizeof(int32_t));
      vnet->Users[i].k_s_i = malloc(sizeof(int32_t));
   }
}

void VNET_Init(DscVNet *vnet)
{
   GroupGen(&(vnet->grp));
   ThrCrypt_DKeyGen(&(vnet->thrcrypt),&(vnet->grp));
   generate_random_mpz_vnet(vnet, vnet->vk);

   for (int i = 0; i < vnet->numClients; i++) {

      generate_random_mpz_vnet(vnet, vnet->Users[i].skey);

      mpz_powm(vnet->Users[i].pkey, (vnet->grp).generator, vnet->Users[i].skey, vnet->grp.prime);
      mpz_set(vnet->Users[i].shares_x,vnet->thrcrypt.thss.shares_x[i]);
      mpz_set(vnet->Users[i].shares_y,vnet->thrcrypt.thss.shares_y[i]); // sk_i^t = (shares_x[i],shares_y[i])
      mpz_clears(vnet->thrcrypt.thss.shares_x[i],vnet->thrcrypt.thss.shares_y[i],NULL); //server doesn't have sk_i^t yet

   }
}

void VNET_KeyShare(DscVNet *vnet, int i)
{
   vnet->Uact1[i]=1; 
   generate_random_mpz_vnet(vnet, vnet->Users[i].betaMasked);
   generate_random_mpz_vnet(vnet, vnet->Users[i].betaVerify);

   size_t count;
   char /* *temp1, *temp2,*/ *temp3;
   char *str1 = calloc(16 , sizeof(unsigned char));
   char *str2 = calloc(16 , sizeof(unsigned char));

   vnet->Users[i].hash.plaintextInput = calloc(128, sizeof(char));
   for (int z = 0; z < vnet->numClients && z != i; z++) {
      mpz_t k;
      mpz_init(k);
      char* sharedSecret; 
      mpz_powm(k, vnet->Users[i].pkey,
         vnet->Users[z].skey, vnet->grp.prime);
      mpz_to_byteArray(&sharedSecret, k);
      memcpy(vnet->Users[i].prf.key, sharedSecret, 16); //F_k, k is the same for users i,j
      free(sharedSecret);

      sprintf((char *)str1, "%d,%d", vnet->rndlbl, 0); //used for generating s_i,j
      sprintf((char *)str2, "%d,%d", vnet->rndlbl, 1); //used for generating s_i,j'
      //initialize s_i,j
      PRF_Eval(&(vnet->Users[i].prf),str1,16);
      vnet->Users[i].sdata[z] = malloc(16 * sizeof(char));
      memcpy(vnet->Users[i].sdata[z],vnet->Users[i].prf.randomOutput,16);
      //initialize s_i,j'
      PRF_Eval(&(vnet->Users[i].prf),str2,16);
      vnet->Users[i].sverify[z] = malloc(16 * sizeof(char));
      memcpy(vnet->Users[i].sverify[z], vnet->Users[i].prf.randomOutput,16);
   }
   free(str1);free(str2);

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

   char* P = malloc(2*(vnet->numClients-1)*16);
   for (int j = 0; j < vnet->numClients && j != i; j++) {
      memcpy(P+j*16,vnet->Users[i].sdata[j],16);
      memcpy(P+(vnet->numClients-1+j)*16,vnet->Users[i].sverify[j],16);
   }
   ThrCrypt_Enc(&(vnet->thrcrypt), P, 2*(vnet->numClients-1)*16);
   vnet->Users[i].P = vnet->thrcrypt.cipher;
   free(P);
}

// Convert Prg bytes to int numbers
void bytes_to_ints(unsigned char *byteArray, uint32_t *intArray, int size)
{
   for (int i = 0; i < size; i++) {
      int index = i * 4; // Each int is 4 bytes

      // Convert from Big-Endian to system's Endian format
      intArray[i] = ((uint32_t)byteArray[index] << 24) | 
      ((uint32_t)byteArray[index + 1] << 16) |
                    ((uint32_t)byteArray[index + 2] << 8)
                     | ((uint32_t)byteArray[index + 3]);
   }
}

void VNET_Mask(DscVNet *vnet, int i, DscPRG *prg)
{
   size_t count;
   char *temp1, *temp2, *temp3, *temp4;

   uint32_t *prgArray = malloc(vnet->grdSize * sizeof(uint32_t));
   int32_t *Sum_prgArray = malloc(vnet->grdSize * sizeof(int32_t));
   memset(Sum_prgArray, 0, vnet->grdSize * sizeof(int32_t));

   uint32_t *prgArrayTag = malloc(vnet->grdSize * sizeof(uint32_t));
   int32_t *Sum_prgArrayTag = malloc(vnet->grdSize * sizeof(int32_t));
   memset(Sum_prgArrayTag, 0, vnet->grdSize * sizeof(int32_t));

   char *str1 = malloc(16 * sizeof(unsigned char));
   char *str2 = malloc(16 * sizeof(unsigned char));

   sprintf((char *)str1, "%d,%d", vnet->rndlbl, 0);
   sprintf((char *)str2, "%d,%d", vnet->rndlbl, i); // shouldn't i be zero or one???

   // Prf key

   //memcpy(vnet->Users[i].prf.key, vnet->Users[i].vk, vnet->secparam);
   //printf("\n %s \n", vnet->vk);

   //  strcpy((char *)vnet->Users[i].prf.key, (const char *)vnet->Users[i].vk);

   /* temp3 = realloc(vnet->Users[i].prf.randomOutput, (prg->extendedRate) * ((&(prg->hmac))->secparam));
   if (temp3 != NULL) {
      vnet->Users[i].prf.randomOutput = temp3;
   }  */


   temp1 = realloc(prg->hmac.key, 128 * sizeof(char));
   if (temp1 != NULL) {
      prg->hmac.key = temp1;
   }
   
   temp2 = realloc(prg->hmac.DigestOutput, vnet->grdSize*4 * sizeof(char));
   if (temp2 != NULL) {
      prg->hmac.DigestOutput = (unsigned char*)temp2;
   }
   
   temp3 = realloc(prg->randomOutput, prg->size);
   if (temp3 != NULL) {
      prg->randomOutput = (unsigned char*)temp3;
   } 
   
   strcpy((char *)vnet->Users[i].prf.plaintextInput, (const char *)str1);

   PRF_Eval(&(vnet->Users[i].prf),str1,16);
   printf("\nPRF output: ");
   for (int p = 0; p < 10; p++) {
      printf("%02x", vnet->Users[i].prf.randomOutput[p]);
   }
   printf("\n\n"); 

   memcpy((prg->hmac.key),vnet->Users[i].prf.randomOutput, 16);
   //strncpy((prg->hmac.key), (const char *)vnet->Users[i].prf.randomOutput, 128);
   // printf ("\nPRG key: ");
   // for (int p = 0; p < 10; p++) {
   //    printf("%02x", prg->hmac.key[p]);
   // }
   // printf("111111111111s\n\n");
   PRG_Eval(prg);
   memcpy((char *)vnet->Users[i].k_p, (const char *)prg->randomOutput,sizeof(int));
   
   PRF_Eval(&(vnet->Users[i].prf),str2,16);
   memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].prf.randomOutput, 16);
   //PRF_Eval(&(vnet->Users[i].prf));

   PRG_Eval(prg);
   memcpy((char *)vnet->Users[i].k_s_i, (const char *)prg->randomOutput,sizeof(int));

   for (int z = 0; z < vnet->numClients; z++) {
      if (z != i) {

         memset(prgArray, 0, vnet->grdSize);
         memset(prgArrayTag, 0, vnet->grdSize);

         // Mask Gradient
         //strncpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sdata[z], 128);
         memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sdata[z], 16);
         PRG_Eval(prg);
         bytes_to_ints(prg->randomOutput, prgArray, vnet->grdSize);

         // Mask Tag
         //strncpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sverify[z], 128);
         memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sverify[z], 16);

         PRG_Eval(prg);
         // Convert bytes to integer array
         bytes_to_ints(prg->randomOutput, prgArrayTag, vnet->grdSize);

         if (z > i) {
            for (int j = 0; j < vnet->grdSize; j++) {
               Sum_prgArray[j] = Sum_prgArray[j] + prgArray[j];
               Sum_prgArrayTag[j] = Sum_prgArrayTag[j] + prgArrayTag[j];
            }

         } else {
            for (int j = 0; j < vnet->grdSize; j++) {
               Sum_prgArray[j] = Sum_prgArray[j] - prgArray[j];
               Sum_prgArrayTag[j] = Sum_prgArrayTag[j] - prgArrayTag[j];
            }
         }
      } else {
         continue;
      }
   }

   for (int j = 0; j < vnet->grdSize; j++) {
      vnet->Users[i].maskedLocalVector[j] += vnet->Users[i].plainLocalVector[j];
      vnet->Users[i].maskedLocalVector[j] += Sum_prgArray[j];
      vnet->Users[i].maskTag[j] += Sum_prgArrayTag[j];
   }

   // Add PRG-Beta to mask
   temp4 = malloc(128 * sizeof(unsigned char *));
   mpz_export((char *)temp4, &count, 1, sizeof(unsigned char), 0, 0, vnet->Users[i].betaMasked);
   memcpy((char *)prg->hmac.key, (char *)temp4, 16);
   PRG_Eval(prg);
   memset(prgArray, 0, vnet->grdSize * sizeof(uint32_t));
   bytes_to_ints(prg->randomOutput, prgArray, vnet->grdSize);
   for (int j = 0; j < vnet->grdSize; j++) {
      vnet->Users[i].maskedLocalVector[j] += prgArray[j];
   }

   // Add PRG-Betatag to mask Tag
   // temp4 = malloc(128 * sizeof(unsigned char *));
   mpz_export((char *)temp4, &count, 1, sizeof(unsigned char), 0, 0, vnet->Users[i].betaVerify);
   memcpy((char *)prg->hmac.key, (char *)temp4, 16);
   PRG_Eval(prg);
   memset(prgArrayTag, 0, vnet->grdSize * sizeof(uint32_t));
   bytes_to_ints(prg->randomOutput, prgArrayTag, vnet->grdSize);
   for (int j = 0; j < vnet->grdSize; j++) {

      vnet->Users[i].maskTag[j] +=
          ((uint32_t)(*vnet->Users[i].k_p) * vnet->Users[i].plainLocalVector[j] + (uint32_t)(*vnet->Users[i].k_s_i));
      vnet->Users[i].maskTag[j] += prgArrayTag[j];
   }
}

void VNET_UNMask(DscVNet *vnet, DscPRG *prg)
{
   size_t count;
   unsigned char *temp4;

   uint32_t *prgArray = malloc(vnet->grdSize * sizeof(uint32_t));
   int32_t *Sum_prgArray = malloc(vnet->grdSize * sizeof(int32_t));
   memset(Sum_prgArray, 0, vnet->grdSize * sizeof(int32_t));

   uint32_t *prgArrayTag = malloc(vnet->grdSize * sizeof(uint32_t));
   int32_t *Sum_prgArrayTag = malloc(vnet->grdSize * sizeof(int32_t));
   memset(Sum_prgArrayTag, 0, vnet->grdSize * sizeof(int32_t));

   for (int j = 0; j < vnet->grdSize; j++)
      for (int i = 0; i < vnet->numClients; i++) {
         Sum_prgArray[j] += vnet->Users[i].maskedLocalVector[j];
         Sum_prgArrayTag[j] += vnet->Users[i].maskTag[j];
      }

   // Add MaskBeta to mask
   for (int i = 0; i < vnet->numClients; i++) {
      //128 -> 16
      temp4 = malloc(128 * sizeof(unsigned char *));
      mpz_export((char *)temp4, &count, 1, sizeof(unsigned char), 0, 0, vnet->Users[i].betaMasked);
      //strncpy((char *)prg->hmac.key, (char *)temp4, 128);
      memcpy((char *)prg->hmac.key, (char *)temp4, 16);
      free(temp4);
      PRG_Eval(prg);
      memset(prgArray, 0, vnet->grdSize * sizeof(uint32_t));
      bytes_to_ints(prg->randomOutput, prgArray, vnet->grdSize);
      for (int j = 0; j < vnet->grdSize; j++) {
         Sum_prgArray[j] -= prgArray[j];
      }

   }

   // Add Maskverify to mask
   for (int i = 0; i < vnet->numClients; i++) {
      temp4 = malloc(128 * sizeof(unsigned char *));
      mpz_export((char *)temp4, &count, 1, sizeof(unsigned char), 0, 0, vnet->Users[i].betaVerify);
      //strncpy((char *)prg->hmac.key, (char *)temp4, 128);
      memcpy((char *)prg->hmac.key, (char *)temp4, 16);
      free(temp4);

      PRG_Eval(prg);
      memset(prgArray, 0, vnet->grdSize * sizeof(uint32_t));
      bytes_to_ints(prg->randomOutput, prgArray, vnet->grdSize);
      for (int j = 0; j < vnet->grdSize; j++) {
         Sum_prgArrayTag[j] -= prgArray[j];
      }
   }

   for (int j = 0; j < vnet->grdSize; j++) {
      vnet->gradGlobalVector[j] = Sum_prgArray[j];
      vnet->tagGlobalVector[j] = Sum_prgArrayTag[j];
      //printf("%ld, %ld \t", vnet->gradGlobalVector[j], vnet->tagGlobalVector[j]);
   }
   printf("\n");
}

void VNET_Vrfy(DscVNet *vnet, int i)
{
   bool vrfy = true;

   int32_t *maskTagPrime = malloc(vnet->grdSize * sizeof(int32_t));
   int32_t *tagPrime = malloc(vnet->grdSize * sizeof(int32_t));
   memset(tagPrime, 0, vnet->grdSize * sizeof(int32_t));

   for (int i = 0; i < vnet->numClients; i++) {
      for (int j = 0; j < vnet->grdSize; j++) {

         tagPrime[j] += (*vnet->Users[i].k_s_i);
      }
   }

   for (int j = 0; j < vnet->grdSize; j++) {
      maskTagPrime[j] = (*vnet->Users[i].k_p) * vnet->gradGlobalVector[j] + tagPrime[j];
      // printf("%d ,%ld, %ld , %ld \n",j,vnet->gradGlobalVector[j],  maskTagPrime[j],vnet->tagGlobalVector[j]);
      if (maskTagPrime[j] != vnet->tagGlobalVector[j]) {
         vrfy = false;

         printf("%d , %d \n", maskTagPrime[j], vnet->tagGlobalVector[j]);
         break;
      }
   }
   if (vrfy)
      printf("valid\n");
   else
      printf("invalid\n");
}

void randomly_zero_out(uint8_t *dest, uint8_t *src, size_t size, double percentage)
{
   size_t count = (size_t)(size * percentage); // Number of elements to set to 0
   size_t i, selected;

   // Copy src to dest
   for (i = 0; i < size; i++) {
      dest[i] = src[i]; // Copy previous array
   }

   // Randomly select 'count' indices where src[i] is 1
   for (i = 0; i < count; i++) {
      do {
         selected = rand() % size; // Pick a random index
      } while (dest[selected] == 0); // Ensure we only zero out once

      dest[selected] = 0;
   }
}

int main()
{

  DscTimeMeasure timemeasure;

  uint32_t size = GRAD_SIZE*4;

  DscPRG prg2;
  PRG_Config(&prg2, SEC_PARAM, size);
  PRG_SeedGen(&prg2);

  DscVNet vnet;

  VNET_Config(&vnet);

  VNET_Init(&vnet);

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  for (int i = 0; i < vnet.numClients; i++) {
     VNET_KeyShare(&vnet, i);
  }
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("\nElapsed Time for key is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);

  //    // Step 2: Set 10% of indices in Uact2 to 0 based on Uact1
  //    randomly_zero_out(vnet.Uact2, vnet.Uact1, vnet.numClients, 0.10);

  //    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  //    for (int i = 0; i < 1; i++) {
  //       // if (vnet.Uact2[i] == 1)
  //       VNET_Mask(&vnet, i, &prg2);
  //    }
  //    PRG_Free(&prg2);
  //    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  //    Time_Measure(&timemeasure);
  //    printf("\nElapsed Time for Mask Function is as below:\n");
  //    printf("In Seconds: %ld\n", timemeasure.seconds);
  //    printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  //    printf("In Microseconds: %ld\n", timemeasure.microseconds);
  //    printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);

  //    // Step 3: Set 10% of indices in Uact3 to 0 based on Uact2

  //    DscPRG prg;
  //    PRG_Config(&prg, SEC_PARAM, size);
  //    PRG_SeedGen(&prg);
  //    randomly_zero_out(vnet.Uact3, vnet.Uact2, vnet.numClients, 0.10);

  //    VNET_UNMask(&vnet, &prg);
  //    VNET_Vrfy(&vnet, 1);
  //    PRG_Free(&prg);
  //    clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  //    Time_Measure(&timemeasure);
  //    printf("\nElapsed Time for Verify and Unmask Function is as below:\n");
  //    printf("In Seconds: %ld\n", timemeasure.seconds);
  //    printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  //    printf("In Microseconds: %ld\n", timemeasure.microseconds);
  //    printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);
  //    return 0;
}