#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
// #include <pbc/pbc_test.h>
#include <gmp.h>
#include <math.h>
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
#define GRAD_SIZE 300
#define USERS_SIZE 200
#define SEC_PARAM  16

typedef struct {
   int Uid; // Unique ID for the user
   unsigned char *vk;
   DscKAgreeV1 kagree;
   mpz_t skey;
   mpz_t pkey;
   mpz_t shares_x;      // id related to thss
   mpz_t shares_y;      // secret share related to thss
   mpz_t pkey_thrcrypt; // public key related to cryptthss

   int *plainLocalVector;
   int32_t *maskedLocalVector;
   int32_t *maskTag;

   mpz_t betaMasked, betaVerify;

   DscPRF prf;
   DscHash hash;

   char **sdata;
   char **sverify;

   // output thrcrypt
   mpz_t **P;

   // for using in tag
   int *k_p;
   unsigned char *k_s_i;

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

} DscVNet;

void generate_random_mpz_vnet(DscVNet *vnet, mpz_ptr rndelement)
{

   mpz_urandomm(rndelement, vnet->grp.state, vnet->grp.prime);
}

void VNET_Config(DscVNet *vnet)
{
   vnet->secparam = SEC_PARAM;
   vnet->thrshld = 5;
   vnet->numClients = USERS_SIZE;
   vnet->grdSize = GRAD_SIZE;
   vnet->rndlbl = 1;

   vnet->Uact1 = malloc(vnet->numClients * sizeof(uint8_t));
   vnet->Uact2 = malloc(vnet->numClients * sizeof(uint8_t));
   vnet->Uact3 = malloc(vnet->numClients * sizeof(uint8_t));

   vnet->gradGlobalVector = malloc(vnet->grdSize * sizeof(int32_t));
   vnet->tagGlobalVector = malloc(vnet->grdSize * sizeof(int32_t));

   GroupGen_Config(&(vnet->grp));
   // Allocate memory for the array of users

   vnet->Users = malloc(vnet->numClients * sizeof(DscClient));
   // vnet->Users = malloc(vnet->numClients * 100000);

   // THRCRYPT
   ThrCrypt_Config(&(vnet->thrcrypt), vnet->secparam * 8, vnet->numClients, vnet->thrshld);

   // Initialize each user's UID and random gradients
   for (int i = 0; i < vnet->numClients; i++) {
      vnet->Users[i].Uid = i; // Example: Assign UIDs from 1 to numClients

      // Phase 1: All users active (100%)
      vnet->Uact1[i] = 1;

      vnet->Users[i].kagree.numUsers = vnet->numClients;
      vnet->Users[i].kagree.secparam = vnet->secparam;
      KAgreeV1_Config(&(vnet->Users[i].kagree));

      vnet->Users[i].vk = calloc(vnet->secparam, sizeof(unsigned char *));
      strncpy((char *)vnet->Users[i].vk, "This is a test for verification key",vnet->secparam);
      vnet->Users[i].vk[vnet->secparam] = '\0';

      // mpz_init(vnet->Users[i].vk1);
      mpz_init(vnet->Users[i].skey);
      mpz_init(vnet->Users[i].pkey);

      // To initialize local data vector for each user
      srand(time(NULL));
      vnet->Users[i].plainLocalVector = calloc(vnet->grdSize, sizeof(int));
      vnet->Users[i].maskedLocalVector = calloc(vnet->grdSize, sizeof(int32_t));
      vnet->Users[i].maskTag = calloc(vnet->grdSize, sizeof(int32_t));

      for (int j = 0; j < vnet->grdSize; j++) {
         // vnet->Users[i].plainLocalVector[j]=(int)(rand()%32768);

         // This is only for test
         vnet->Users[i].plainLocalVector[j] = i;
      }

      // To initialize PRF for each user
      PRF_Config(&(vnet->Users[i].prf), 16);
      PRF_KeyGen(&(vnet->Users[i].prf));

      // To initialize HASH for each user
      Hash_Config(&(vnet->Users[i].hash), 32);
      vnet->Users[i].sdata = malloc(vnet->numClients * sizeof(char *));
      if (vnet->Users[i].sdata == NULL) {
         fprintf(stderr, "Memory allocation failed for vnet->Users[i].sdata\n");
         return;
      }
      vnet->Users[i].sverify = malloc(vnet->numClients * sizeof(char *));
      if (vnet->Users[i].sverify == NULL) {
         fprintf(stderr, "Memory allocation failed for vnet->Users[i].sverify\n");
         return;
      }

      vnet->Users[i].P = malloc(vnet->numClients * sizeof(mpz_t *));
      if (vnet->Users[i].P == NULL) {
         printf("Memory allocation failed for vnet->Users[i].P\n");
         return;
      }
      //changed 128 to 16
      vnet->Users[i].k_p = malloc(sizeof(int));
      vnet->Users[i].k_s_i = malloc(sizeof(int));
   }

   // PRG_Config
   /*    PRG_Config(&(vnet->prg), 16, 3);
      PRG_SeedGen(&(vnet->prg)); */
}

void VNET_Init(DscVNet *vnet)
{
   GroupGen(&(vnet->grp));

   ThrCrypt_DKeyGen(&(vnet->thrcrypt));
   /*  mpz_t vk1;
   mpz_init(vk1);
   generate_random_mpz_vnet(vnet, vk1); */

   for (int i = 0; i < vnet->numClients; i++) {

      mpz_set(vnet->Users[i].kagree.grp.generator, vnet->grp.generator);
      mpz_set(vnet->Users[i].kagree.grp.order, vnet->grp.order);
      mpz_set(vnet->Users[i].kagree.grp.prime, vnet->grp.prime);
       //mpz_set(vnet->Users[i].kagree.grp.state,vnet->grp.state);

      vnet->Users[i].kagree.grp.secparam = vnet->grp.secparam;
      generate_random_mpz_vnet(vnet, vnet->Users[i].skey);

      mpz_powm(vnet->Users[i].pkey, (vnet->grp).generator, vnet->Users[i].skey, vnet->grp.prime);
       //gmp_printf("\npkey %Zd\n",vnet->Users[i].pkey);
      // gmp_printf("\nskey %Zd\n\n",vnet->Users[i].skey);

      // thcrypt
      mpz_init(vnet->Users[i].pkey_thrcrypt);
      mpz_init(vnet->Users[i].shares_x);
      mpz_init(vnet->Users[i].shares_y);

      mpz_set(vnet->Users[i].pkey_thrcrypt, vnet->thrcrypt.pkey);
      mpz_set(vnet->Users[i].shares_x, vnet->thrcrypt.thss.shares_x[i]);
      mpz_set(vnet->Users[i].shares_y, vnet->thrcrypt.thss.shares_y[i]);

      mpz_init(vnet->Users[i].betaMasked);
      mpz_init(vnet->Users[i].betaVerify);
   }

   // printf("\n %d ok\n",vnet->numClients);
   for (int i = 0; i < vnet->numClients; i++) {
      for (int j = 0; j < vnet->numClients; j++) {
         // gmp_printf("\ngmp %d: %Zd\n",i ,vnet->Users[i].pkey);
         mpz_init(vnet->Users[i].kagree.sharedSecret[j]);
         mpz_powm(vnet->Users[i].kagree.sharedSecret[j], vnet->Users[j].pkey,
             vnet->Users[i].skey, vnet->grp.prime);
         // gmp_printf("\ngmp %d: %Zd\n",j ,vnet->Users[i].kagree.sharedSecret[j]);
      }
   }
}

void VNET_KeyShare(DscVNet *vnet, int i)
{

   generate_random_mpz_vnet(vnet, vnet->Users[i].betaMasked);
   generate_random_mpz_vnet(vnet, vnet->Users[i].betaVerify);

   size_t count;
   unsigned char *temp1, *temp2, *temp3;
   unsigned char *str1 = malloc(16 * sizeof(unsigned char));
   unsigned char *str2 = malloc(16 * sizeof(unsigned char));
   unsigned char *tmpstr1 = malloc(512 * sizeof(unsigned char));

   vnet->Users[i].hash.plaintextInput = malloc( 128 * sizeof(char));
   for (int z = 0; z < vnet->numClients; z++) {
      //assert(vnet->Users[i].hash.plaintextInput != NULL); failed
      //temp2 = realloc(vnet->Users[i].hash.plaintextInput, 128 * sizeof(char));
      //if (temp2 != NULL) {
      //   vnet->Users[i].hash.plaintextInput = temp2;
      //}
      mpz_export(vnet->Users[i].hash.plaintextInput, &count, 1, sizeof(char), 0, 0,
                 vnet->Users[i].kagree.sharedSecret[z]);
      vnet->Users[i].hash.plaintextInput[count] = '\0';

      //temp1 = realloc(vnet->Users[i].hash.DigestOutput, 256 * sizeof(char));
      //if (temp1 != NULL) {
      //   vnet->Users[i].hash.DigestOutput = temp1;
      //}
      free(vnet->Users[i].hash.DigestOutput);
      vnet->Users[i].hash.DigestOutput = malloc( 256 * sizeof(char));

      Hash_Eval(&(vnet->Users[i].hash));

      // printf("\nstrlen(hash): %ld\n",strlen(vnet->Users[i].hash.DigestOutput));
      memcpy(vnet->Users[i].prf.key, vnet->Users[i].hash.DigestOutput, 16);
      // memset(vnet->Users[i].prf.key + 16, '\0', 1);
     //for (int k = 0; k < 16; k++)
          // printf("\nSTR: %d\n",vnet->Users[i].prf.key[k]);

      sprintf((char *)str1, "%d,%d", vnet->rndlbl, 0);
      sprintf((char *)str2, "%d,%d", vnet->rndlbl, 1);

      // printf("\nstr1:%s, str2=%s\n",str1,str2);

      temp3 = realloc(vnet->Users[i].prf.plaintextInput, 128 * sizeof(char));
      if (temp3 != NULL) {
         vnet->Users[i].prf.plaintextInput = temp3;
      }

      strcpy((char *)vnet->Users[i].prf.plaintextInput, (const char *)str1);
      PRF_Eval(&(vnet->Users[i].prf));
      vnet->Users[i].sdata[z] = malloc(128 * sizeof(char));

      if (vnet->Users[i].sdata[z] == NULL) {
         fprintf(stderr, "Memory allocation failed for vnet->Users[i].sdata[z]\n");
         return;
      }

      if (z >= i) {
         //no null termination for prf.randomOutput
         memcpy((char *)vnet->Users[i].sdata[z], (const char *)vnet->Users[i].prf.randomOutput,16);
         vnet->Users[i].sdata[z][127] = '\0';
      } else {
         memcpy((char *)vnet->Users[i].sdata[z], (char *)vnet->Users[z].sdata[i],16);
      }

      strcpy((char *)vnet->Users[i].prf.plaintextInput, (const char *)str2);
      PRF_Eval(&(vnet->Users[i].prf));
      vnet->Users[i].sverify[z] = malloc(128 * sizeof(char));
      memcpy((char *)vnet->Users[i].sverify[z], (const char *)vnet->Users[i].prf.randomOutput,16);

      if (z >= i) {
         //strcpy((char *)vnet->Users[i].sverify[z], (const char *)vnet->Users[i].prf.randomOutput);
         memcpy((char *)vnet->Users[i].sverify[z], (const char *)vnet->Users[i].prf.randomOutput,16);

         vnet->Users[i].sverify[z][127] = '\0';
      } else {
         strcpy((char *)vnet->Users[i].sverify[z], (char *)vnet->Users[z].sverify[i]);
      }
      /*  printf("\nPRF output: ");
      for (int p = 0; p < vnet->Users[i].prf.secparam; p++) {
          printf("%02x", vnet->Users[i].prf.randomOutput[p]);
      }
      printf("\n\n"); */

      /*  vnet->Users[i].P[z] = (mpz_t*)malloc(vnet->numClients * sizeof(mpz_t));
       if (vnet->Users[i].P[z] == NULL) {
          fprintf(stderr, "Memory allocation failed for vnet->Users[i].P[z]\n");
          return;
       } */

      gmp_sprintf((char *)tmpstr1, "%B,%B", vnet->Users[i].sdata[z], vnet->Users[i].sverify[z]);

      temp3 = realloc(vnet->thrcrypt.plaintextInput, 512 * sizeof(char));
      if (temp3 != NULL) {
         vnet->thrcrypt.plaintextInput = (char *)temp3;
      }
      strcpy((char *)vnet->thrcrypt.plaintextInput, (const char *)tmpstr1);

      ThrCrypt_ENC(&(vnet->thrcrypt));

      // strcpy(vnet->Users[i].P[z],vnet->thrcrypt.partialDectypted[z]);
   }
   gmp_sprintf((char *)tmpstr1, "%B,%B", vnet->Users[i].betaMasked, vnet->Users[i].betaVerify);
   // printf("\nbetaconcat: %s\n", tmpstr1);

   // mpz_import(ds.tag1, strlen((const char *)(&(ds.hash))->DigestOutput), 1, sizeof(char), 0, 0, (const char
   // *)(&(ds.hash))->DigestOutput);
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
   unsigned char *temp1, *temp2, *temp3, *temp4;

   uint32_t *prgArray = malloc(vnet->grdSize * sizeof(uint32_t));
   int32_t *Sum_prgArray = malloc(vnet->grdSize * sizeof(int32_t));
   memset(Sum_prgArray, 0, vnet->grdSize * sizeof(int32_t));

   uint32_t *prgArrayTag = malloc(vnet->grdSize * sizeof(uint32_t));
   int32_t *Sum_prgArrayTag = malloc(vnet->grdSize * sizeof(int32_t));
   memset(Sum_prgArrayTag, 0, vnet->grdSize * sizeof(int32_t));

   unsigned char *str1 = malloc(16 * sizeof(unsigned char));
   unsigned char *str2 = malloc(16 * sizeof(unsigned char));

   sprintf((char *)str1, "%d,%d", vnet->rndlbl, 0);
   sprintf((char *)str2, "%d,%d", vnet->rndlbl, i);

   // Prf key

   memcpy(vnet->Users[i].prf.key, vnet->Users[i].vk, vnet->secparam);
   printf("\n %s \n", vnet->Users[i].vk);
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
      prg->hmac.DigestOutput = temp2;
   }
   
   temp3 = realloc(prg->randomOutput, prg->size);
   if (temp3 != NULL) {
      prg->randomOutput = temp3;
   } 
   
   strcpy((char *)vnet->Users[i].prf.plaintextInput, (const char *)str1);



   PRF_Eval(&(vnet->Users[i].prf));
   printf("\nPRF output: ");
   for (int p = 0; p < 10; p++) {
      printf("%02x", vnet->Users[i].prf.randomOutput[p]);
   }
   printf("\n\n"); 

   memcpy((prg->hmac.key),vnet->Users[i].prf.randomOutput, 16);
   //strncpy((prg->hmac.key), (const char *)vnet->Users[i].prf.randomOutput, 128);
   printf ("\nPRG key: ");
   for (int p = 0; p < 10; p++) {
      printf("%02x", prg->hmac.key[p]);
   }
   printf("111111111111s\n\n");

   //memcpy((prg->hmac.plaintextInput),"I am a student123", 16);

   //sprintf((char *)str1, "%d,%d", vnet->rndlbl, 0);
   
   //memcpy(prg->hmac.key, vnet->Users[i].vk, vnet->secparam);
   PRG_Eval(prg);
   //for (int p = 0; p < vnet->numClients; p++) {
   //   printf("%02x", prg->randomOutput[p]);
   //}
   //printf("--------\n\n"); 
   
   //bytes_to_ints(prg->randomOutput, (char *)vnet->Users[i].k_p, vnet->grdSize);
   
   //strcpy((char *)vnet->Users[i].k_p, (const char *)prg->randomOutput);
   memcpy((char *)vnet->Users[i].k_p, (const char *)prg->randomOutput,sizeof(int));


   strcpy((char *)vnet->Users[i].prf.plaintextInput, (const char *)str2);
   PRF_Eval(&(vnet->Users[i].prf));
   //strncpy((char *)prg->hmac.key, (const char *)vnet->Users[i].prf.randomOutput, 128);
   memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].prf.randomOutput, 16);
   PRG_Eval(prg);


   //strcpy((char *)vnet->Users[i].k_s_i, (const char *)vnet->Users[i].prf.randomOutput);
   memcpy((char *)vnet->Users[i].k_s_i, (const char *)vnet->Users[i].prf.randomOutput, sizeof(int));



   for (int z = 0; z < vnet->numClients; z++) {
      if (z != i) {

         memset(prgArray, 0, vnet->grdSize);
         memset(prgArrayTag, 0, vnet->grdSize);

         // Mask Gradient
         //strncpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sdata[z], 128);
         memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sdata[z], 16);
         PRG_Eval(prg);
         /*     printf("\nPRG output22: ");
            for (int j = 0; j < 128; j++) {
               printf("%2x\t", prg->randomOutput[j]);
            }
            printf("\n"); */
         

         // Convert bytes to integer array
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
   memset(tagPrime, 0, vnet->grdSize * sizeof(int));

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

         printf("%ld , %ld \n", maskTagPrime[j], vnet->tagGlobalVector[j]);
         break;
      }
   }
   if (vrfy)
      printf("valid\n");
   else
      printf("invalid");
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
   /*DscPRG prg;
   PRG_Config(&prg,16,3);

   PRG_SeedGen(&prg);
   printf("\nSeed = ");
   for (int i = 0; i < prg.secparam; i++) {
       printf("%02x", prg.hmac.key[i]);
   }
   printf("\n");

   PRG_Eval(&prg);
   printf("\nPRG1(seed,rate=%d): ",prg.extendedRate);
   for (int i = 0; i < ((prg.extendedRate)*((&(prg.hmac))->secparam)); i++) {
       printf("%02x", prg.randomOutput[i]);
   }
   PRG_SeedGen(&prg);
   //prg.hmac.key="thisddddd";
   printf("\n\n");
   PRG_Eval(&prg);
   printf("\nPRG2(seed,rate=%d): ",prg.extendedRate);
   for (int i = 0; i < ((prg.extendedRate)*((&(prg.hmac))->secparam)); i++) {
       printf("%02x", prg.randomOutput[i]);
   }
   printf("\n\n");
*/

/* Previous Code
   DscTimeMeasure timemeasure;

   DscPRG prg;
   int size = GRAD_SIZE*4;
   PRG_Config(&prg, SEC_PARAM, size);
   PRG_SeedGen(&prg);

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

   // Step 2: Set 10% of indices in Uact2 to 0 based on Uact1
   randomly_zero_out(vnet.Uact2, vnet.Uact1, vnet.numClients, 0.10);

   clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
   for (int i = 0; i < 1; i++) {
      // if (vnet.Uact2[i] == 1)
      VNET_Mask(&vnet, i, &prg2);
   }

   clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
   Time_Measure(&timemeasure);
   printf("\nElapsed Time for Mask Function is as below:\n");
   printf("In Seconds: %ld\n", timemeasure.seconds);
   printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
   printf("In Microseconds: %ld\n", timemeasure.microseconds);
   printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);

   // Step 3: Set 10% of indices in Uact3 to 0 based on Uact2
   randomly_zero_out(vnet.Uact3, vnet.Uact2, vnet.numClients, 0.10);

   VNET_UNMask(&vnet, &prg);
   VNET_Vrfy(&vnet, 1);


   
   // VNET_Vrfy(&vnet, 2);
   /*  for(int j=0;j<vnet.grdSize;j++){
      printf("%d\t", vnet.Users[16].plainLocalVector[j]);
    } */

   DscThrCrypt thrcrypt;
    ThrCrypt_Config(&thrcrypt,128,5,3);
    ThrCrypt_DKeyGen(&thrcrypt);

    printf("\n PlaintextInput: %s\n",thrcrypt.plaintextInput);
    

    ThrCrypt_ENC(&thrcrypt);

   mpz_out_str(stdout, 10, thrcrypt.input);

    ThrCrypt_Dec(&thrcrypt);

    printf("\n PlaintextOutput: %s\n",thrcrypt.plaintextOutput);

    mpz_out_str(stdout, 10, thrcrypt.dectypted);
    printf("\n");
   return 0;
}