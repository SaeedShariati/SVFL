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
#define USERS_SIZE 20
#define SEC_PARAM  16 //in bytes
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
   mpz_t *maskedLocalVector;
   mpz_t *maskTag;

   mpz_t betaMasked, betaVerify;
   u_int32_t betaMaskedSize,betaVerifySize;

   DscPRF prf;
   DscHash hash;

   char **sdata; //s_i,j ,4 bytes each
   char **sverify; //s_i,j hat ,4 bytes each

   // output thrcrypt
   DscCipher P;
   DscCipher B;

   // for using in tag
   mpz_t k_p;
   u_int32_t *k_s_i;

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

   vnet->Uact1 = calloc(vnet->numClients ,sizeof(u_int8_t));
   vnet->Uact2 = calloc(vnet->numClients , sizeof(u_int8_t));
   vnet->Uact3 = calloc(vnet->numClients , sizeof(u_int8_t));

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

      mpz_init(vnet->Users[i].skey);
      mpz_init(vnet->Users[i].pkey);
      mpz_inits(vnet->Users[i].shares_x,vnet->Users[i].shares_y,NULL);
      mpz_inits(vnet->Users[i].betaMasked,vnet->Users[i].betaVerify,NULL);


      // To initialize local data vector for each user
      srand(time(NULL));
      vnet->Users[i].plainLocalVector = calloc(vnet->grdSize, sizeof(int32_t));
      vnet->Users[i].maskedLocalVector = malloc(vnet->grdSize * sizeof(mpz_t));
      vnet->Users[i].maskTag = malloc(vnet->grdSize* sizeof(mpz_t));

      for (int j = 0; j < vnet->grdSize; j++) {
         vnet->Users[i].plainLocalVector[j] = i;
         mpz_inits(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskTag[j],NULL);
      }

      // To initialize PRF for each user
      PRF_Config(&(vnet->Users[i].prf), vnet->secparam);
      PRF_KeyGen(&(vnet->Users[i].prf));

      // To initialize HASH for each user
      Hash_Config(&(vnet->Users[i].hash), 32);
      vnet->Users[i].sdata = calloc((vnet->numClients) , sizeof(char*));
      vnet->Users[i].sverify = calloc((vnet->numClients) , sizeof(char*));

      mpz_init(vnet->Users[i].k_p);
      vnet->Users[i].k_s_i = malloc(sizeof(int32_t)*vnet->grdSize);
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
      memcpy(vnet->Users[i].prf.key, sharedSecret, vnet->secparam); //F_k, k is the same for users i,j
      free(sharedSecret);

      sprintf((char *)str1, "%d,%d", vnet->rndlbl, 0); //used for generating s_i,j
      sprintf((char *)str2, "%d,%d", vnet->rndlbl, 1); //used for generating s_i,j'
      //initialize s_i,j
      PRF_Eval(&(vnet->Users[i].prf),str1,16);
      vnet->Users[i].sdata[z] = malloc(sizeof(uint32_t));
      memcpy(vnet->Users[i].sdata[z],vnet->Users[i].prf.randomOutput,sizeof(uint32_t));
      //initialize s_i,j'
      PRF_Eval(&(vnet->Users[i].prf),str2,16);
      vnet->Users[i].sverify[z] = malloc(sizeof(uint32_t));
      memcpy(vnet->Users[i].sverify[z], vnet->Users[i].prf.randomOutput,sizeof(uint32_t));
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

   char* P = malloc(2*(vnet->numClients)*16);
   for (int j = 0; j < vnet->numClients && j != i; j++) {
      memcpy(P+j*16,vnet->Users[i].sdata[j],sizeof(uint32_t));
      memcpy(P+(vnet->numClients-1+j)*16,vnet->Users[i].sverify[j],sizeof(uint32_t));
   }
   ThrCrypt_Enc(&(vnet->thrcrypt), P, 2*(vnet->numClients)*sizeof(uint32_t));
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
   uint32_t Uact1Active = 0;
   for(int k=0;k<vnet->numClients;k++){
      Uact1Active+=vnet->Uact1[k];
   }
   if(Uact1Active<vnet->thrshld){
      printf("\nVNET_MASK: Not enough active members to continue.\n");
      exit(1);
   }

   uint32_t *prgArray = malloc(vnet->grdSize * sizeof(uint32_t));
   mpz_t *Sum_prgArray = malloc(vnet->grdSize * sizeof(mpz_t));

   uint32_t *prgArrayTag = malloc(vnet->grdSize * sizeof(uint32_t));
   mpz_t *Sum_prgArrayTag = malloc(vnet->grdSize * sizeof(mpz_t));

   for(int k=0;k<vnet->grdSize;k++){
      mpz_inits(Sum_prgArray[k],Sum_prgArrayTag[k],NULL);
      mpz_set_ui(Sum_prgArray[k],0);
      mpz_set_ui(Sum_prgArrayTag[k],0);
      mpz_set_ui(vnet->Users[i].maskedLocalVector[k],0);
      mpz_set_ui(vnet->Users[i].maskTag[k],0);
   }
 
   char *str1 = malloc(16 * sizeof(unsigned char));
   char *str2 = malloc(16 * sizeof(unsigned char));

   sprintf((char *)str1, "%d,%d", vnet->rndlbl, 0);
   sprintf((char *)str2, "%d,%d", vnet->rndlbl, i);

   // Prf key
   char* vk;
   mpz_to_byteArray(&vk, vnet->vk);
   memcpy(vnet->Users[i].prf.key, vk, vnet->secparam);
   free(vk);
   
   PRF_Eval(&(vnet->Users[i].prf),str1,16);
   memcpy((prg->hmac.key),vnet->Users[i].prf.randomOutput, 16);
   free(str1);

   PRG_Eval(prg);
   byteArray_to_mpz(vnet->Users[i].k_p, (char*)prg->randomOutput, prg->size);
   mpz_mod(vnet->Users[i].k_p,vnet->Users[i].k_p,vnet->grp.prime);
   
   PRF_Eval(&(vnet->Users[i].prf),str2,16);
   memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].prf.randomOutput, 16); 
   free(str2);  

   PRG_Eval(prg);
   memcpy((char *)vnet->Users[i].k_s_i, (const char *)prg->randomOutput,prg->size);


   for (int z = 0; z < vnet->numClients && z!=i; z++) {

      // Mask Gradient
      memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sdata[z], 16);
      PRG_Eval(prg);
      memcpy(prgArray,prg->randomOutput,vnet->grdSize*sizeof(uint32_t));
      //bytes_to_ints(prg->randomOutput, prgArray, vnet->grdSize); data is random so the ordre of bytes don't matter

      // Mask Tag
      memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sverify[z], 16);
      PRG_Eval(prg);
      memcpy(prgArrayTag,prg->randomOutput,vnet->grdSize*sizeof(uint32_t));
      //bytes_to_ints(prg->randomOutput, prgArrayTag, vnet->grdSize);

      for (int j = 0; j < vnet->grdSize; j++) {
         if(z>i){
            mpz_add_ui(Sum_prgArray[j],Sum_prgArray[j],prgArray[j]);
            mpz_mod(Sum_prgArray[j],Sum_prgArray[j],vnet->grp.prime);
            mpz_add_ui(Sum_prgArrayTag[j],Sum_prgArrayTag[j],prgArrayTag[j]);
            mpz_mod(Sum_prgArrayTag[j],Sum_prgArrayTag[j],vnet->grp.prime);
         }
         else{
            mpz_sub_ui(Sum_prgArray[j],Sum_prgArray[j],prgArray[j]);
            mpz_mod(Sum_prgArray[j],Sum_prgArray[j],vnet->grp.prime);
            mpz_sub_ui(Sum_prgArrayTag[j],Sum_prgArrayTag[j],prgArrayTag[j]);
            mpz_mod(Sum_prgArrayTag[j],Sum_prgArrayTag[j],vnet->grp.prime);
         }
      }
   }

   for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],
         ((uint32_t *)(vnet->Users[i].plainLocalVector))[j]);
      mpz_add(vnet->Users[i].maskedLocalVector[j], vnet->Users[i].maskedLocalVector[j], Sum_prgArray[j]);
      mpz_mod(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],vnet->grp.prime);

      mpz_add(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],Sum_prgArrayTag[j]);
      mpz_mod(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],vnet->grp.prime);
   }

   // Add PRG-Beta to mask
   char *betaMasked;
   mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
   memcpy((char *)prg->hmac.key, (char *)betaMasked, prg->hmac.secparam);
   free(betaMasked);

   PRG_Eval(prg);
   memcpy(prgArray,prg->randomOutput,prg->size);

   for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],prgArray[j]);
      mpz_mod(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],vnet->grp.prime);
   }

   // Add PRG-Betatag to mask Tag
   char* betatag;
   mpz_to_byteArray(&betatag, vnet->Users[i].betaVerify);
   memcpy((char *)prg->hmac.key, betatag, prg->hmac.secparam);
   free(betatag);

   PRG_Eval(prg);
   memcpy(prgArrayTag,prg->randomOutput,prg->size);

   for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j] ,prgArrayTag[j]);
      mpz_mod(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],vnet->grp.prime);
      mpz_add_ui(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],vnet->Users[i].k_s_i[j]);
      mpz_mod(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],vnet->grp.prime);

      mpz_addmul_ui(vnet->Users[i].maskTag[j],vnet->Users[i].k_p,((uint32_t *)(vnet->Users[i].plainLocalVector))[j]);
      mpz_mod(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],vnet->grp.prime);    
   }
}

void VNET_UNMask(DscVNet *vnet, DscPRG *prg)
{
   uint32_t Uact2Active = 0;
   uint32_t Uact3Active = 0;
   for(int k=0;k<vnet->numClients;k++){
      Uact2Active += vnet->Uact2[k];
      Uact3Active += vnet->Uact3[k];
   }
   if(Uact2Active<vnet->thrshld || Uact3Active < vnet->thrshld){
      printf("\nVNET_UNMAsk: Not enough active users to continue\n");
      exit(1);
   }
   for(int j =0;j<vnet->numClients && vnet->Uact3[j]==1;j++){
       //server gets the Uact3's sharess
      mpz_inits(vnet->thrcrypt.thss.shares_x[j],vnet->thrcrypt.thss.shares_y[j],NULL);
      mpz_set(vnet->thrcrypt.thss.shares_x[j] , vnet->Users[j].shares_x);
      mpz_set(vnet->thrcrypt.thss.shares_x[j] , vnet->Users[j].shares_y);
   }
   for(int i =0;i<vnet->numClients && vnet->Uact2[i]==1;i++){
     // Decrypts B_i for Uact2
     vnet->thrcrypt.cipher = vnet->Users[i].B;
     ThrCrypt_Dec(&(vnet->thrcrypt));
     memcpy(vnet->Users[i].betaMasked, vnet->thrcrypt.plaintextOutput,
            vnet->Users[i].betaMaskedSize);
     memcpy(vnet->Users[i].betaVerify,
            vnet->thrcrypt.plaintextOutput + vnet->Users[i].betaMaskedSize,
            vnet->Users[i].betaVerifySize);
     Cipher_Free(&(vnet->thrcrypt.cipher));
     vnet->Users[i].B.output1 = NULL;
     vnet->Users[i].B.output2 = NULL;
     vnet->Users[i].B.blocks = 0;

     if (vnet->Uact3 == 0) {
       // Decrypts P_i for (Uact2-Uact3) WRONG??
       vnet->thrcrypt.cipher = vnet->Users[i].P;
       ThrCrypt_Dec(&(vnet->thrcrypt));

      char* P = malloc(2*(vnet->numClients)*16);
      for (int j = 0; j < vnet->numClients && j != i; j++) {
         memcpy(P+j*16,vnet->Users[i].sdata[j],16);
         memcpy(P+(vnet->numClients+j)*16,vnet->Users[i].sverify[j],16);
      }

       memcpy(vnet->Users[i].sdata, vnet->thrcrypt.plaintextOutput,
              (vnet->numClients)*sizeof(u_int16_t));
       memcpy(vnet->Users[i].sverify,
              vnet->thrcrypt.plaintextOutput + (vnet->numClients)*sizeof(u_int16_t),
              (vnet->numClients)*sizeof(u_int16_t));
       Cipher_Free(&(vnet->thrcrypt.cipher));
       vnet->Users[i].P.output1 = NULL;
       vnet->Users[i].P.output2 = NULL;
       vnet->Users[i].P.blocks = 0;
     }
   }

   uint32_t *prgArray = malloc(vnet->grdSize * sizeof(uint32_t));
   mpz_t *Sum_prgArray = malloc(vnet->grdSize * sizeof(mpz_t));

   uint32_t *prgArrayTag = malloc(vnet->grdSize * sizeof(uint32_t));
   mpz_t *Sum_prgArrayTag = malloc(vnet->grdSize * sizeof(mpz_t));

   for(int k=0;k<vnet->grdSize;k++){
      mpz_inits(Sum_prgArray[k],Sum_prgArrayTag[k],NULL);

      mpz_set_ui(Sum_prgArray[k],0);
      mpz_set_ui(Sum_prgArrayTag[k],0);
   }


   for (int i = 0; i < vnet->numClients && vnet->Uact2[i]==1; i++) {
      for (int j = 0; j < vnet->grdSize; j++){
      mpz_add(Sum_prgArray[j],Sum_prgArray[j],vnet->Users[i].maskedLocalVector[j]);
      mpz_mod(Sum_prgArray[j],Sum_prgArray[j],vnet->grp.prime);
      mpz_sub(Sum_prgArray[j],Sum_prgArray[j],vnet->Users[i].betaMasked);
      mpz_mod(Sum_prgArray[j],Sum_prgArray[j],vnet->grp.prime);

      mpz_add(Sum_prgArrayTag[j],Sum_prgArrayTag[j],vnet->Users[i].maskTag[j]);
      mpz_mod(Sum_prgArrayTag[j],Sum_prgArrayTag[j],vnet->grp.prime);
      mpz_sub(Sum_prgArrayTag[j],Sum_prgArrayTag[j],vnet->Users[i].betaVerify);
      mpz_mod(Sum_prgArrayTag[j],Sum_prgArrayTag[j],vnet->grp.prime);
      }
      for(int j = i+1; j<vnet->numClients;j++){

      }
   }


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
      //maskTagPrime[j] = (*vnet->Users[i].k_p) * vnet->gradGlobalVector[j] + tagPrime[j];
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
  for(int i =0;i<vnet.numClients;i++){
   vnet.Uact1[i]=1;
  }
   // users active (90%)
   // double percentage = 0.90;
   // size_t count = (size_t)(vnet.numClients * percentage); // Number of elements to set to 1
   // size_t selected;
   // for (int i = 0; i < count; i++) {
   //    do{

   //       selected = rand() % vnet.numClients;
   //    }while (vnet.Uact1[selected] == 1);
   //    vnet.Uact1[selected] =1;
   //    printf("\nUact[%lu]=1",selected);
   // }
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  for (int i = 0; i < vnet.numClients && vnet.Uact1[i]==1; i++) {
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
   for (int i = 0; i < 1 && vnet.Uact2[i]==1; i++) {
      VNET_Mask(&vnet, i, &prg2);
   }
   PRG_Free(&prg2);
   clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
   Time_Measure(&timemeasure);
   printf("\nElapsed Time for Mask Function is as below:\n");
   printf("In Seconds: %ld\n", timemeasure.seconds);
   printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
   printf("In Microseconds: %ld\n", timemeasure.microseconds);
   printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);

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