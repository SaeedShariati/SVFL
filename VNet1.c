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
#define GRAD_SIZE 20
#define USERS_SIZE 1000
#define SEC_PARAM 32  //in bytes
#define Threshold 10
#define PrimeBits 512 //used for masking (if the number of users is large, value of globalGradient might exceed this value 
                       //which will make the result invalid, because the result is mod p.

typedef struct {
   int Uid; // Unique ID for the user

   mpz_t skey;
   mpz_t pkey;
   mpz_t shares_x;      // id related to thss
   mpz_t shares_y;      // secret share related to thss

   u_int32_t *plainLocalVector;

   mpz_t *maskedLocalVector;
   mpz_t *maskTag;

   mpz_t betaMasked; 
   mpz_t betaVerify;  
   u_int32_t betaMaskedSize,betaVerifySize;

   DscPRF prf;

   char **sdata; //s_i,j ,8 bytes each
   char **sverify; //s_i,j hat ,8 bytes each

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
   DscPRF prf;
   mpz_t prime; //only used for masking 33 bit (1 bit bigger than the gradients)


   DscThrCrypt thrcrypt;

   u_int32_t secparam;   // Security parameter
   u_int32_t numClients; // Number of clients
   u_int32_t thrshld;    // Threshold
   u_int32_t grdSize;
   u_int32_t rndlbl;

   u_int16_t *Uact1, *Uact2, *Uact3;

   u_int32_t *gradGlobalVector;
   mpz_t *tagGlobalVector;

   DscClient *Users; // Array of users (clients)
   mpz_t vk;

} DscVNet;

void generate_random_mpz_vnet(DscVNet *vnet, mpz_ptr rndelement)
{
   mpz_urandomm(rndelement, vnet->grp.state, vnet->grp.prime);
}
//prints hex code
void print(char* a, u_int32_t size)
{
   for(int i =0;i<size;i++){
      printf(" %02x",(unsigned char)a[i]);
   }
   printf("\n");
}
//prints hex code
void printIndex(char* a, u_int32_t size, char* name,u_int32_t index)
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
//not secure, used to give random inputs for local gra
uint64_t rand_uint64() {
    static uint64_t state = 88172645463325252ull; // seed
    state = state * 6364136223846793005ULL + 1;
    return state;
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
//if originalSize<newSize then adds zeros to the end until the size of bytes* becomes newSize
void padWithZero(char** bytes,size_t originalSize,size_t newSize){
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
void VNET_Config(DscVNet *vnet)
{

   vnet->secparam = SEC_PARAM;
   vnet->thrshld = Threshold;
   vnet->numClients = USERS_SIZE;
   vnet->grdSize = GRAD_SIZE;
   vnet->rndlbl = 1;

   vnet->Uact1 = calloc(vnet->numClients ,sizeof(u_int16_t));
   vnet->Uact2 = calloc(vnet->numClients , sizeof(u_int16_t));
   vnet->Uact3 = calloc(vnet->numClients , sizeof(u_int16_t));

   vnet->gradGlobalVector = malloc(vnet->grdSize * sizeof(int32_t));
   vnet->tagGlobalVector = malloc(vnet->grdSize * sizeof(mpz_t));
   mpz_init(vnet->prime);
   generatePrime(vnet->prime,sizeof(uint32_t)+1);
   // To initialize PRF for server
   PRF_Config(&(vnet->prf), vnet->secparam);
   PRF_KeyGen(&(vnet->prf));
   GroupGen_Config(&(vnet->grp),vnet->secparam*8);
   // Allocate memory for the array of users

   vnet->Users = malloc(vnet->numClients * sizeof(DscClient));

   // THRCRYPT
   ThrCrypt_Config(&(vnet->thrcrypt), 256, vnet->numClients,
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
         //vnet->Users[i].plainLocalVector[j] = i;
         vnet->Users[i].plainLocalVector[j]=(uint32_t)(rand()%32768);
         mpz_inits(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskTag[j],NULL);
      }

      // To initialize PRF for each user
      PRF_Config(&(vnet->Users[i].prf), vnet->secparam);
      PRF_KeyGen(&(vnet->Users[i].prf));

      vnet->Users[i].sdata = calloc((vnet->numClients) , sizeof(char*));
      vnet->Users[i].sverify = calloc((vnet->numClients) , sizeof(char*));

      mpz_init(vnet->Users[i].k_p);
      vnet->Users[i].k_s_i = malloc(sizeof(int32_t)*vnet->grdSize);
   }
}

void VNET_Init(DscVNet *vnet)
{
   GroupGen(&(vnet->grp));
   ThrCrypt_DKeyGen(&(vnet->thrcrypt));
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

   unsigned char str1[5];

   for (int z = 0; z < vnet->numClients; z++) {
      if(z==i)
         continue;
      mpz_t k;
      mpz_init(k);
      char* sharedSecret; 
      mpz_powm(k, vnet->Users[i].pkey,
         vnet->Users[z].skey, vnet->grp.prime);
      size_t size = mpz_to_byteArray(&sharedSecret, k);
      if(size<vnet->secparam)
         padWithZero(&sharedSecret, size, vnet->secparam);
      memcpy(vnet->Users[i].prf.key, sharedSecret, vnet->secparam); //F_k, k is the same for users i,j
      free(sharedSecret);

      str1[0] = (vnet->rndlbl >> 24) & 0xFF;
      str1[1] = (vnet->rndlbl >> 16) & 0xFF;
      str1[2] = (vnet->rndlbl >> 8) & 0xFF;
      str1[3] = vnet->rndlbl & 0xFF;
      str1[4] = 0;


      //initialize s_i,j
      PRF_Eval(&(vnet->Users[i].prf),(char*)str1,5);
      vnet->Users[i].sdata[z] = malloc(8);
      memcpy(vnet->Users[i].sdata[z],vnet->Users[i].prf.randomOutput,8);
      

      str1[4]=1;
      //initialize s_i,j'
      PRF_Eval(&(vnet->Users[i].prf),(char*)str1,5);
      vnet->Users[i].sverify[z] = malloc(8);
      memcpy(vnet->Users[i].sverify[z], vnet->Users[i].prf.randomOutput,8);
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
   printf(",B%d encrypted,",i);


   char* P = malloc(2*(vnet->numClients)*8);
   for (int j = 0; j < vnet->numClients; j++) {
      if(j==i)
         continue;
      memcpy(P+j*8,vnet->Users[i].sdata[j],8);
      memcpy(P+(vnet->numClients*8) + j*8
      ,vnet->Users[i].sverify[j],8);
   }
   ThrCrypt_Enc(&(vnet->thrcrypt), P, 2*(vnet->numClients)*8);
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

void VNET_Mask(DscVNet *vnet, u_int16_t i, DscPRG *prg)
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
 
   
   // Prf key
   char* vk;
   size_t vkSize = mpz_to_byteArray(&vk, vnet->vk);
   padWithZero(&vk, vkSize, vnet->secparam);
   memcpy(vnet->Users[i].prf.key, vk, vnet->secparam);
   free(vk);
   
   //generate k_p
   unsigned char str1 [6];
   str1[0] = (vnet->rndlbl >> 24) & 0xFF;
   str1[1] = (vnet->rndlbl >> 16) & 0xFF;
   str1[2] = (vnet->rndlbl >> 8) & 0xFF;
   str1[3] = vnet->rndlbl & 0xFF;
   str1[4] = 0;
   str1[5] = 0;
   memset(prg->hmac.key,0,vnet->secparam); //for any letover bytes of key to be zero
   PRF_Eval(&(vnet->Users[i].prf),(char*)str1,6);
   memcpy((char*)(prg->hmac.key),vnet->Users[i].prf.randomOutput, MIN(32,vnet->secparam));
   PRG_Eval(prg);
   byteArray_to_mpz(vnet->Users[i].k_p, (char*)prg->randomOutput, prg->size);
   mpz_mod(vnet->Users[i].k_p,vnet->Users[i].k_p,vnet->grp.prime);
   //generate k_s_i
   str1[4] = (i >>  8)&0xFF;
   str1[5] = i & 0xFF;
   memset(prg->hmac.key,0,vnet->secparam); //for any letover bytes of key to be zero
   PRF_Eval(&(vnet->Users[i].prf),(char*)str1,6);
   memcpy((char *)prg->hmac.key, vnet->Users[i].prf.randomOutput, MIN(32,vnet->secparam)); 
   PRG_Eval(prg);
   memcpy((char *)vnet->Users[i].k_s_i, prg->randomOutput,prg->size);


   for (int z = 0; z < vnet->numClients; z++) {
      if(z==i || vnet->Uact1[z]==0)
         continue;
      // Mask Gradient prgArray = G(s_i,z)
      memset(prg->hmac.key,0,vnet->secparam);
      memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sdata[z], MIN(8,vnet->secparam));
      PRG_Eval(prg);
      memcpy(prgArray,prg->randomOutput,prg->size);

      // Mask Tag prgArrayTag = G(s hat_i,z)
      memset(prg->hmac.key,0,vnet->secparam);
      memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sverify[z], MIN(8,vnet->secparam));
      PRG_Eval(prg);
      memcpy(prgArrayTag,prg->randomOutput,prg->size);

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
         vnet->Users[i].plainLocalVector[j]);
      mpz_add(vnet->Users[i].maskedLocalVector[j], vnet->Users[i].maskedLocalVector[j], Sum_prgArray[j]);
      mpz_mod(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],vnet->grp.prime);

      mpz_add(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],Sum_prgArrayTag[j]);
      mpz_mod(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],vnet->grp.prime);
   }

   // generate prgArray G(beta_i)
   char *betaMasked;
   size_t betaMaskedSize = mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
   padWithZero(&betaMasked, betaMaskedSize, vnet->secparam);
   memcpy((char *)prg->hmac.key, (char *)betaMasked, vnet->secparam);
   free(betaMasked);
   PRG_Eval(prg);
   memcpy(prgArray,prg->randomOutput,prg->size);

   for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],prgArray[j]);
      mpz_mod(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],vnet->grp.prime);
   }


   // generate G( prgArrayTag = beta hat_i)
   char* betatag;
   size_t betatagSize = mpz_to_byteArray(&betatag, vnet->Users[i].betaVerify);
   padWithZero(&betatag, betatagSize, vnet->secparam);
   memcpy((char *)prg->hmac.key, betatag, vnet->secparam);
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

   free(prgArray);free(prgArrayTag);
   for(int k=0;k<vnet->grdSize;k++){
      mpz_clears(Sum_prgArray[k],Sum_prgArrayTag[k],NULL);
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
   int t=0;
   for(int j =0;j<vnet->numClients;j++){
      if(vnet->Uact3[j]==0)
         continue;
       //server gets the Uact3's sharess
      mpz_inits(vnet->thrcrypt.thss.shares_x[t],vnet->thrcrypt.thss.shares_y[t],NULL);
      mpz_set(vnet->thrcrypt.thss.shares_x[t] , vnet->Users[j].shares_x);
      mpz_set(vnet->thrcrypt.thss.shares_y[t] , vnet->Users[j].shares_y);
      t+=1;
   }
   for(int i =0;i<vnet->numClients;i++){
      if(!(vnet->Uact2[i]==1 && vnet->Uact3[i] == 0 )){
         continue;
      }
     // Decrypts B_i for Uact2 that have gone offline
     vnet->thrcrypt.cipher = vnet->Users[i].B;
     ThrCrypt_Dec(&(vnet->thrcrypt));
     char* betaMasked = malloc(vnet->Users[i].betaMaskedSize);
     char* betaVerify = malloc(vnet->Users[i].betaVerifySize);
     memcpy(betaMasked, vnet->thrcrypt.plaintextOutput,
            vnet->Users[i].betaMaskedSize);
     memcpy(betaVerify,
            vnet->thrcrypt.plaintextOutput + vnet->Users[i].betaMaskedSize,
            vnet->Users[i].betaVerifySize);
      byteArray_to_mpz(vnet->Users[i].betaMasked,betaMasked,vnet->Users[i].betaMaskedSize);
      byteArray_to_mpz(vnet->Users[i].betaVerify,betaVerify,vnet->Users[i].betaVerifySize);
      free(betaMasked);
      free(betaVerify);
     Cipher_Free(&(vnet->thrcrypt.cipher));
     vnet->Users[i].B.output1 = NULL;
     vnet->Users[i].B.output2 = NULL;
     vnet->Users[i].B.blocks = 0;
   }
   for (int i = 0; i < vnet->numClients; i++) {
     if (vnet->Uact1[i] == 0 || vnet->Uact2[i] == 1)
       continue;
     // decrypts P_i for users whose G(s_i,j) is not included in the sum
     vnet->thrcrypt.cipher = vnet->Users[i].P;
     ThrCrypt_Dec(&(vnet->thrcrypt));
     vnet->Users[i].P = vnet->thrcrypt.cipher;
     for (int j = 0; j < vnet->numClients; j++) {
       if (j == i || vnet->Uact1[j] == 0)
         continue;
       memcpy(vnet->Users[i].sdata[j], vnet->thrcrypt.plaintextOutput + j * 8,
              8);
       memcpy(vnet->Users[i].sverify[j],
              vnet->thrcrypt.plaintextOutput + (vnet->numClients * 8) + j * 8,
              8);
     }

     Cipher_Free(&(vnet->thrcrypt.cipher));
     vnet->Users[i].P.output1 = NULL;
     vnet->Users[i].P.output2 = NULL;
     vnet->Users[i].P.blocks = 0;
   }

   uint32_t *prgArray = malloc(vnet->grdSize * sizeof(uint32_t));
   mpz_t *Sum_prgArray = malloc(vnet->grdSize * sizeof(mpz_t));

   uint32_t *prgArrayTag = malloc(vnet->grdSize * sizeof(uint32_t));

   for(int k=0;k<vnet->grdSize;k++){
      mpz_init(vnet->tagGlobalVector[k]);
      mpz_init(Sum_prgArray[k]);
      mpz_set_ui(vnet->tagGlobalVector[k],0);
      mpz_set_ui(Sum_prgArray[k],0);
   }
   for (int i = 0; i < vnet->numClients; i++) {
      if(vnet->Uact2[i]==0)
         continue;

      // generate prgArray G(beta_i)
      char *betaMasked;
      size_t betaMaskedSize = mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
      padWithZero(&betaMasked, betaMaskedSize, vnet->secparam);
      memcpy((char *)prg->hmac.key, (char *)betaMasked, vnet->secparam);
      free(betaMasked);
      PRG_Eval(prg);
      memcpy(prgArray,prg->randomOutput,prg->size);

      // generate G( prgArrayTag = beta hat_i)
      char* betatag;
      size_t betatagSize = mpz_to_byteArray(&betatag, vnet->Users[i].betaVerify);
      padWithZero(&betatag, betatagSize, vnet->secparam);
      memcpy((char *)prg->hmac.key, betatag, vnet->secparam);
      free(betatag);
      PRG_Eval(prg);
      memcpy(prgArrayTag,prg->randomOutput,prg->size);
      
      for (int j = 0; j < vnet->grdSize; j++){
      mpz_add(Sum_prgArray[j],Sum_prgArray[j],vnet->Users[i].maskedLocalVector[j]);
      mpz_mod(Sum_prgArray[j],Sum_prgArray[j],vnet->grp.prime);

      mpz_sub_ui(Sum_prgArray[j],Sum_prgArray[j],prgArray[j]);
      mpz_mod(Sum_prgArray[j],Sum_prgArray[j],vnet->grp.prime);
      
      mpz_add(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],vnet->Users[i].maskTag[j]);
      mpz_mod(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],vnet->grp.prime);
      mpz_sub_ui(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],prgArrayTag[j]);
      mpz_mod(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],vnet->grp.prime);
      }
   }


   for(int i=0;i< vnet->numClients;i++){
      if(vnet->Uact1[i]==0||vnet->Uact2[i]==1)
         continue;
      for (int z = 0; z < vnet->numClients; z++) {
         if(z==i || vnet->Uact1[z]==0)
            continue;
         // Mask Gradient
         memset(prg->hmac.key,0,vnet->secparam);
         memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sdata[z], MIN(8,vnet->secparam));
         PRG_Eval(prg);
         memcpy(prgArray,prg->randomOutput,prg->size);

         // Mask Tag
         memset(prg->hmac.key,0,vnet->secparam);
         memcpy((char *)prg->hmac.key, (const char *)vnet->Users[i].sverify[z], MIN(8,vnet->secparam));
         PRG_Eval(prg);
         memcpy(prgArrayTag,prg->randomOutput,prg->size);

         for (int j = 0; j < vnet->grdSize; j++) {
            if(z>i){
               mpz_add_ui(Sum_prgArray[j],Sum_prgArray[j],prgArray[j]);
               mpz_mod(Sum_prgArray[j],Sum_prgArray[j],vnet->grp.prime);

               mpz_add_ui(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],prgArrayTag[j]);
               mpz_mod(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],vnet->grp.prime);
            }
            else{
               mpz_sub_ui(Sum_prgArray[j],Sum_prgArray[j],prgArray[j]);
               mpz_mod(Sum_prgArray[j],Sum_prgArray[j],vnet->grp.prime);

               mpz_sub_ui(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],prgArrayTag[j]);
               mpz_mod(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],vnet->grp.prime);
            }
         }

      }
   }

   for(int j=0;j<vnet->grdSize;j++){
      vnet->gradGlobalVector[j] = (u_int32_t)mpz_get_ui(Sum_prgArray[j]);
      mpz_clear(Sum_prgArray[j]);
   }
   free(prgArray);
   free(prgArrayTag);
   free(Sum_prgArray);

}

void VNET_Vrfy(DscVNet *vnet,DscPRG* prg)
{
   bool vrfy = true;


   
   // Prf key
   char* vk;
   size_t vkSize = mpz_to_byteArray(&vk, vnet->vk);
   padWithZero(&vk, vkSize, vnet->secparam);
   memcpy(vnet->prf.key, vk, vnet->secparam);
   free(vk);
   
   unsigned char str1 [6];
   str1[0] = (vnet->rndlbl >> 24) & 0xFF;
   str1[1] = (vnet->rndlbl >> 16) & 0xFF;
   str1[2] = (vnet->rndlbl >> 8) & 0xFF;
   str1[3] = vnet->rndlbl & 0xFF;
   str1[4] = 0;
   str1[5] = 0;
   
   memset(prg->hmac.key,0,vnet->secparam); //for any letover bytes of key to be zero
   PRF_Eval(&(vnet->prf),(char*)str1,6);
   memcpy((char*)(prg->hmac.key),vnet->prf.randomOutput, MIN(32,vnet->secparam));
   
   mpz_t k_p;
   mpz_init(k_p);
   PRG_Eval(prg);
   byteArray_to_mpz(k_p, (char*)prg->randomOutput, prg->size);
   mpz_mod(k_p,k_p,vnet->grp.prime);

   uint32_t** k_s_i = (uint32_t**) malloc(vnet->numClients*sizeof(uint32_t*));

   for(u_int16_t user=0;user<vnet->numClients;user++){
      if(vnet->Uact1[user]==0)
         continue;
      str1[4] = (user>>8)&0xFF;
      str1[5] = user & 0xFF;
      k_s_i[user] = (uint32_t*)malloc(vnet->grdSize*sizeof(uint32_t));
      memset(prg->hmac.key,0,vnet->secparam); //for any letover bytes of key to be zero
      PRF_Eval(&(vnet->prf),(char*)str1,6);
      memcpy((char*)(prg->hmac.key),vnet->prf.randomOutput, MIN(32,vnet->secparam));
      PRG_Eval(prg);
      memcpy(k_s_i[user], prg->randomOutput, prg->size);    
   }

   mpz_t *tagPrime = malloc(vnet->grdSize * sizeof(mpz_t));

   for(int j =0;j<vnet->grdSize;j++){
      mpz_init(tagPrime[j]);
      mpz_set_ui(tagPrime[j],0);
   }
   for (int j = 0; j < vnet->grdSize; j++) {
      mpz_addmul_ui(tagPrime[j],k_p,vnet->gradGlobalVector[j]);
      mpz_mod(tagPrime[j],tagPrime[j],vnet->grp.prime);
   }
   for(int user=0;user<vnet->numClients;user++){
      if(vnet->Uact2[user]==0)
         continue;
      for(int k=0;k<vnet->grdSize;k++){
         mpz_add_ui(tagPrime[k],tagPrime[k],k_s_i[user][k]);
         mpz_mod(tagPrime[k],tagPrime[k],vnet->grp.prime);
      }
   }


   for(int k=0;k<vnet->grdSize;k++){
      int result = mpz_cmp(vnet->tagGlobalVector[k],tagPrime[k]);
      if(result != 0){
         printf("\ninvalid\n");
         exit(1);
      }
   }

   printf("\nvalid\n");
}

void randomly_zero_out(uint16_t *dest, uint16_t *src, size_t size, double percentage)
{
   if ((dest <= src && src < dest + size) ||
    (src <= dest && dest < src + size)) {
    printf("WARNING: src and dest overlap!\n");
}
   size_t count = (size_t)(size * percentage); // Number of elements to set to 0
   size_t i, selected;

   // Copy src to dest
   for (i = 0; i < size; i++) {
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

  DscTimeMeasure timemeasure;

  uint32_t size = GRAD_SIZE * 4;

  DscPRG prg2;
  PRG_Config(&prg2, SEC_PARAM, size);
  PRG_SeedGen(&prg2);

  DscVNet vnet;

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  VNET_Config(&vnet);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("\nElapsed Time for Config is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  VNET_Init(&vnet);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("\nElapsed Time for Init is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);

  double percentage = 1;
  size_t count = (size_t)(vnet.numClients * percentage);
  size_t selected; for (int i = 0; i < count; i++) {
     do{

        selected = rand() % vnet.numClients;
     }while (vnet.Uact1[selected] == 1);
     vnet.Uact1[selected] =1;
  }

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  for (int i = 0; i < vnet.numClients; i++) {
    if (vnet.Uact1 == 0)
      continue;
    VNET_KeyShare(&vnet, i);
  }
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("\nElapsed Time for key is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);

  // Step 2: Set 10% of indices in Uact2 to 0 based on Uact1

  randomly_zero_out(vnet.Uact2, vnet.Uact1, vnet.numClients, 0.2);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  for (int i = 0; i < vnet.numClients; i++) {
    if (vnet.Uact2[i] == 0)
      continue;
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

  // Step 3: Set 10% of indices in Uact3 to 0 based on Uact2

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  DscPRG prg;
  PRG_Config(&prg, SEC_PARAM, size);
  PRG_SeedGen(&prg);
  randomly_zero_out(vnet.Uact3, vnet.Uact2, vnet.numClients, 0.2);
  VNET_UNMask(&vnet, &prg);
  PRG_Free(&prg);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("\nElapsed Time for UNmask Function is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);
  printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  DscPRG prg3;
  PRG_Config(&prg3, SEC_PARAM, size);
  PRG_SeedGen(&prg3);
  VNET_Vrfy(&vnet, &prg3);
  PRG_Free(&(prg3));
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("\nElapsed Time for Verify Function is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);
  printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);
  return 0;
}