#include <pbc/pbc.h>
#include <pbc/pbc_curve.h>
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

typedef struct{
   uint8_t val[32];
} Seed;

typedef struct {
   int Uid; // Unique ID for the user

   mpz_t skey;
   mpz_t pkey;
   mpz_t shares_x;      // id related to thss
   mpz_t shares_y;      // secret share related to thss

   unsigned long *plainLocalVector;

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
   mpz_t* k_p;
   mpz_t* k_s_i;

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

   uint16_t *Uact1, *Uact2, *Uact3;

   mpz_t *gradGlobalVector;
   mpz_t *tagGlobalVector;

   DscClient *Users; // Array of users (clients)
   unsigned char vk[32];

} DscVNet;

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
void VNET_Config(DscVNet *vnet)
{

   vnet->secparam = SEC_PARAM;
   vnet->thrshld = Threshold;
   vnet->numClients = USERS_SIZE;
   vnet->grdSize = GRAD_SIZE;
   vnet->rndlbl = 1;

   vnet->Uact1 = calloc(vnet->numClients ,sizeof(uint16_t));
   vnet->Uact2 = calloc(vnet->numClients , sizeof(uint16_t));
   vnet->Uact3 = calloc(vnet->numClients , sizeof(uint16_t));

   vnet->gradGlobalVector = malloc(vnet->grdSize * sizeof(mpz_t));
   vnet->tagGlobalVector = malloc(vnet->grdSize * sizeof(mpz_t));

   GroupGen_Config(&(vnet->grp),vnet->secparam*8);
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
      vnet->Users[i].plainLocalVector = calloc(vnet->grdSize, sizeof(unsigned long));
      vnet->Users[i].maskedLocalVector = malloc(vnet->grdSize * sizeof(mpz_t));
      vnet->Users[i].maskTag = malloc(vnet->grdSize* sizeof(mpz_t));
      vnet->Users[i].k_p = malloc(vnet->grdSize* sizeof(mpz_t));
      vnet->Users[i].k_s_i = malloc(vnet->grdSize* sizeof(mpz_t));

      for (int j = 0; j < vnet->grdSize; j++) {
         vnet->Users[i].plainLocalVector[j]= rand_uint64();
         mpz_init2(vnet->Users[i].k_p[j],sizeof(unsigned long)*8);
         mpz_init(vnet->Users[i].k_s_i[j]);

         mpz_inits(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskTag[j],NULL);
      }

   }
}

void VNET_Init(DscVNet *vnet)
{
   GroupGen(&(vnet->grp));
   ThrCrypt_DKeyGen(&(vnet->thrcrypt));
   RAND_bytes(vnet->vk, sizeof(vnet->vk));

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
}
void VNET_Mask(DscVNet *vnet, uint16_t i)
{
   uint32_t Uact1Active = 0;
   for(int k=0;k<vnet->numClients;k++){
      Uact1Active+=vnet->Uact1[k];
   }
   if(Uact1Active<vnet->thrshld){
      printf("\nVNET_MASK: Not enough active members to continue.\n");
      exit(1);
   }

   unsigned long *prgArray = malloc(vnet->grdSize * sizeof(unsigned long));
   unsigned long *prgArrayTag = malloc(vnet->grdSize * sizeof(unsigned long));
   
   //generate k_p
   uint8_t str1 [6]={0};
   str1[0] = (vnet->rndlbl >> 24) & 0xFF;
   str1[1] = (vnet->rndlbl >> 16) & 0xFF;
   str1[2] = (vnet->rndlbl >> 8) & 0xFF;
   str1[3] = vnet->rndlbl & 0xFF;

   uint8_t randomOutput[GRAD_SIZE*sizeof(unsigned long)];
   uint8_t t[32];
   PRF(t,vnet->vk,sizeof(vnet->vk),str1,sizeof(str1));
   PRG(randomOutput,sizeof(randomOutput),t);
   for(int j=0;j<GRAD_SIZE;j++){
      mpz_set_ui(vnet->Users[i].k_p[j],((unsigned long*)randomOutput)[j]);
   }

   //generate k_s_i
   str1[4] = (i >>  8)&0xFF;
   str1[5] = i & 0xFF;
   PRF(t,vnet->vk,sizeof(vnet->vk),str1,sizeof(str1));
   PRG(randomOutput,sizeof(randomOutput),t);
   for(int j=0;j<GRAD_SIZE;j++){
      mpz_set_ui(vnet->Users[i].k_s_i[j],((unsigned long*)randomOutput)[j]);
   }

   for (int z = 0; z < vnet->numClients; z++) {
      if(z==i || vnet->Uact1[z]==0)
         continue;
      // Mask Gradient prgArray = G(s_i,z)
      PRG((uint8_t*)prgArray,GRAD_SIZE*sizeof(unsigned long),vnet->Users[i].sdata[z].val);
      // Mask Tag prgArrayTag = G(s hat_i,z)
      PRG((uint8_t*)prgArrayTag,GRAD_SIZE*sizeof(unsigned long),vnet->Users[i].sverify[z].val);

      if(z>i){
         for (int j = 0; j < vnet->grdSize; j++) {
            mpz_add_ui(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],prgArray[j]);
            mpz_add_ui(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],prgArrayTag[j]);
         }
      }
      else{
         for (int j = 0; j < vnet->grdSize; j++) {
            mpz_sub_ui(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],prgArray[j]);
            mpz_sub_ui(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],prgArrayTag[j]);
         }
      }
   }

   for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],
         vnet->Users[i].plainLocalVector[j]);
   }

   // generate prgArray G(beta_i)
   char *betaMasked;
   size_t betaMaskedSize = mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
   padWithZero(&betaMasked, betaMaskedSize, 32);
   PRG((uint8_t*)prgArray,GRAD_SIZE*sizeof(unsigned long),(uint8_t*)betaMasked);
   free(betaMasked);

   for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskedLocalVector[j],vnet->Users[i].maskedLocalVector[j],prgArray[j]);
   }


   // generate G( prgArrayTag = beta hat_i)
   char* betatag;
   size_t betatagSize = mpz_to_byteArray(&betatag, vnet->Users[i].betaVerify);
   padWithZero(&betatag, betatagSize, 32);
   PRG((uint8_t*)prgArrayTag,GRAD_SIZE*sizeof(unsigned long),(uint8_t*)betatag);
   free(betatag);

   for (int j = 0; j < vnet->grdSize; j++) {
      mpz_add_ui(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j] ,prgArrayTag[j]);
      mpz_add(vnet->Users[i].maskTag[j],vnet->Users[i].maskTag[j],vnet->Users[i].k_s_i[j]);
      mpz_addmul_ui(vnet->Users[i].maskTag[j],vnet->Users[i].k_p[j],vnet->Users[i].plainLocalVector[j]);   
   }

   free(prgArray);free(prgArrayTag);
}

void VNET_UNMask(DscVNet *vnet)
{
   uint32_t Uact1Active = 0;
   uint32_t Uact2Active = 0;
   uint32_t Uact3Active = 0;
   for(int k=0;k<vnet->numClients;k++){
      Uact2Active += vnet->Uact2[k];
      Uact3Active += vnet->Uact3[k];
      Uact1Active += vnet->Uact1[k];
   }
   printf("U1: %u, U2 %u, U3 %u\n",Uact1Active,Uact2Active,Uact3Active);

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
     memcpy(vnet->Users[i].sdata, vnet->thrcrypt.plaintextOutput,
            sizeof(Seed) * USERS_SIZE);
     memcpy(vnet->Users[i].sverify,
            vnet->thrcrypt.plaintextOutput + USERS_SIZE * sizeof(Seed),
            sizeof(Seed) * USERS_SIZE);

     Cipher_Free(&(vnet->thrcrypt.cipher));
     vnet->Users[i].P.output1 = NULL;
     vnet->Users[i].P.output2 = NULL;
     vnet->Users[i].P.blocks = 0;
   }

   unsigned long *prgArray = malloc(vnet->grdSize * sizeof(unsigned long));
   unsigned long *prgArrayTag = malloc(vnet->grdSize * sizeof(unsigned long));

   for(int k=0;k<vnet->grdSize;k++){
      mpz_init(vnet->tagGlobalVector[k]);
      mpz_init(vnet->gradGlobalVector[k]);
   }
   for (int i = 0; i < vnet->numClients; i++) {
      if(vnet->Uact2[i]==0)
         continue;

      // generate prgArray G(beta_i)
      char *betaMasked;
      size_t betaMaskedSize = mpz_to_byteArray(&betaMasked, vnet->Users[i].betaMasked);
      padWithZero(&betaMasked, betaMaskedSize, 32);
      PRG((uint8_t*)prgArray,GRAD_SIZE*sizeof(unsigned long),(uint8_t*)betaMasked);
      free(betaMasked);

      // generate G( prgArrayTag = beta hat_i)
      char* betatag;
      size_t betatagSize = mpz_to_byteArray(&betatag, vnet->Users[i].betaVerify);
      padWithZero(&betatag, betatagSize, 32);
      PRG((uint8_t*)prgArrayTag,GRAD_SIZE*sizeof(unsigned long),(uint8_t*)betatag);
      free(betatag);
      
      for (int j = 0; j < vnet->grdSize; j++){
      mpz_add(vnet->gradGlobalVector[j],vnet->gradGlobalVector[j],vnet->Users[i].maskedLocalVector[j]);
      mpz_sub_ui(vnet->gradGlobalVector[j],vnet->gradGlobalVector[j],prgArray[j]);
      
      mpz_add(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],vnet->Users[i].maskTag[j]);
      mpz_sub_ui(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],prgArrayTag[j]);
      }
   }


   for(int i=0;i< vnet->numClients;i++){
      if(vnet->Uact1[i]==0||vnet->Uact2[i]==1)
         continue;
      for (int z = 0; z < vnet->numClients; z++) {
         if(z==i || vnet->Uact1[z]==0)
            continue;
         // Mask Gradient prgArray = G(s_i,z)
         PRG((uint8_t*)prgArray,GRAD_SIZE*sizeof(unsigned long),vnet->Users[i].sdata[z].val);

         // Mask Tag prgArrayTag = G(s hat_i,z)
         PRG((uint8_t*)prgArrayTag,GRAD_SIZE*sizeof(unsigned long),vnet->Users[i].sverify[z].val);

         if(z>i){
            for (int j = 0; j < vnet->grdSize; j++) {
               mpz_add_ui(vnet->gradGlobalVector[j],vnet->gradGlobalVector[j],prgArray[j]);
               mpz_add_ui(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],prgArrayTag[j]);
            }
         }
         else{
            for (int j = 0; j < vnet->grdSize; j++) {
               mpz_sub_ui(vnet->gradGlobalVector[j],vnet->gradGlobalVector[j],prgArray[j]);
               mpz_sub_ui(vnet->tagGlobalVector[j],vnet->tagGlobalVector[j],prgArrayTag[j]);
            }
         }
      }
   }
   free(prgArray);
   free(prgArrayTag);
}

void VNET_Vrfy(DscVNet *vnet)
{
   bool vrfy = true;
   
   uint8_t str1 [6]={0};
   str1[0] = (vnet->rndlbl >> 24) & 0xFF;
   str1[1] = (vnet->rndlbl >> 16) & 0xFF;
   str1[2] = (vnet->rndlbl >> 8) & 0xFF;
   str1[3] = vnet->rndlbl & 0xFF;
   mpz_t *k_p = malloc(GRAD_SIZE*sizeof(mpz_t));
   uint8_t randomOutput[GRAD_SIZE*sizeof(unsigned long)];

   uint8_t t[32];
   PRF(t,vnet->vk,sizeof(vnet->vk),str1,sizeof(str1));
   PRG(randomOutput,sizeof(randomOutput),t);
   for(int j=0;j<GRAD_SIZE;j++){
      mpz_init_set_ui(k_p[j],((unsigned long*)randomOutput)[j]);
   }
   mpz_t** k_s_i = (mpz_t**) malloc(USERS_SIZE*sizeof(mpz_t*));

   for(uint16_t user=0;user<vnet->numClients;user++){
      if(vnet->Uact1[user]==0)
         continue;
      str1[4] = (user>>8)&0xFF;
      str1[5] = user & 0xFF;
      k_s_i[user] = (mpz_t *)malloc(GRAD_SIZE*sizeof(mpz_t));

      PRF(t,vnet->vk,sizeof(vnet->vk),str1,sizeof(str1));
      PRG(randomOutput,sizeof(randomOutput),t);
      for(int j=0;j<GRAD_SIZE;j++){
         mpz_init_set_ui(k_s_i[user][j],((unsigned long*)randomOutput)[j]);
      }
   }

   mpz_t *tagPrime = malloc(vnet->grdSize * sizeof(mpz_t));
   
   for(int j =0;j<vnet->grdSize;j++){
      mpz_init(tagPrime[j]);
      mpz_addmul(tagPrime[j],k_p[j],vnet->gradGlobalVector[j]);
   }
   for(int user=0;user<vnet->numClients;user++){
      if(vnet->Uact2[user]==0)
         continue;
      for(int k=0;k<vnet->grdSize;k++){
         mpz_add(tagPrime[k],tagPrime[k],k_s_i[user][k]);
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

  DscTimeMeasure timemeasure;

  uint32_t size = GRAD_SIZE * sizeof(unsigned long);

  printf("\n** Dropout = %f, n = %d, gradient size: %d**\n",(float)DropOut,USERS_SIZE,GRAD_SIZE);
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
  printf("Elapsed Time for Init is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);

  double percentage = 1-DropOut;
  size_t count = (size_t)(vnet.numClients * percentage);
  size_t selected; 
  for (int i = 0; i < count; i++) {
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
  printf("Elapsed Time for key is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);

  // Step 2: Set 10% of indices in Uact2 to 0 based on Uact1

  randomly_zero_out(vnet.Uact2, vnet.Uact1, (1-DropOut)*vnet.numClients, DropOut);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  for (int i = 0; i < vnet.numClients; i++) {
    if (vnet.Uact2[i] == 0)
      continue;
    VNET_Mask(&vnet, i);
  }
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("Elapsed Time for Mask Function is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);
  printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);

  // Step 3: Set 10% of indices in Uact3 to 0 based on Uact2

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  randomly_zero_out(vnet.Uact3, vnet.Uact2, (1-DropOut)*(1-DropOut)*vnet.numClients, DropOut);
  VNET_UNMask(&vnet);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("Elapsed Time for UNmask Function is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);
  printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);

  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.start)));
  VNET_Vrfy(&vnet);
  clock_gettime(CLOCK_MONOTONIC, (&(timemeasure.end)));
  Time_Measure(&timemeasure);
  printf("Elapsed Time for Verify Function is as below:\n");
  printf("In Seconds: %ld\n", timemeasure.seconds);
  printf("In Milliseconds: %ld\n", timemeasure.milliseconds);
  printf("In Microseconds: %ld\n", timemeasure.microseconds);
  printf("In Nanoseconds: %ld\n\n", timemeasure.nanoseconds);
  return 0;
}