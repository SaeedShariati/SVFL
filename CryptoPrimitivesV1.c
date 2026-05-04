#include "CryptoPrimitivesV1.h"
#include <gmp.h>
#include <pbc/pbc.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <tomcrypt.h>
#include <unistd.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
//turns mpz_t into an array of bytes and returns the number of bytes
uint32_t mpz_to_byteArray(char** rop, mpz_ptr integer){
    size_t count = 0;
    size_t size_in_bytes = (mpz_sizeinbase(integer, 2) + 7) / 8;
    
    *rop = (char*)malloc(size_in_bytes);
    if (!*rop) return 0;  // malloc failed
    mpz_export(*rop, &count, 1, sizeof(char), 1, 0, integer);

    return (uint32_t)count;
}
void byteArray_to_mpz(mpz_ptr rop, char *byteArray, uint32_t size) {
  mpz_import(rop, size, 1, sizeof(char), 0, 0,
              byteArray);
}
// ############ Time Measurement ############
void Time_Measure(DscTimeMeasure *time) {
  time->seconds = time->end.tv_sec - time->start.tv_sec;
  time->nanoseconds = time->end.tv_nsec - time->start.tv_nsec;

  if (time->nanoseconds < 0) {
    time->seconds -= 1;
    time->nanoseconds += 1000000000;
  }

  time->milliseconds = time->seconds * 1000 + time->nanoseconds / 1000000;
  time->microseconds = time->seconds * 1000000 + time->nanoseconds / 1000;
  time->nanoseconds = time->seconds*1000000000 + time->nanoseconds;
}

/* 16 bytes key
void PRG(uint8_t *out, size_t outlen, const uint8_t *seed16) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  uint8_t iv[16] = {0};
  
  EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed16, iv);
  memset(out,0,20);
  int len;
  EVP_EncryptUpdate(ctx, out, &len, out, outlen);  // encrypt zeros
  EVP_CIPHER_CTX_free(ctx);
}
*/
//outlen is in bytes
void PRG(uint8_t *out, size_t outlen, const uint8_t *key32) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  uint8_t iv[16] = {0};  // 128-bit IV (can also be passed as a parameter)

  EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key32, iv);
  memset(out, 0, outlen);
  int len;
  EVP_EncryptUpdate(ctx, out, &len, out, outlen);
  EVP_CIPHER_CTX_free(ctx);
}
void PRF(
    uint8_t out[32],
    const uint8_t *key, size_t keylen,
    const uint8_t *input, size_t inputlen
) {
    unsigned int outlen = 32;
    HMAC(EVP_sha256(), key, keylen, input, inputlen, out, &outlen);
}


void hash256(char* plaintext,uint32_t length, char* digest){
  EVP_Q_digest(NULL, "SHA256", NULL, plaintext, length, (unsigned char*)digest, NULL);
}
static void print(char* a, uint32_t size)
{
   for(int i =0;i<size;i++){
      printf(" %02x",(unsigned char)a[i]);
   }
   printf("\n");
}
// commitment = Hash256(skey||value)
void commit(mpz_ptr skey,mpz_ptr value,char** commitment){
  register_hash(&sha256_desc);
  *commitment = malloc(32);
  char* skey_b,*value_b;
  int skey_size = mpz_to_byteArray(&skey_b,skey);
  int value_size = mpz_to_byteArray(&value_b,value);
  char* input = malloc(skey_size+value_size);
  memcpy(input,skey_b,skey_size);
  memcpy(input+skey_size,value_b,value_size);
  free(skey_b);free(value_b);
  
  hash256(input, skey_size+value_size, *commitment);
  free(input);
}
//verifies and then frees the commitment
void open_commitment(mpz_ptr skey,mpz_ptr value,char* commitment){
  register_hash(&sha256_desc);
  char* skey_b,*value_b;
  int skey_size = mpz_to_byteArray(&skey_b,skey);
  int value_size = mpz_to_byteArray(&value_b,value);
  char* input = malloc(skey_size+value_size);
  memcpy(input,skey_b,skey_size);
  memcpy(input+skey_size,value_b,value_size);
  free(skey_b);free(value_b);

  char* computed = malloc(32);
  hash256(input, skey_size+value_size, computed);
  if(memcmp(computed, commitment, 32)){
    fprintf(stderr, "[open_commitment] commitment not valid.\n");
    exit(-1);
  }

  free(computed);
  free(input);
  //free(commitment);
}
// ###############################
// initilizes prime, generator and order and sets secparam=512 bits
void GroupGen_Config(DscGrp *grp, uint32_t secparam) {
  grp->secparam = secparam;
  mpz_inits(grp->q,grp->p,grp->generator,grp->order,NULL);
}
// generates Z_p* with generator = 2, and p is a safe prime (p=2q+1 where q is a
// prime)
void GroupGen(DscGrp *grp) {
  // Generate a random safe prime number (p = 2q + 1)
  mpz_t test;
  gmp_randinit_default(grp->state);
  gmp_randseed_ui(grp->state, time(NULL));
  mpz_init(test);

  while (1) {
    // Generate random 511-bit prime q
    mpz_urandomb(grp->q, grp->state, grp->secparam);
    mpz_setbit(grp->q, grp->secparam - 1); // ensure it's secparam bits

    mpz_nextprime(grp->q, grp->q);
    // q might be a secparam bit prime,if so p will be secparam+1 bit prime,
    // might cause buffer overlfow somewhere in the code
    mpz_mul_ui(grp->p, grp->q, 2);
    mpz_add_ui(grp->p, grp->p, 1);

    if (mpz_probab_prime_p(grp->p, 250) > 0) {
      mpz_set_ui(test, 2);
      mpz_powm(test, test, grp->q, grp->p);

      if (mpz_cmp_ui(test, 1) == 0) {
        mpz_set_ui(grp->generator, 2);
        mpz_sub_ui(grp->order, grp->q, 1);
        break;
      }
    }
  }

  mpz_clears( test, NULL);
}
void GroupGen_Free(DscGrp* grp){
  mpz_clears(grp->q,grp->p,grp->generator,grp->order,NULL);
  gmp_randclear(grp->state);
}

void generatePrime(mpz_ptr rop, uint32_t sizeInBits){
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));

  mpz_urandomb(rop, state, sizeInBits);
  mpz_nextprime(rop, rop);
  gmp_randclear(state);
}
// sets the value of rndelement to a random value less than prime (does NOT initialize rndelement)
void generate_random_mpz(mpz_ptr prime, mpz_ptr rndelement) {
  char out[32];
  char key[32];
  for(int i =0;i<32;i++)
    key[i] = i;
  PRG((unsigned char*)out, 32, (unsigned char*)key);
  //print(out,32);
  byteArray_to_mpz(rndelement, out, 32);
  gmp_printf("[generate_random_mpz]    %Zd\n",rndelement);
}
// ###### Thrss=(Share,ReConst) (Shamir Secret Sharing)
void Thss_Config(DscThssFeldman *thss,DscGrp* grp, int secparam_bits, int total, int threshold) {
  thss->num_bits = secparam_bits;
  thss->num_shares = total;
  thss->threshold = threshold;

  thss->commitments = (mpz_t*)malloc(thss->threshold * sizeof(mpz_t));
  thss->shares_x = (mpz_t *)malloc(thss->num_shares * sizeof(mpz_t));
  thss->shares_y = (mpz_t *)malloc(thss->num_shares * sizeof(mpz_t));
  mpz_init(thss->recovered_secret);
  thss->coeffs = (mpz_t *)malloc((thss->threshold) * sizeof(mpz_t));
  thss->grp = grp;
}
// find (thss->num_shares) points on the polynomial, if secret is NULL then
// generates one randomly
void Thss_Share(DscThssFeldman *thss, mpz_ptr secret) {
  mpz_init(thss->secret);
  if (!secret) {
    mpz_urandomm(thss->secret,thss->grp->state,thss->grp->q);
  } else {
    mpz_set(thss->secret, secret);
  }
  mpz_init(thss->coeffs[0]);
  mpz_set(thss->coeffs[0], thss->secret);
  mpz_init(thss->commitments[0]);
  mpz_powm(thss->commitments[0],thss->grp->generator,thss->coeffs[0],thss->grp->p);

  for (int i = 1; i < thss->threshold; i++) {
    mpz_init(thss->coeffs[i]);
    mpz_urandomm(thss->coeffs[i],thss->grp->state,thss->grp->q);
    mpz_init(thss->commitments[i]);
    mpz_powm(thss->commitments[i],thss->grp->generator,thss->coeffs[i],thss->grp->p);
  }

  mpz_t x,term;
  mpz_inits(term,x,NULL);

  for (int i = 0; i < thss->num_shares; i++) {
    mpz_set_ui(x, i + 1); 
    mpz_init(thss->shares_x[i]);
    mpz_init(thss->shares_y[i]);
    mpz_set(thss->shares_x[i], x);
    mpz_set_ui(thss->shares_y[i], 0);

    for (int j = thss->threshold - 1; j >= 0; j--) {
      mpz_mul(term, thss->shares_y[i], thss->shares_x[i]);
      mpz_mod(term, term, thss->grp->q);
      mpz_add(thss->shares_y[i], term, thss->coeffs[j]);
      mpz_mod(thss->shares_y[i], thss->shares_y[i], thss->grp->q);
    }
  }
  mpz_clear(x);
  mpz_clear(term);

  for (int i = 0; i < thss->threshold; i++) {
    mpz_clear(thss->coeffs[i]);
  }

}
//index of share (i) return 1 if valid 0 if not
uint32_t power(uint32_t i,uint32_t j){
  uint32_t result =1;
  for(int t =0;t<j;t++){
    result *= i;
  }
  return result;
}
void Thss_Verify_Share(DscThssFeldman* thss, uint32_t i){

  mpz_t result;
  mpz_init(result);
  mpz_set_ui(result,1);
  mpz_t term;
  mpz_init(term);

  mpz_t i_index,power;
  mpz_inits(i_index,power,NULL);
  mpz_set_ui(i_index,i+1);
  for(uint32_t j =0;j<thss->threshold;j++){
    mpz_powm_ui(power,i_index,j,thss->grp->q);
    mpz_powm(term,thss->commitments[j],power,thss->grp->p);
    mpz_mul(result,result,term);
    mpz_mod(result,result,thss->grp->p);
  }
  mpz_clears(i_index,power,NULL);
  mpz_clear(term);
  mpz_t gsi;
  mpz_init(gsi);
  mpz_powm(gsi,thss->grp->generator,thss->shares_y[i],thss->grp->p);
  /*
  printf("[%d]",i);
  gmp_printf("Thss Verify gsi:     %#Zx\n", gsi);
  printf("[%d]",i);
  gmp_printf("Thss Verify result:  %#Zx\n", result);
  printf("-----------------------------\n");
  */
  
  if(mpz_cmp(result,gsi)){
    fprintf(stderr, "[Thss_Verify_Share(%d)] Not Equal!\n",i);
    exit(-1);
  }
  mpz_clear(result);
  mpz_clear(gsi);
}
void Thss_ReCons(DscThssFeldman *thss) {
  mpz_set_ui(thss->recovered_secret, 0);
  mpz_t term, numerator, denominator, temp;
  mpz_inits(term, numerator, denominator, temp, NULL);

  for (int i = 0; i < thss->threshold; i++) {
    mpz_set_ui(term, 1);
    for (int j = 0; j < thss->threshold; j++) {
      if (i != j) {
        mpz_sub(numerator, thss->shares_x[j], thss->shares_x[i]);
        mpz_set(denominator, numerator);
        mpz_set_ui(temp, 0);
        mpz_add(temp, temp, thss->shares_x[j]);
        mpz_mul(term, term, temp);
        mpz_mod(term, term, thss->grp->q);
        mpz_invert(denominator, denominator, thss->grp->q);
        mpz_mul(term, term, denominator);
        mpz_mod(term, term, thss->grp->q);
      }
    }
    mpz_mul(term, term, thss->shares_y[i]);
    mpz_mod(term, term, thss->grp->q);
    mpz_add(thss->recovered_secret, thss->recovered_secret, term);
    mpz_mod(thss->recovered_secret, thss->recovered_secret, thss->grp->q);
  }

  mpz_clears(term, numerator, denominator, temp, NULL);
}
void Thss_Free(DscThssFeldman *thss) {
  mpz_clears(thss->secret,thss->recovered_secret, NULL);
  free(thss->coeffs);
  for (int i = 0; i < thss->num_shares; i++) {
    mpz_clear(thss->shares_x[i]);
    mpz_clear(thss->shares_y[i]);
  }
  for(int j=0;j<thss->threshold;j++){
    mpz_clear(thss->commitments[j]);
  }
  free(thss->commitments);
  free(thss->shares_x);
  free(thss->shares_y);
}
// ###############################
//###### ThrCrypt=(DKeyGen,Enc,Dec) (Threshold Elgamal Cryptosystem)
void generate_random_polynomial(Polynomial* polynomial, uint8_t degree, mpz_ptr prime){
  polynomial->degree = degree;
  polynomial->coeffs = malloc(sizeof(mpz_t)*(degree+1));
  for(int i =0;i<(degree+1);i++){
    mpz_init(polynomial->coeffs[i]);
    generate_random_mpz(prime, polynomial->coeffs[i]);
  }
}
void polynomial_free(Polynomial* polynomial){
  for(int i =0;i<(polynomial->degree+1);i++){
    mpz_clear(polynomial->coeffs[i]);
  }
  free(polynomial->coeffs);
}

void ThrCrypt_Enc_Block(DscThrCrypt *thrcrypt,char* plaintext, uint32_t size, uint32_t blockNumber);
void ThrCrypt_Dec_Block(DscThrCrypt *thrcrypt, uint32_t blockNumber);
uint16_t decode_mpz_as_byteArray(char* rop, mpz_ptr integer);
void encode_bytes_as_mpz(mpz_ptr rop, char *byteArray, uint32_t size);

void ThrCrypt_Config(DscThrCrypt *thrcrypt,uint16_t secparam_bits,uint16_t total, uint16_t threshold) {

    thrcrypt->secparam_bits=secparam_bits;
    thrcrypt->total = total;
    thrcrypt->threshold = threshold;
    thrcrypt->maximumBlockSize = (u_int16_t)(thrcrypt->secparam_bits/8 -2);
    thrcrypt->commits = malloc(total*sizeof(char*));
    thrcrypt->u = malloc(total*sizeof(mpz_t));
    thrcrypt->gsi = malloc(total*sizeof(mpz_t));
    thrcrypt->xi = malloc(total*sizeof(mpz_t));
    thrcrypt->hi = malloc(total*sizeof(mpz_t));

    GroupGen_Config(&(thrcrypt->grp),secparam_bits);
    GroupGen(&(thrcrypt->grp));


    thrcrypt->ai = malloc(sizeof(DscThssFeldman)*total);
    for(int i =0;i<total;i++){
      Thss_Config(&(thrcrypt->ai[i]),&(thrcrypt->grp),secparam_bits,total,threshold);
    }

    Thss_Config(&(thrcrypt->thss),&(thrcrypt->grp),secparam_bits,total,threshold);
    mpz_inits(thrcrypt->pkey,thrcrypt->skey,NULL);
}

void ThrCrypt_DKeyGen(DscThrCrypt *thrcrypt){
  Thss_Share(&(thrcrypt->thss),NULL);

  for(int i =0;i< thrcrypt->thss.num_shares;i++)
    Thss_Verify_Share(&(thrcrypt->thss), i);


  //step 1, each party makes a random polynomial and commits to g^(si), si = ai(0)
  for(int i =0;i<thrcrypt->total;i++){
    mpz_init(thrcrypt->gsi[i]);

    Thss_Share(&(thrcrypt->ai[i]), NULL); //makes a random polynomial for each user
    mpz_powm(thrcrypt->gsi[i],thrcrypt->grp.generator,thrcrypt->ai[i].secret,thrcrypt->grp.p);
    mpz_init(thrcrypt->u[i]);
    mpz_urandomb(thrcrypt->u[i],thrcrypt->grp.state,thrcrypt->secparam_bits);
    commit(thrcrypt->u[i],thrcrypt->gsi[i],&(thrcrypt->commits[i]) );
  }
  //step 2, each party opens its commitment and calculate the public key
  for(int i =0;i<thrcrypt->total;i++){
    for(int j =0;j<thrcrypt->total;j++){
      if(j==i)
        continue;
      //verify the commitments
      open_commitment(thrcrypt->u[j], thrcrypt->gsi[j], thrcrypt->commits[j]); 
    }
    mpz_set_ui(thrcrypt->pkey,1);
    for(int j = 0;j<thrcrypt->total;j++){
      mpz_mul(thrcrypt->pkey,thrcrypt->pkey,thrcrypt->gsi[j]);
      mpz_mod(thrcrypt->pkey,thrcrypt->pkey,thrcrypt->grp.p);
    }
  }
  for(int i =0;i<thrcrypt->total;i++){
    mpz_clear(thrcrypt->u[i]);
  }
  free(thrcrypt->u);
  //step 3: Feldman already done
  //step 4: calculate xi and hi
  for(int i =0;i<thrcrypt->total;i++){
    mpz_inits(thrcrypt->xi[i],thrcrypt->hi[i],NULL);
    mpz_set_ui(thrcrypt->xi[i],0);
    for(int j =0;j<thrcrypt->total;j++){
      mpz_add(thrcrypt->xi[i],thrcrypt->xi[i],thrcrypt->ai[j].shares_y[i]);
      mpz_mod(thrcrypt->xi[i],thrcrypt->xi[i],thrcrypt->grp.q);
    }
    mpz_powm(thrcrypt->hi[i],thrcrypt->grp.generator,thrcrypt->xi[i],thrcrypt->grp.p);
  }
  mpz_set(thrcrypt->skey,thrcrypt->thss.secret);
}
//plaintext can be any series of bytes, doesn't have to be a string, size is in bytes
void ThrCrypt_Enc(DscThrCrypt *thrcrypt,char* plaintext, uint32_t size){
  thrcrypt->cipher.blocks=(uint32_t)((size+thrcrypt->maximumBlockSize-1)/thrcrypt->maximumBlockSize);
  thrcrypt->plaintextInput = malloc(size);
  memcpy(thrcrypt->plaintextInput,plaintext,size);

  uint32_t blockCount = thrcrypt->cipher.blocks;
  thrcrypt->cipher.output1 = (mpz_t*)malloc(blockCount*sizeof(mpz_t));
  thrcrypt->cipher.output2 = (mpz_t*)malloc(blockCount*sizeof(mpz_t));

  for(int block =0;block<blockCount-1;block++){
    mpz_inits(thrcrypt->cipher.output1[block],thrcrypt->cipher.output2[block],NULL);
    ThrCrypt_Enc_Block(thrcrypt,plaintext+block*(thrcrypt->maximumBlockSize)
      ,thrcrypt->maximumBlockSize,block);
  }
  mpz_inits(thrcrypt->cipher.output1[blockCount-1],thrcrypt->cipher.output2[blockCount-1],NULL);
  ThrCrypt_Enc_Block(thrcrypt, plaintext+(blockCount-1)*thrcrypt->maximumBlockSize
    ,size - (blockCount-1)*thrcrypt->maximumBlockSize, blockCount-1);

  free(thrcrypt->plaintextInput);

}
void ThrCrypt_Enc_Block(DscThrCrypt *thrcrypt,char* plaintext, uint32_t size, uint32_t blockNumber){
  mpz_t input;
  mpz_init(input);
  encode_bytes_as_mpz(input, plaintext, size);

  mpz_t k;
  mpz_init(k); 
  mpz_urandomm(k,thrcrypt->grp.state, thrcrypt->grp.q);

  // A = g^k mod p
  mpz_powm(thrcrypt->cipher.output1[blockNumber], thrcrypt->grp.generator,k, thrcrypt->grp.p);

  // B = m * h^k mod p
  mpz_powm(thrcrypt->cipher.output2[blockNumber], thrcrypt->pkey, k, thrcrypt->grp.p);
  mpz_mul(thrcrypt->cipher.output2[blockNumber], thrcrypt->cipher.output2[blockNumber], input);
  mpz_mod(thrcrypt->cipher.output2[blockNumber], thrcrypt->cipher.output2[blockNumber], thrcrypt->grp.p);
  mpz_clear(input);
  mpz_clear(k);
}
void ThrCrypt_Dec(DscThrCrypt *thrcrypt)
{
  thrcrypt->di = malloc((thrcrypt->threshold) *sizeof(mpz_t));
  for(int i=0;i<(thrcrypt->threshold);i++)
    mpz_init(thrcrypt->di[i]);

  thrcrypt->sizeOfPlaintext = 0;
  for(int block=0;block<thrcrypt->cipher.blocks;block++){
    ThrCrypt_Dec_Block(thrcrypt, block);
  }
  for(int i=0;i<(thrcrypt->threshold);i++)
    mpz_clear(thrcrypt->di[i]);
  free(thrcrypt->di);
  thrcrypt->plaintextOutput = realloc(thrcrypt->plaintextOutput,thrcrypt->sizeOfPlaintext);
}
void ThrCrypt_Dec_Block(DscThrCrypt *thrcrypt, uint32_t blockNumber)
{
  mpz_t product;
  mpz_t m;
  mpz_t term;
  mpz_inits(m,term,NULL);
  mpz_set(m,thrcrypt->cipher.output2[blockNumber]);
  mpz_t numberator;
  mpz_t denominator;
  mpz_inits(numberator,denominator,product,NULL);
  for(int i =0;i<thrcrypt->threshold;i++){
    mpz_powm(thrcrypt->di[i], thrcrypt->cipher.output1[blockNumber],thrcrypt->xi[i],thrcrypt->grp.p);
    mpz_set_ui(product,1);
    
    for(int j=0;j<thrcrypt->threshold;j++){
      if(j==i)
        continue;
      mpz_set_d(denominator,j-i);
      mpz_invert(denominator,denominator,thrcrypt->grp.q);
      mpz_set_d(numberator,j+1);
      mpz_mul(product,product,numberator);
      mpz_mul(product,product,denominator);
      mpz_mod(product,product,thrcrypt->grp.q);
    }
    mpz_powm(term,thrcrypt->di[i],product,thrcrypt->grp.p);
    mpz_invert(term,term,thrcrypt->grp.p);
    mpz_mul(m,m,term);
    mpz_mod(m,m,thrcrypt->grp.p);
  }
  mpz_clears(numberator,denominator,product,term,NULL);
  if(blockNumber==0){
    uint16_t bytes = mpz_size(m) * sizeof(mp_limb_t);
    thrcrypt->plaintextOutput = malloc((bytes-1)*thrcrypt->cipher.blocks);
  }
  thrcrypt->sizeOfPlaintext += 
    decode_mpz_as_byteArray(thrcrypt->plaintextOutput + blockNumber*thrcrypt->maximumBlockSize, m);
  mpz_clears(m,NULL);;
}
void ThrCrypt_Free(DscThrCrypt *thrcrypt) {
  for(int i=0;i<thrcrypt->total;i++)
  {
    mpz_clears(thrcrypt->gsi[i],thrcrypt->xi[i],thrcrypt->hi[i],NULL);
  }
  free(thrcrypt->gsi);
  free(thrcrypt->xi);
  free(thrcrypt->hi);

  mpz_clears(thrcrypt->skey,thrcrypt->pkey,NULL);
  GroupGen_Free(&(thrcrypt->grp));
  Thss_Free(&(thrcrypt->thss));
}
void Cipher_Free(DscCipher* cipher){
  for(int i=0;i<cipher->blocks;i++){
    mpz_clears(cipher->output1[i],cipher->output2[i],NULL);
  }
  free(cipher->output1);
  free(cipher->output2);
}
//convert byteArray with the specified size to mpz_t (rop must be initialized)
void encode_bytes_as_mpz(mpz_ptr rop, char *byteArray, uint32_t size) {
  char* paddedMessage = malloc(size + 1);
  paddedMessage[0] = 1; // padding(because mpz_t ignores leading zeros so we add a nonzero byte at the start)
  memcpy(paddedMessage+1, byteArray, size); //actual message
  mpz_import(rop, size+1, 1, sizeof(char), 0, 0,
              paddedMessage);
  free(paddedMessage);
}
//converts back the padded integer to byteArray(returns bytes read)
uint16_t decode_mpz_as_byteArray(char* rop, mpz_ptr integer){
  //size_t bytes = mpz_size(integer) * sizeof(mp_limb_t);
  size_t bytes = (mpz_sizeinbase(integer, 2) + 7) / 8;

  char* paddedMessage = malloc(bytes);
  mpz_export(paddedMessage, &bytes, 1, sizeof(char), 0, 0, integer);
  memcpy(rop, paddedMessage + 1, bytes - 1);
  free(paddedMessage);
  return bytes-1;
}
