#ifndef HASHING_H
#define HASHING_H

#include "includes.h"

typedef struct HashingField_s HashingField_t ;
typedef const EVP_MD* (*hash_func_t)(void);

int HashingFieldSize(void) ;

typedef enum { 
  SHA_512,
  SHA_384,
  SHA_256
} hashing_options_idx;


#include "user.h"
#include "usersconfig.h"
#include "bytebuffer.h"

int InitHashingField(HashingField_t **hf,
    const ByteBuff_t *text,
    const ByteBuff_t *salt);

int CreateHashingField(HashingField_t **hf,
    const ByteBuff_t *text);
int DupHashingField(HashingField_t **dst,
    const HashingField_t *src);

int DestroyHashingField(HashingField_t *hf);
int SerializeHashingField(const HashingField_t *hf,ByteBuff_t **out);
int DeserializeHashingField(HashingField_t **hf,const ByteBuff_t *in);


int HashingFieldGetText(const HashingField_t *hf,ByteBuff_t **text);
int HashingFieldGetSalt(const HashingField_t *hf,ByteBuff_t **salt);



int pkcs5_keyed_hash(const char *master,
                     int  master_size,
                     unsigned char *key,
                     const unsigned char *salt,
                     int salt_size,
                     const EVP_MD *digest,
                     int key_size,
                     uint32_t iters) ;
int pkcs5_keyed_hash_bytebuff(
    const ByteBuff_t *master,
    ByteBuff_t **key,
    size_t key_size,
    const ByteBuff_t *salt,
    const EVP_MD *digest,
    uint32_t iters) ;

int pkcs5_keyed_hash_HashingField(
    const HashingField_t *master,
    HashingField_t **key,
    int key_size,
    const EVP_MD *digest,
    uint32_t iters);
int hash_not_keyed(const unsigned char *plain,
                  size_t plain_size,
                  const EVP_MD *type 
                  ,unsigned char *hash
                  ,unsigned int *hash_size);

enum CryptohashErrors{
  ERROR_HASH_FAILED = -7000,
  ERROR_INITHASHINGFIELD_FAILURE = -7004,
  ERROR_SERIALIZEHASHINGFIELD_FAILURE = -7004,
  ERROR_CREATEHASHINGFIELD_FAILURE = -7005,
  ERROR_DUPHASHINGFIELD_FAILURE = -7006,
  ERROR_HASHINGFIELD_GETTEXT_FAILURE = -7007,
  ERROR_HASHBYTEBUFF_FAILED = -7008,
  ERROR_HASHINGFIELD_GETSALT_FAILURE = -7009

};

#endif /* ifndef ENRYPTION_H */
