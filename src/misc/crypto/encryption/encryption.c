#include "encryption.h" 

typedef struct EncryptionField_s {
  ByteBuff_t *text;
  ByteBuff_t *iv;
  ByteBuff_t *tag; //for AEAD
} EncryptionField_t ;


int InitEncryptionField(EncryptionField_t **ef,
    const ByteBuff_t *text,
    const ByteBuff_t *iv,
    const ByteBuff_t *tag) {
  ERROR_CHECK_NULL_LOG(text,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(ef,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  int rc = 0;

  MALLOC_CHECK_NULL_LOG(*ef,sizeof(EncryptionField_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate encryption field");
  (*ef)->text = NULL;
  (*ef)->iv = NULL;
  (*ef)->tag = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*ef)->text,text)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate text bytebuffer",
      rc,cleanup);
 
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*ef)->iv,iv)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate iv bytebuffer",
      rc,cleanup);

  if (tag){
    ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
        (DupByteBuff(&(*ef)->tag,tag)), ERROR_SUCCESS,
        ERROR_BUFFDUP_FAILURE,
        "failed to duplicate tag bytebuffer",
        rc,cleanup);
  }
  return ERROR_SUCCESS;
cleanup:
  DestroyEncryptionField(*ef);
  *ef = NULL;
  return rc;
}



int CreateEncryptionField(
    const EVP_CIPHER *type,
    EncryptionField_t **ef,
    const ByteBuff_t *text) {
  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(ef,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(text,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ByteBuff_t *iv_buf = NULL ;
  unsigned char *iv = NULL;
  int rc = 0 , iv_len = 0;

  MALLOC_CHECK_NULL_LOG(*ef,sizeof(EncryptionField_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate encryption field");
  (*ef)->text = NULL;
  (*ef)->iv = NULL;
  (*ef)->tag = NULL;




  iv_len= EVP_CIPHER_get_iv_length(type);

  MALLOC_CHECK_NULL_LOG(iv,
      iv_len,
      ERROR_MEMORY_ALLOCATION,
      "error allocating memory for account IV");

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (RAND_bytes(
                  iv,
                  iv_len
                 )),
      LIBSSL_SUCCESS,
      ERROR_LIBSSL_FAILURE,
      "failed to generate iv",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&iv_buf,
                    iv,
                    (size_t)iv_len)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for iv",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitEncryptionField(
                           ef
                           ,text
                           ,iv_buf
                           ,NULL)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize encryption field",
      rc,
      cleanup);
  return ERROR_SUCCESS;
cleanup:
  if (iv){
    OPENSSL_cleanse(iv,iv_len);
    free(iv);
  }
  if (iv_buf){
    DestroyByteBuff_Secure(iv_buf);
  }
  return rc;
}

int DupEncryptionField(EncryptionField_t **dst,
    const EncryptionField_t *src) {
  ERROR_CHECK_NULL_LOG(src,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(dst,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  int rc = 0;

  MALLOC_CHECK_NULL_LOG(*dst,sizeof(EncryptionField_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate encryption field");
  (*dst)->text = NULL;
  (*dst)->iv = NULL;
  (*dst)->tag = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*dst)->text,src->text)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate text bytebuffer",
      rc,cleanup);
 
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*dst)->iv,src->iv)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate iv bytebuffer",
      rc,cleanup);

  
  if (src->tag){
    ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
        (DupByteBuff(&(*dst)->tag,src->tag)), ERROR_SUCCESS,
        ERROR_BUFFDUP_FAILURE,
        "failed to duplicate tag bytebuffer",
        rc,cleanup);
  }

  return ERROR_SUCCESS;
cleanup:
  DestroyEncryptionField(*dst);
  *dst = NULL;
  return rc;
}


int DestroyEncryptionField(EncryptionField_t *ef){
  ERROR_CHECK_NULL_LOG(ef,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  if (ef->text) DestroyByteBuff_Secure(ef->text);
  if (ef->iv) DestroyByteBuff_Secure(ef->iv);
  if (ef->tag) DestroyByteBuff_Secure(ef->tag);

  OPENSSL_cleanse(ef, sizeof(EncryptionField_t));
  free(ef);
  return ERROR_SUCCESS;
}

int EncryptionFieldGetText(const EncryptionField_t *ef,ByteBuff_t **text){
  ERROR_CHECK_NULL_LOG(ef,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(text,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(text,ef->text)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate text buff");
  return ERROR_SUCCESS;
}

int EncryptionFieldGetIv(const EncryptionField_t *ef,ByteBuff_t **iv){
  ERROR_CHECK_NULL_LOG(ef,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(iv,ef->iv)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate iv buff");
  return ERROR_SUCCESS;
}

int EncryptionFieldGetTag(const EncryptionField_t *ef,ByteBuff_t **tag){
  ERROR_CHECK_NULL_LOG(ef,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(tag,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(ef->tag,ERROR_NULL_VALUE_GIVEN,"tag is NULL");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(tag,ef->tag)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate tag buff");
  return ERROR_SUCCESS;
}


int SerializeEncryptionField(const EncryptionField_t *ef
    ,ByteBuff_t **out)
{
  ERROR_CHECK_NULL_LOG(ef,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(out,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  *out = NULL;

  int rc = 0;
  unsigned char *text_serialized = NULL,
                *iv_serialized = NULL,
                *tag_serialized = NULL;
  size_t text_serialized_length = 0,
         iv_serialized_length = 0,
         tag_serialized_length = 0;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(ef->iv,&iv_serialized,&iv_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize iv",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(ef->tag,&tag_serialized,&tag_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize tag",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(ef->text,&text_serialized,&text_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize text",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(out,
                    text_serialized,
                    text_serialized_length)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for hash filed serialization",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendBytesByteBuff(*out,
                           (const char *)iv_serialized,
                           iv_serialized_length)),
      ERROR_SUCCESS,
      ERROR_APPENDBYTES_FAILED,
      "failed to appends iv  to  byte buffer for hash filed serialization",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendBytesByteBuff(*out,
                           (const char *)tag_serialized,
                           tag_serialized_length)),
      ERROR_SUCCESS,
      ERROR_APPENDBYTES_FAILED,
      "failed to appends tag  to  byte buffer for hash filed serialization",
      rc,cleanup);
  rc = ERROR_SUCCESS;
cleanup:
  if (text_serialized) 
  {
    OPENSSL_cleanse(text_serialized,text_serialized_length);
    free(text_serialized);
  }
  if (iv_serialized) 
  {
    OPENSSL_cleanse(iv_serialized,iv_serialized_length);
    free(iv_serialized);
  }
  if (tag_serialized) {
    OPENSSL_cleanse(tag_serialized,tag_serialized_length);
    free(tag_serialized);
  }
  if (rc != ERROR_SUCCESS){
    if(*out){
      DestroyByteBuff_Secure(*out);
    }
  }
  return rc;
}
int DeserializeEncryptionField(EncryptionField_t **ef,
    const ByteBuff_t *in)
{
  ERROR_CHECK_NULL_LOG(ef,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(in,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  *ef = NULL;

  int rc = 0;
   ByteBuff_t *text = NULL,
              *iv = NULL,
              *tag = NULL;
   unsigned char *buff = NULL;
   size_t len = 0,
          iv_offset =0,
          tag_offset =0;
   
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      ( GetLenByteBuff(in , &len)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "fialed to get len to deserialize",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (
       GetBuffByteBuff(in, &buff)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get buf to deserialize ",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&text,buff,len)),
      ERROR_SUCCESS,
      ERROR_DESERIALIZATION_FAILURE,
      "failed to deserialize text",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      ( GetLenByteBuff(text , &iv_offset)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "fialed to get len for iv ofset",
      rc,cleanup);
  iv_offset += sizeof(uint64_t);
  if (iv_offset > len) {
    rc = ERROR_SERIALIZED_DATA_CORRUPTION;
    goto cleanup;
}
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&iv,buff+iv_offset,len - iv_offset)),
      ERROR_SUCCESS,
      ERROR_DESERIALIZATION_FAILURE,
      "failed to deserialize iv",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      ( GetLenByteBuff(iv , &tag_offset)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "fialed to get len for tag ofset",
      rc,cleanup);
  tag_offset += sizeof(uint64_t);
  if (tag_offset > SIZE_MAX - iv_offset) {
    rc = ERROR_SERIALIZED_DATA_CORRUPTION;
    goto cleanup;
  }
tag_offset += iv_offset;
  if (tag_offset > len) {
    rc = ERROR_SERIALIZED_DATA_CORRUPTION;
    goto cleanup;
}
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&tag,buff+tag_offset,len - tag_offset)),
      ERROR_SUCCESS,
      ERROR_DESERIALIZATION_FAILURE,
      "failed to deserialize tag",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitEncryptionField(ef,
                    text,
                    iv,
                    tag)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize hash filed deserialization",
      rc,cleanup);
  rc = ERROR_SUCCESS;
cleanup:
  if (text) 
  {
    DestroyByteBuff_Secure(text);
  }
  if (tag) 
  {
    DestroyByteBuff_Secure(tag);
  }
  if (iv) 
  {
    DestroyByteBuff_Secure(iv);
  }
    if (buff) 
  {
    OPENSSL_cleanse(buff,len);
    free(buff);
  }
 
  return rc;
}



cipher_func_t encryption_options_fetchers[] = {
[AES_256_GCM] = EVP_aes_256_gcm,
[AES_192_GCM] = EVP_aes_192_gcm,
[AES_128_GCM] = EVP_aes_128_gcm,
[CHACHA20_POLY1305]    = EVP_chacha20_poly1305,
};





int encrypt(const EVP_CIPHER *type,
            const unsigned char*key,
            const unsigned char *iv,
            const unsigned char *plain,
            int plain_size,
            unsigned char *cipher,
            int *cipher_size,
            unsigned char *tag
            ){
  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher_size,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ERROR_CHECK_NULL_LOG(ctx,ERROR_NULL_VALUE_GIVEN,"cannot get context");

  int block_size = EVP_CIPHER_block_size(type);
  int cipher_size_tmp = 0;
  int cipher_max = 0;
  int rc = 0;
  *cipher_size = 0;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (EVP_EncryptInit_ex(ctx,
                      type,
                      NULL,
                      key,
                      iv)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "encrypt init failed",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (EVP_EncryptUpdate(ctx,
                     cipher,
                     &cipher_size_tmp,
                     plain,
                     plain_size)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "encrypt update failed",
    rc,cleanup);
  *cipher_size += cipher_size_tmp;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (EVP_EncryptFinal_ex(ctx,
                     cipher+*cipher_size,
                     &cipher_size_tmp)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "encrypt final failed",
    rc,cleanup);
  *cipher_size += cipher_size_tmp;


  cipher_max = plain_size +block_size;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (*cipher_size > cipher_max),
    0,
    ERROR_BUF_OVERFLOW,
    "cipher buffer overflowed",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (EVP_CIPHER_CTX_ctrl(ctx, 
                       EVP_CTRL_AEAD_GET_TAG,
                       TAG_SIZE,
                       tag)
   ),
    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "tag retrieval failed",
    rc,cleanup);


  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  EVP_CIPHER_CTX_free(ctx);
  return rc;

}


// EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
//                              const char *properties);
//
// int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
// int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
//                       int *outl, const unsigned char *in, int inl);
// int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
//
int EncryptByteBuff(
            const EVP_CIPHER *type,
            const ByteBuff_t *plain,
            const ByteBuff_t *key,
            const ByteBuff_t *iv,
            ByteBuff_t **cipher,
            ByteBuff_t **tag)
{
  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(tag,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  unsigned char *key_str = NULL;
  unsigned char *iv_str = NULL;
  unsigned char *plain_str = NULL;
  unsigned char *cipher_str = NULL;
  unsigned char *tag_str = NULL;
  int plain_size = 0;
  int cipher_size = 0;
  size_t key_size = 0;
  size_t iv_size = 0;
  int cipher_max = 0;
  int rc = 0;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetLenByteBuff(key
                       ,&key_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get key len from byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetLenByteBuff(iv
                       ,&iv_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get iv len from byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (!(key_size == EVP_CIPHER_key_length(type))),
      0,
      ERROR_INVALID_KEYLEN,
      "key lenght is inconsistent with cipher type",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (!(iv_size == EVP_CIPHER_get_iv_length(type))),
      0,
      ERROR_INVALID_IVLEN,
      "iv lenght is inconsistent with cipher type",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetLenByteBuff(plain
                       ,(size_t *)&plain_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get plain len from byte buff",
      rc,cleanup);

  cipher_max = plain_size +EVP_CIPHER_get_block_size(type);
  MALLOC_CHECK_NULL_LOG(cipher_str,
      cipher_max,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for cipher str");

  MALLOC_CHECK_NULL_LOG(tag_str,
      TAG_SIZE,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for tag str");

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff(key
                       ,(unsigned char **)&key_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get key  str from byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff(iv
                       ,(unsigned char **)&iv_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get iv  str from byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff(plain
                       ,(unsigned char **)&plain_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get plain  str from byte buff",
      rc,cleanup);



  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (encrypt(type
               ,key_str
               ,iv_str
               ,plain_str
               ,plain_size
               ,cipher_str
               ,&cipher_size
               ,tag_str
      )),
      ERROR_SUCCESS,
      ERROR_ENCRYPTION_FAILURE,
      "failed to encrypt",
      rc,cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(cipher
                    ,cipher_str
                    ,(size_t)cipher_size)
      ),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to get init encrypted cipher byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(tag
                    ,tag_str
                    ,TAG_SIZE)
      ),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to get init tag byte buff",
      rc,cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (cipher_str) {
    OPENSSL_cleanse(cipher_str,cipher_size);
    free(cipher_str);
  }
  if (tag_str) {
    OPENSSL_cleanse(tag_str,TAG_SIZE);
    free(tag_str);
  }
  if (plain_str) {
    OPENSSL_cleanse(plain_str,plain_size);
    free(plain_str);
  }
  if (iv_str) {
    OPENSSL_cleanse(iv_str,iv_size);
    free(iv_str);
  }
  return rc;
}


int EncryptEncryptionField(
    const EVP_CIPHER *type,
    const EncryptionField_t *plain,
    const ByteBuff_t *key,
    EncryptionField_t **cipher)
{
  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ByteBuff_t *cipher_buf = NULL;
  int rc = 0;
  ByteBuff_t *tag = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptByteBuff(type
                       ,plain->text
                       ,key
                       ,plain->iv
                       ,&cipher_buf
                       ,&tag)
      ),
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to encrypt byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitEncryptionField(
                           cipher
                           ,cipher_buf
                           ,plain->iv
                           ,tag)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize encryption field",
      rc,
      cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (cipher_buf) {
    DestroyByteBuff_Secure(cipher_buf);
  }
  if (tag) {
    DestroyByteBuff_Secure(tag);
  }
  return rc;
}




/*decryption stuff*/

//
// int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
// int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
//                       int *outl, const unsigned char *in, int inl);
// int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
//
//
int decrypt(const EVP_CIPHER *type,
            const unsigned char*key,
            const unsigned char *iv,
            const unsigned char *cipher,
            int cipher_size,
            unsigned char *plain,
            int *plain_size,
            unsigned char *tag)
{
  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain_size,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(tag,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ERROR_CHECK_NULL_LOG(ctx,ERROR_NULL_VALUE_GIVEN,"cannot get context");

  int plain_size_tmp = 0;
  int plain_max = 0;
  int rc = 0;
  *plain_size = 0;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (EVP_DecryptInit_ex(ctx,
                      type,
                      NULL,
                      key,
                      iv)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "decrypt init failed",
    rc,cleanup);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (EVP_DecryptUpdate(ctx,
                     plain,
                     &plain_size_tmp,
                     cipher,
                     cipher_size)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "decrypt update failed",
    rc,cleanup);
  *plain_size += plain_size_tmp;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (EVP_DecryptFinal_ex(ctx,
                     plain+*plain_size,
                     &plain_size_tmp)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "decrypt final failed",
    rc,cleanup);
  *plain_size += plain_size_tmp;


  plain_max = cipher_size ;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (*plain_size > plain_max),
    0,
    ERROR_BUF_OVERFLOW,
    "plain buffer overflowed",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  EVP_CIPHER_CTX_free(ctx);
  return rc;

}




int DecryptByteBuff(
            const EVP_CIPHER *type,
            const ByteBuff_t *cipher,
            const ByteBuff_t *key,
            const ByteBuff_t *iv,
            ByteBuff_t **plain,
            const ByteBuff_t *tag)
{
  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(tag,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  unsigned char *key_str = NULL;
  unsigned char *iv_str = NULL;
  unsigned char *plain_str = NULL;
  unsigned char *cipher_str = NULL;
  unsigned char *tag_str = NULL;
  int plain_size = 0;
  int cipher_size = 0;
  int plain_max = 0;
  int rc = 0;

  int iv_size = 0;
  int key_size = 0;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetLenByteBuff(key
                       ,(size_t *)&key_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get key len from byte buff",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetLenByteBuff(iv
                       ,(size_t *)&iv_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get iv len from byte buff",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (!(key_size == EVP_CIPHER_key_length(type))),
      0,
      ERROR_INVALID_KEYLEN,
      "key lenght is inconsistent with cipher type",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (!(iv_size == EVP_CIPHER_get_iv_length(type))),
      0,
      ERROR_INVALID_IVLEN,
      "iv lenght is inconsistent with cipher type",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetLenByteBuff(cipher
                       ,(size_t *)&cipher_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get plain len from byte buff",
      rc,cleanup);

  plain_max = cipher_size;
  MALLOC_CHECK_NULL_LOG(plain_str,
      plain_max,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for plain str");


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff(tag
                       ,(unsigned char **)&tag_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get tag  str from byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff(key
                       ,(unsigned char **)&key_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get key  str from byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff(iv
                       ,(unsigned char **)&iv_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get iv  str from byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff(cipher
                       ,(unsigned char **)&cipher_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get plain  str from byte buff",
      rc,cleanup);



  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (decrypt(type
               ,key_str
               ,iv_str
               ,cipher_str
               ,cipher_size
               ,plain_str
               ,&plain_size
               ,tag_str
      )),
      ERROR_SUCCESS,
      ERROR_DECRYPTION_FAILURE,
      "failed to decrypt",
      rc,cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(plain
                    ,plain_str
                    ,(size_t)plain_size)
      ),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to init byte buff for decrypted plain",
      rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (cipher_str) {
    OPENSSL_cleanse(cipher_str,cipher_size);
    free(cipher_str);
  }
  if (tag_str) {
    OPENSSL_cleanse(tag_str,TAG_SIZE);
    free(tag_str);
  }
  if (plain_str) {
    OPENSSL_cleanse(plain_str,plain_size);
    free(plain_str);
  }
  if (iv_str) {
    OPENSSL_cleanse(iv_str,iv_size);
    free(iv_str);
  }
  return rc;
}


int DecryptEncryptionField(
    const EVP_CIPHER *type,
    const EncryptionField_t *cipher,
    const ByteBuff_t *key,
    EncryptionField_t **plain)
{

  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  int rc = 0;
  ByteBuff_t *plain_buf = NULL;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptByteBuff(type
                       ,cipher->text
                       ,key
                       ,cipher->iv
                       ,&plain_buf
                       ,cipher->tag
                       )
      ),
      ERROR_SUCCESS,
      ERROR_DECRYPTBYTEBUFF_FAILURE,
      "failed to decrypt byte buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitEncryptionField(
                           plain
                           ,plain_buf
                           ,cipher->iv
                           ,NULL)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize encryption field",
      rc,
      cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (plain_buf) {
    DestroyByteBuff_Secure(plain_buf);
  }
  return rc;
}

