
#include "bytebuffer.h" 

typedef struct ByteBuff_s {
  unsigned char *buff;
  size_t len;
} ByteBuff_t ;

int InitByteBuff(ByteBuff_t **bytebuff,const unsigned char *buff,size_t len){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;
  ERROR_CHECK_SUCCESS_LOG(
      (len < 0 || len >  SIZE_MAX),
      0,
      ERROR_LEN_VAR_INVALID,
      "lenght is invalid");

  MALLOC_CHECK_NULL_LOG(*bytebuff,
      sizeof(ByteBuff_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate bytebuff");

  MALLOC_CHECK_NULL_SET_RC_GOTO((*bytebuff)->buff,
      len,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate bytebuff buffer",
      rc,
      cleanup);

  memcpy((*bytebuff)->buff,buff,len);
  (*bytebuff)->len = len;
  return ERROR_SUCCESS;
cleanup :
  if (*bytebuff) {
    if ((*bytebuff)->buff) {
      OPENSSL_cleanse((*bytebuff)->buff,(*bytebuff)->len);
      free((*bytebuff)->buff);
      (*bytebuff)->buff = NULL;
    } 
    OPENSSL_cleanse(*bytebuff,sizeof(ByteBuff_t));
    free(*bytebuff);
    *bytebuff = NULL;
  } 
  return rc;

}

int DestroyByteBuff_Secure(ByteBuff_t *bytebuff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(bytebuff->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  OPENSSL_cleanse(bytebuff->buff, bytebuff->len);
  OPENSSL_cleanse(bytebuff, sizeof(ByteBuff_t));
  free(bytebuff->buff);
  free(bytebuff);
  return ERROR_SUCCESS;
}

int DestroyByteBuff_NoWipe(ByteBuff_t *bytebuff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  free(bytebuff->buff);
  free(bytebuff);
  return ERROR_SUCCESS;
}

int DupByteBuff(ByteBuff_t **dst,const ByteBuff_t *src){
  ERROR_CHECK_NULL_LOG(src,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(src->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(dst,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_SUCCESS_LOG(
      (InitByteBuff(dst,src->buff,src->len)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to inittialize user");
  return ERROR_SUCCESS;
}

int CmpByteBuff(ByteBuff_t *first,const ByteBuff_t *second,size_t len){
  ERROR_CHECK_NULL_LOG(first,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(first->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(second,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(second->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
    (len == 0),
    0,
    ERROR_LEN_VAR_INVALID,
    "length must be > 0");

  ERROR_CHECK_SUCCESS_LOG(
      (len > first->len || len > second->len),
      0,
      ERROR_LEN_VAR_INVALID,
      "lenght is larger than compared buffer size");
  ERROR_CHECK_SUCCESS_LOG(
      (0 != memcmp(first->buff,second->buff,len)),
      0,
      ERROR_BYTEBUFF_CMP_UNEQUAL,
      "note equal");
  return ERROR_SUCCESS;
}
int CmpByteBuff_Secure(ByteBuff_t *first,const ByteBuff_t *second,size_t len){
  ERROR_CHECK_NULL_LOG(first,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(first->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(second,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(second->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_SUCCESS_LOG(
      (len > first->len || len > second->len),
      0,
      ERROR_LEN_VAR_INVALID,
      "lenght is larger than compared buffer size");
  ERROR_CHECK_SUCCESS_LOG(
      (0 != CRYPTO_memcmp(first->buff,second->buff,len)),
      0,
      ERROR_BYTEBUFF_CMP_UNEQUAL,
      "not equal");
  return ERROR_SUCCESS;
}
int GetBuffByteBuff(const ByteBuff_t *bytebuff,unsigned char **buff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  MALLOC_CHECK_NULL_LOG(*buff,
      bytebuff->len,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for buff copy");
  memset(*buff, 0, bytebuff->len);
  memcpy(*buff,bytebuff->buff,bytebuff->len);
  return ERROR_SUCCESS;
}

int GetBuffByteBuff_NullTerminated(const ByteBuff_t *bytebuff,unsigned char **buff){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(bytebuff->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  MALLOC_CHECK_NULL_LOG(*buff,
      bytebuff->len+1,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for buff copy");
  memset(*buff, 0, bytebuff->len);
  memcpy(*buff,bytebuff->buff,bytebuff->len);
  (*buff)[bytebuff->len] = 0;
  return ERROR_SUCCESS;
}
int GetLenByteBuff(const ByteBuff_t *bytebuff,size_t *len){
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(len,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  *len = bytebuff->len;
  return ERROR_SUCCESS;
}

int AppendByteBuff(ByteBuff_t *appendee,ByteBuff_t *appended){
  ERROR_CHECK_NULL_LOG(appendee,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appended,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appended->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appendee->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  if (appendee->len > SIZE_MAX - appended->len)
    return ERROR_APPENDBUFF_OVERFLOW;
  void *tmp = realloc(appendee->buff,appendee->len + appended->len);
  if (!tmp){
    return ERROR_MEMORY_ALLOCATION;
  }
  appendee->buff = tmp;
  memcpy(appendee->buff + appendee->len,appended->buff,appended->len);
  appendee->len += appended->len;
  return ERROR_SUCCESS;
}

int AppendBytesByteBuff(ByteBuff_t *appendee,const char *appended,size_t len){
  ERROR_CHECK_NULL_LOG(appendee,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appendee->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(appended,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  if (appendee->len > SIZE_MAX - len)
    return ERROR_APPENDBUFF_OVERFLOW;
  void *tmp = realloc(appendee->buff,appendee->len + len);
  if (!tmp){
    return ERROR_MEMORY_ALLOCATION;
  }
  appendee->buff = tmp;
  memcpy(appendee->buff + appendee->len,appended,len);
  appendee->len += len;
  return ERROR_SUCCESS;
}


int SerializeByteBuff(const ByteBuff_t *bytebuff,unsigned char **out,size_t *outlen)
{
  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(outlen,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(bytebuff->buff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(out,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  if (bytebuff->len > SIZE_MAX - sizeof(uint64_t))
    return ERROR_SERIALIZED_DATA_CORRUPTION;
  uint64_t len = bytebuff->len;

  MALLOC_CHECK_NULL_LOG(*out,
      sizeof(uint64_t)+bytebuff->len,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate buffer for seialization");
  *outlen = sizeof(uint64_t) + bytebuff->len;
  memcpy(*out,&len,sizeof(uint64_t));
  memcpy(*out+sizeof(uint64_t),bytebuff->buff,bytebuff->len);
  return ERROR_SUCCESS;
}

int DeserializeByteBuff(ByteBuff_t **bytebuff,
    const unsigned char *in,
    size_t in_size)
{

  ERROR_CHECK_NULL_LOG(bytebuff,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(in,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  uint64_t len  =0 ;
  if (in_size < sizeof(uint64_t))
    return ERROR_SERIALIZED_DATA_CORRUPTION;
  memcpy(&len,in,sizeof(uint64_t));
  if ((len > in_size - sizeof(uint64_t )) || len > SIZE_MAX)
  {
    return ERROR_SERIALIZED_DATA_CORRUPTION;
  }
  const unsigned char *buff  = in+sizeof(uint64_t);

  ERROR_CHECK_SUCCESS_LOG(
      (InitByteBuff(bytebuff,buff,(size_t)len)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to inittialize user");
  return ERROR_SUCCESS;
}


int AccessPathByteBuff(const ByteBuff_t *path)
{

  ERROR_CHECK_NULL_LOG(path,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0 ;
  char *path_null_term = NULL;

  ERROR_CHECK_SUCCESS_LOG(
      (GetBuffByteBuff_NullTerminated(path
                                      ,(unsigned char **)&path_null_term)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_NL_FAILURE,
      "failed to get  path null terminated str from byte buff");
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (access(path_null_term, F_OK)),
      ERROR_SUCCESS,
      ERROR_BYTEBUFF_ACCESSPATH_FAILURE,
      "failed to accesspath",
      rc,cleanup);
cleanup:
    if (path_null_term) {
      OPENSSL_cleanse(path_null_term,path->len);
      free(path_null_term);
    } 
  return rc;
}
//debug
int printbb(ByteBuff_t *bb)
{
  write(1,bb->buff,bb->len);
  return ERROR_SUCCESS;
}
