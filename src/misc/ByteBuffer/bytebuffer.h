
#ifndef BYTEBUFF
#define BYTEBUFF

typedef struct ByteBuff_s  ByteBuff_t ;

#include "includes.h"

int bytebuffsize(void) ;

/*note : these buffer are NOT null terminated , they designed to 
 * be used inherently with the lenght member in mind , do NOT use them as strings*/
int InitByteBuff(ByteBuff_t **bytebuff,const unsigned char *buff,size_t len);
int DestroyByteBuff_Secure(ByteBuff_t *bytebuff);
int DestroyByteBuff_NoWipe(ByteBuff_t *bytebuff);
int DupByteBuff(ByteBuff_t **dst,const ByteBuff_t *src);

int GetBuffByteBuff(const ByteBuff_t *bytebuff,unsigned char **buff);

/*@buff : should be passed to free ,
 * better yet to OPENSSL_cleanse if 
 * it is sensitive
 * */
int GetLenByteBuff(const ByteBuff_t *bytebuff,size_t *len);

int AppendByteBuff(ByteBuff_t *appendee,ByteBuff_t *appended);

int AppendBytesByteBuff(ByteBuff_t *appendee,const char *appended,size_t len);

#define AppendStrByteBuff(buf, lit) \
    AppendBytesByteBuff(buf, lit, sizeof(lit) - 1)

int GetBuffByteBuff_NullTerminated(const ByteBuff_t *bytebuff,unsigned char **buff);

int SerializeByteBuff(const ByteBuff_t *bytebuff,unsigned char **out,size_t *outlen);
int DeserializeByteBuff(ByteBuff_t **bytebuff,
    const unsigned char *in,
    size_t in_size);

enum ByteBuffErrors {
  ERROR_BUFFDUP_FAILURE = -6000,
  ERROR_BUFFINIT_FAILURE = -6001,
  ERROR_GETBUFF_FAILURE = -6002,
  ERROR_GETLEN_FAILURE = -6003,
  ERROR_CORRUPTED_BYTEBUFF = -6004,
  ERROR_APPENDBUFF_OVERFLOW = -6005,
  ERROR_APPENDBUFF_FAILED = -6006,
  ERROR_APPENDBYTES_FAILED = -6006,
  ERROR_APPENDSTRBUFF_FAILED = -6007,
  ERROR_GETBUFF_NL_FAILURE = -6008,
  ERROR_LEN_VAR_INVALID = -6009,
  ERROR_SERIALIZED_DATA_CORRUPTION = -6010,
  ERROR_SERIALIZATION_FAILURE = -6011,
  ERROR_DESERIALIZATION_FAILURE = -6012
};

int printbb(ByteBuff_t *bb);
#endif
