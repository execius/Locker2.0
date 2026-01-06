#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "includes.h"

typedef struct EncryptionOption_s {
  const EVP_CIPHER *(*EncryptionScheme)(void);
  size_t key_size;
  size_t iv_size;
} EncryptionOption_t ;
#endif
