#ifndef USRCONF
#define USRCONF
#include "includes.h"

typedef struct UserConfig_s {
  char username[STRMAX];
  EncryptionOption_t encryption_option;
} UserConfig_t;  
#endif
