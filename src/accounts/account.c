#include "includes.h"

typedef struct account_s {
  char username[STRMAX];
  char email[STRMAX];
  char platform[STRMAX];
  char note[STRMAX];
}account_t ;

typedef struct EnjcyptedJson_s {
  char cipher[STRMAX];
  size_t cipherlenght;
} EncryptedJson_t;
