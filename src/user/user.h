#ifndef USER_H
#define USER_H
#include "includes.h" 

typedef struct user_s {
  char username[STRMAX];
  char hashed_pass[STRMAX];
  UserConfig_t userconf;
} user_t;
#endif
