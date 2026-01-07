#ifndef USER_H
#define USER_H
#include "includes.h" 
typedef struct user_s  user_t;
int LoadUser(user_t *user,const char *username);
int SaveUser(user_t *);
int ChangeUserPass(user_t *);
#endif
