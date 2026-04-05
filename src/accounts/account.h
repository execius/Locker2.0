#ifndef ACCOUNTS_H
#define ACCOUNTS_H
#include "includes.h" 


typedef struct EncryptedAccount_s EncryptedAccount_t;
typedef struct Account_s Account_t;

#include "encryption.h"
#include "hashing.h"
#include "bytebuffer.h" 
#include "user.h" 

int DestroyAccount(Account_t *account);

int CreateAccount(Account_t **account
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note
    ,user_t *user);

int AccountGetUsername(const Account_t *account,ByteBuff_t **username);
int AccountGetPassword(const Account_t *account,ByteBuff_t **password);
int AccountGetEmail(const Account_t *account,ByteBuff_t **email);
int AccountGetPlatform(const Account_t *account,ByteBuff_t **platform);
int AccountGetNote(const Account_t *account,ByteBuff_t **note);


int DestroyEncryptedAccount(EncryptedAccount_t *account);

int EncryptedAccountGetUsernameHash(const EncryptedAccount_t *eac,
    ByteBuff_t **username_hash);
int EncryptedAccountGetPlatformHash(const EncryptedAccount_t *eac,
    ByteBuff_t **platform_hash);
int EncryptedAccountGetEmailHash(const EncryptedAccount_t *eac,
    ByteBuff_t **email_hash);


int EncryptAccount(Account_t *account
    ,EncryptedAccount_t **eac
    ,user_t *user);

int DecryptAccount(EncryptedAccount_t *eac
    ,Account_t **account
    ,user_t *user);
enum AccErrors
{ 
  ERROR_ACCOUNT_INNIT_FAILURE = -9000,
  ERROR_ENCACCOUNT_INNIT_FAILURE = -9001,
  ERROR_ENCACCOUNT_FAILURE = -9002,
  ERROR_FETCHENCACC_FAILURE = -9003,
  ERROR_DECACCOUNT_FAILURE = -9004
};

#endif /* ifndef ACCOUNTS_H */
