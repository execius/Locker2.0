#ifndef ACCOUNTS_H
#define ACCOUNTS_H
#include "includes.h" 


typedef struct Account_s Account_t;

#include "bytebuffer.h" 
#include "user.h" 

int DestroyAccount(Account_t *account);

/*the value returned in the second argument is caller owned 
 * and is to be passed to DestroyAccount after usage , 
 * otherwise SENSITIVE DATA WILL LEAK INTO MEMORY
 * */
int InitAccount(Account_t **account 
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note);

/*the values returned in the second arguments are caller owned
 * this is SENSITIVE information , please do not free and pass 
 * them to DestroyByteBuff_Secure for secure wiping and memory 
 * release
 * */
int AccountGetUsername(const Account_t *account,ByteBuff_t **username);
int AccountGetPassword(const Account_t *account,ByteBuff_t **password);
int AccountGetEmail(const Account_t *account,ByteBuff_t **email);
int AccountGetPlatform(const Account_t *account,ByteBuff_t **platform);
int AccountGetNote(const Account_t *account,ByteBuff_t **note);


int InsertAccount(user_t *user
    ,Account_t *acc);

int FetchAccount(user_t *user
    ,Account_t **acc 
    ,uint64_t id);
enum AccErrors
{ 
  ERROR_ACCOUNT_INIT_FAILURE = -9000,
  ERROR_ACCOUNT_DECRYPT_FAILURE = -9004,
};
#endif /* ifndef ACCOUNTS_H */
