#ifndef USER_H
#define USER_H

typedef struct user_s user_t;

#include "includes.h" 
#include "globalconfig.h"
#include "usersconfig.h"
#include "bytebuffer.h" 
#include "encryption.h"
#include "SqliteInterface.h"


/*the value returned in the second argument is caller owned 
 * and is to be passed to DestroyUser after usage , 
 * otherwise SENSITIVE DATA WILL LEAK INTO MEMORY
 * */
int CreateUser(user_t **user
    ,ByteBuff_t *username
    ,ByteBuff_t *password
    ,UserConfig_t *userconfig);
int DestroyUser(user_t *user);

int ChangeUserPass(user_t *usre,ByteBuff_t *newpassword);


/*the value given by any of the following functions
 * in the second argument should be passed to :
 *   - DestroyByteBuff_Secure : for ByteBuff_t type  
 *   - DestroyHashingField : for HashingField_t type
 * if not the data (which is slightly sensitive) , WILL leak
 *
 * pass userconf to free , it has no sensitive data 
 * */
int UserGetUsername(const user_t *user,ByteBuff_t **username);
int UserGetKey(const user_t *user,HashingField_t **key);
int UserGetLookupSalt(const user_t *user,ByteBuff_t **lookup_salt);
int UserGetHashedPass(const user_t *user,HashingField_t **hashed_pass);
int UserGetDbPath(const user_t *user, ByteBuff_t **user_db_path);
int UserGetUserConf(const user_t *user,UserConfig_t **userconf);
int UserInsertDb(user_t *user);
int UserInsertConfig(user_t *user);
int UserDbSetUp(user_t *user );
int UserLoadFromDb(user_t **user
    ,ByteBuff_t *username
    ,ByteBuff_t *password);
int UserOpenDb(user_t *user,sqlite3 **userdb);

enum  UserErrors
{ 
  ERROR_USER_INIT = - 3000,
  ERROR_USER_GET_USERNAME = -3001,
  ERROR_USER_GETUSERCONF_FAILURE = -3002,
  ERROR_USER_GET_DBPATH = -3003,
  ERROR_USER_GET_KEY = -3004,
  ERROR_USER_GET_LOOKUPSALT = -3005,
  ERROR_USER_GET_HASHED_PASS = -3006,
  ERROR_USER_OPENDDB = -3007,
  ERROR_USER_INSRTDB = -3008,
  ERROR_USER_INSRTCONF = -3009,
  ERROR_USER_MAKEDB = -3010

};

#endif
