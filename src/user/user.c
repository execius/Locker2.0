#include "user.h"

typedef struct user_s {
  ByteBuff_t *username;
  ByteBuff_t *user_db_path;

  HashingField_t *hashed_pass;
  HashingField_t *key;
  /*used for lookup*/
  ByteBuff_t *lookup_salt;
  UserConfig_t userconf;
} user_t;

int InitUser(user_t **user
             ,ByteBuff_t *username
             ,HashingField_t *hashed_pass
             ,HashingField_t *key
             ,ByteBuff_t *lookup_salt
             ,ByteBuff_t *user_db_path
             ,UserConfig_t *userconfig)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hashed_pass,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(lookup_salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user_db_path,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;
  *user = NULL;
  MALLOC_CHECK_NULL_LOG(*user,sizeof(user_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate user");

  (*user)->lookup_salt = NULL;
  (*user)->user_db_path = NULL;
  (*user)->hashed_pass = NULL;
  (*user)->key = NULL;
  (*user)->username = NULL;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->username,username)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username bytebuffer",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->user_db_path,user_db_path)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate user db path bytebuffer",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (DupByteBuff(&(*user)->lookup_salt, lookup_salt)),
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to duplicate lookup salt",
    rc, cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupHashingField(&(*user)->hashed_pass,hashed_pass)),
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate hashed_pass hashing field",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupHashingField(&(*user)->key,key)),
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate key hashing field",
      rc,cleanup);
  memcpy(&(*user)->userconf,userconfig,sizeof(UserConfig_t));

  return ERROR_SUCCESS;
cleanup:
  DestroyUser(*user);
  *user = NULL;
  return rc;
}




int CreateUser(user_t **user
    ,ByteBuff_t *username
    ,ByteBuff_t *password
    ,UserConfig_t *userconfig)

{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  *user = NULL;
  int rc = 0;

  HashingField_t *hashed_pass_hf = NULL,
                 *key_hf = NULL,
                 *password_hash_hf = NULL,
                 *password_key_hf = NULL;
  ByteBuff_t *lookup_salt = NULL;
  ByteBuff_t *user_db_path = NULL;
  unsigned char *lookup_salt_buf = NULL;
  MALLOC_CHECK_NULL_LOG(lookup_salt_buf,
      SALT_SIZE,
      ERROR_MEMORY_ALLOCATION,
      "error allocating memory for account lookup salt");

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (RAND_bytes(
                  lookup_salt_buf,
                  SALT_SIZE
                 )),
      LIBSSL_SUCCESS,
      ERROR_LIBSSL_FAILURE,
      "failed to generate lookup salt",
      rc,
      cleanup);



  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateHashingField(&password_hash_hf,
                    password)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to create password_hash hashing field",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateHashingField(&password_key_hf,
                    password)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to create password_key hashing field",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (pkcs5_keyed_hash_HashingField(
      password_hash_hf,
      &hashed_pass_hf,
      EVP_MD_size(hashing_options_fetchers[userconfig->hashing_option_idx]()),
      hashing_options_fetchers[userconfig->hashing_option_idx](),
      globalconf->password_hashing_iters)),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash password",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (pkcs5_keyed_hash_HashingField(
      password_key_hf,
      &key_hf,
      EVP_CIPHER_key_length(
        encryption_options_fetchers[userconfig->encryption_option_idx]()),
      hashing_options_fetchers[userconfig->key_hashing_option_idx](),
      globalconf->key_derivation_iters)),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to derive encryption key",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&user_db_path,
                    (unsigned char *)"",
                    0)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for user db path",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendByteBuff(user_db_path,
                    globalconf->master_db_dir_path)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to append byte buff while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"/")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"users")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append 'users' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"/")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendByteBuff(user_db_path,
                    username)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to append byte buff while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,".db")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '.db' while building user db path",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&lookup_salt,
                    lookup_salt_buf,
                    SALT_SIZE)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for lookup_salt",
      rc,
      cleanup);



  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (InitUser(
      user,
      username,
      hashed_pass_hf,
      key_hf,
      lookup_salt,
      user_db_path,
      userconfig)),
    ERROR_SUCCESS,
    ERROR_USER_INIT,
    "failed to initialize user",
    rc,cleanup);

  rc = ERROR_SUCCESS;
cleanup:
  if (lookup_salt) DestroyByteBuff_Secure(lookup_salt);
  if (hashed_pass_hf) DestroyHashingField(hashed_pass_hf);
  if (password_hash_hf) DestroyHashingField(password_hash_hf);
  if (password_key_hf) DestroyHashingField(password_key_hf);
  if (key_hf) DestroyHashingField(key_hf);
  if (user_db_path)DestroyByteBuff_Secure(user_db_path);
  if (lookup_salt_buf){
    OPENSSL_cleanse(lookup_salt_buf,SALT_SIZE);
    free(lookup_salt_buf);
  }
  return rc;

}
int DestroyUser(user_t *user){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  if (user->username) DestroyByteBuff_Secure(user->username);
  if (user->hashed_pass) DestroyHashingField(user->hashed_pass);
  if (user->key) DestroyHashingField(user->key);
  if (user->lookup_salt) DestroyByteBuff_Secure(user->lookup_salt);
  if (user->user_db_path) DestroyByteBuff_Secure(user->user_db_path);

  OPENSSL_cleanse(user, sizeof(user_t));
  free(user);
  return ERROR_SUCCESS;
}

int ChangeUserPass(user_t *user,ByteBuff_t *newpassword){
  return ERROR_SUCCESS;
}

int UserGetUsername(const user_t *user,ByteBuff_t **username){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(username,user->username)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username buff");
  return ERROR_SUCCESS;
}
int UserGetKey(const user_t *user,HashingField_t **key){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupHashingField(key,user->key)),
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate key hashing field");
  return ERROR_SUCCESS;
}

int UserGetHashedPass(const user_t *user,HashingField_t **hashed_pass){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(hashed_pass,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupHashingField(hashed_pass,user->hashed_pass)),
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate hashed password hashing field");

    return ERROR_SUCCESS;

}

int UserGetDbPath(const user_t *user, ByteBuff_t **user_db_path){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(user_db_path,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(user_db_path,user->user_db_path)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate user_db_path buff");
  return ERROR_SUCCESS;
}

int UserGetLookupSalt(const user_t *user, ByteBuff_t **lookup_salt){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(lookup_salt,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(lookup_salt,user->lookup_salt)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate lookup_salt   buff");
  return ERROR_SUCCESS;
}
int UserGetUserConf(const user_t *user,UserConfig_t **userconf){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(userconf,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  MALLOC_CHECK_NULL_LOG(*userconf,
      sizeof(UserConfig_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate a copy user config struct");

  memcpy(*userconf,
      &user->userconf,
      sizeof(UserConfig_t));
  return ERROR_SUCCESS;
}


int UserAuth(const user_t *user,const ByteBuff_t *password)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  int rc = 0 ;
  const UserConfig_t *userconfig = &user->userconf;
  size_t hash_size = EVP_MD_size(
                               hashing_options_fetchers[userconfig->hashing_option_idx]());
  ByteBuff_t *hashed_pass_input = NULL,
             *hashed_pass_user = NULL,
             *salt = NULL;
  ERROR_CHECK_SUCCESS_LOG(
      (HashingFieldGetSalt(user->hashed_pass,&salt)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETSALT_FAILURE,
      "failed to get salt buff for auth ");

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (HashingFieldGetText(user->hashed_pass,&hashed_pass_user)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "failed to get hashed pass text for auth ",
      rc,cleanup);

    ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (pkcs5_keyed_hash_bytebuff( password
                             ,&hashed_pass_input
                             ,hash_size
                             ,salt
                             ,hashing_options_fetchers[userconfig->hashing_option_idx]()
                             ,globalconf->password_hashing_iters)
   ),

    ERROR_SUCCESS,
    ERROR_HASHBYTEBUFF_FAILED,
    "hasing password byte buffer failed",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CmpByteBuff_Secure(hashed_pass_user
                          ,hashed_pass_input
                          ,hash_size)
       ),
      ERROR_SUCCESS,
      ERROR_USER_AUTH,
      "auth failed",
      rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  DestroyByteBuff_Secure(hashed_pass_input);
  DestroyByteBuff_Secure(hashed_pass_user);
  DestroyByteBuff_Secure(salt);
  return rc;
}

int UserOpenDb(user_t *user,sqlite3 **userdb)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(userdb,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  int rc = 0 ;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (OpenDb(userdb,user->user_db_path)),
      ERROR_SUCCESS,
      ERROR_CANNOT_OPEN_DB,
      "cannot open user db",
      rc,cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  return rc;
}

int UserMakeDb(user_t *user)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  int rc = 0 ;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (init_user_db(user->user_db_path)
       ),
      ERROR_SUCCESS,
      ERROR_USER_MAKEDB,
      "failed to create user db",
      rc,cleanup);
  rc = ERROR_SUCCESS;
cleanup:
  return rc;
}
int UserInsertDb(user_t *user)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  int rc = 0 ;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (insert_user_db( user->username
                      ,user->user_db_path)
       ),
      ERROR_SUCCESS,
      ERROR_USER_INSRTDB,
      "failed to inset user db",
      rc,cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  return rc;
}

int UserInsertConfig(user_t *user)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  int rc = 0 ;

  sqlite3 *userdb = NULL;
  ByteBuff_t *key_derivation_salt = NULL;
  ERROR_CHECK_SUCCESS_LOG(
      (HashingFieldGetSalt(user->key,&key_derivation_salt)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETSALT_FAILURE,
      "failed to get key_derivation_salt buff");

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserOpenDb(user,&userdb)),
      ERROR_SUCCESS,
      ERROR_CANNOT_OPEN_DB,
      "cannot open user db",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (insert_config(userdb
                      ,user->username
                      ,user->hashed_pass
                      ,user->lookup_salt
                      ,&user->userconf 
                      ,key_derivation_salt)
       ),
      ERROR_SUCCESS,
      ERROR_USER_INSRTCONF,
      "failed to inset user configs",
      rc,cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  CloseDb(userdb);
  if (key_derivation_salt)DestroyByteBuff_Secure(key_derivation_salt);
  return rc;
}


int UserDbSetUp(user_t *user)
{

  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");

  int rc = 0;
  sqlite3 *userdb = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserMakeDb(user)
       ),
      ERROR_SUCCESS,
      ERROR_USER_MAKEDB,
      "failed to create user db",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserInsertDb(user)
       ),
      ERROR_SUCCESS,
      ERROR_USER_INSRTDB,
      "failed to inset user db",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserInsertConfig(user)
       ),
      ERROR_SUCCESS,
      ERROR_USER_INSRTCONF,
      "failed to inset user configs",
      rc,cleanup);
  rc = ERROR_SUCCESS;
cleanup :
  if(userdb) CloseDb(userdb);
  return rc;
}

int UserLoadFromDb(user_t **user,ByteBuff_t *username,ByteBuff_t *password)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  int rc = 0;
  ByteBuff_t *lookup_salt = NULL,
             *key_derivation_salt = NULL,
             *user_db_path = NULL;
  HashingField_t *hashed_pass = NULL,
                 *key_hf = NULL,
                 *password_key_hf = NULL;
  UserConfig_t *userconfig = NULL;


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&user_db_path,
                    (unsigned char *)"",
                    0)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for user db path",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendByteBuff(user_db_path,
                    globalconf->master_db_dir_path)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to append byte buff while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"/")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"users")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append 'users' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"/")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendByteBuff(user_db_path,
                    username)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to append byte buff while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,".db")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '.db' while building user db path",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (fetch_config(username
                  ,&lookup_salt
                  ,&hashed_pass
                  ,&userconfig
                  ,&key_derivation_salt)
       ),
      ERROR_SUCCESS,
      ERROR_SQL_FETCHCONFIG_FAILURE,
      "failed to fetch user config",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitHashingField(&password_key_hf,
                    password,
                    key_derivation_salt)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to create password_key hashing field",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (pkcs5_keyed_hash_HashingField(
      password_key_hf,
      &key_hf,
      EVP_CIPHER_key_length(
        encryption_options_fetchers[userconfig->encryption_option_idx]()),
      hashing_options_fetchers[userconfig->key_hashing_option_idx](),
      globalconf->key_derivation_iters)),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to derive encryption key",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (InitUser(
      user,
      username,
      hashed_pass,
      key_hf,
      lookup_salt,
      user_db_path,
      userconfig)),
    ERROR_SUCCESS,
    ERROR_USER_INIT,
    "failed to initialize user",
    rc,cleanup);
  rc = ERROR_SUCCESS;
cleanup :
  if (password_key_hf) DestroyHashingField(password_key_hf);
  if (key_hf) DestroyHashingField(key_hf);
  if (hashed_pass) DestroyHashingField(hashed_pass);
  if (user_db_path)DestroyByteBuff_Secure(user_db_path);
  if (lookup_salt)DestroyByteBuff_Secure(lookup_salt);
  if (key_derivation_salt)DestroyByteBuff_Secure(key_derivation_salt);
  if (userconfig) free(userconfig);
  return rc;
}
