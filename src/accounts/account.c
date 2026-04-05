#include "account.h"
#include "encryption.h"
#include "hashing.h"

enum EncryptAccountErrors
{ 
  ERROR_ENCACCOUNT_INIT_FAILURE = -9001,
  ERROR_ENCACCOUNT_ENCRYPTION_FAILURE = -9002,
  ERROR_ENCACCOUNT_FETCH_FAILURE = -9003,
  ERROR_ENCACCOUNT_INSERT_FAILURE = -9005
};
typedef struct EncryptedAccount_s {

  uint64_t id;
  EncryptionField_t *username_cipher;
  EncryptionField_t *email_cipher;
  EncryptionField_t *password_cipher;
  EncryptionField_t *platform_cipher;
  EncryptionField_t *note_cipher;

  /*these are used for lookup*/
  HashingField_t *username_hash;
  HashingField_t *platform_hash;
  HashingField_t *email_hash;


} EncryptedAccount_t;

typedef struct Account_s {
  uint64_t id;
  ByteBuff_t *username;
  ByteBuff_t *email;
  ByteBuff_t *password;
  ByteBuff_t *platform;
  ByteBuff_t *note;
}Account_t ;

int InitAccount(Account_t **account 
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0 ;
  MALLOC_CHECK_NULL_LOG(*account,sizeof(Account_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate user");
  (*account)->username = NULL;
  (*account)->email = NULL;
  (*account)->password = NULL;
  (*account)->platform = NULL;
  (*account)->note = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (DupByteBuff(&(*account)->username,username)), 
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to duplicate username bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (DupByteBuff(&(*account)->password,password)), 
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to duplicate password bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (DupByteBuff(&(*account)->email,email)), 
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to duplicate email bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (DupByteBuff(&(*account)->platform,platform)), 
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to duplicate platform bytebuffer",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (DupByteBuff(&(*account)->note,note)), 
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to duplicate note bytebuffer",
      rc,
      cleanup);


  rc = ERROR_SUCCESS;
  return rc;
cleanup:
  if (*account){
    DestroyAccount(*account);
  }
  *account = NULL;
  return rc;
}

int DestroyAccount(Account_t *account){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  if (account->username)    DestroyByteBuff_Secure(account->username);
  if (account->password)    DestroyByteBuff_Secure(account->password);
  if (account->email)       DestroyByteBuff_Secure(account->email);
  if (account->platform)    DestroyByteBuff_Secure(account->platform);
  if (account->note)        DestroyByteBuff_Secure(account->note);
  OPENSSL_cleanse(account, sizeof(Account_t));
  free(account);
  return ERROR_SUCCESS;
}


int AccountGetUsername(const Account_t *account,ByteBuff_t **username){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(username,account->username)),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get username buff");
  return ERROR_SUCCESS;
}


int AccountGetPassword(const Account_t *account,ByteBuff_t **password){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(password,account->password)),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get password buff");
  return ERROR_SUCCESS;
}

int AccountGetEmail(const Account_t *account,ByteBuff_t **email){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(email,account->email)),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get email buff");
  return ERROR_SUCCESS;
}

int AccountGetPlatform(const Account_t *account,ByteBuff_t **platform){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(platform,account->platform)),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get platform buff");
  return ERROR_SUCCESS;
}


int AccountGetNote(const Account_t *account,ByteBuff_t **note){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(note,account->note)),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get note buff");
  return ERROR_SUCCESS;
}

/*encrypted account stuff*/





int DestroyEncryptedAccount(EncryptedAccount_t *account){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  if (account->username_cipher)    DestroyEncryptionField(account->username_cipher);
  if (account->password_cipher)    DestroyEncryptionField(account->password_cipher);
  if (account->email_cipher)       DestroyEncryptionField(account->email_cipher);
  if (account->platform_cipher)    DestroyEncryptionField(account->platform_cipher);
  if (account->note_cipher)        DestroyEncryptionField(account->note_cipher);
  if (account->username_hash)    DestroyHashingField(account->username_hash);
  if (account->platform_hash)    DestroyHashingField(account->platform_hash);
  if (account->email_hash)       DestroyHashingField(account->email_hash);
  OPENSSL_cleanse(account, sizeof(EncryptedAccount_t));
  free(account);
  return ERROR_SUCCESS;
}





int InitEncryptedAccount(EncryptedAccount_t **account 
    ,const EncryptionField_t *username_cipher
    ,const EncryptionField_t *password_cipher
    ,const EncryptionField_t *email_cipher
    ,const EncryptionField_t *platform_cipher
    ,const EncryptionField_t *note_cipher
    ,const HashingField_t *username_hash
    ,const HashingField_t *platform_hash
    ,const HashingField_t *email_hash)
{

  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_NULL_LOG(username_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_NULL_LOG(username_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0 ;
  MALLOC_CHECK_NULL_LOG(*account,sizeof(EncryptedAccount_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate encrypted acc");
  (*account)->username_cipher = NULL;
  (*account)->password_cipher = NULL;
  (*account)->email_cipher = NULL;
  (*account)->platform_cipher = NULL;
  (*account)->note_cipher = NULL;

  (*account)->username_hash = NULL;
  (*account)->platform_hash = NULL;
  (*account)->email_hash = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->username_cipher,username_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate username_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->password_cipher,password_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate password_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->email_cipher,email_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate email_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->platform_cipher,platform_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate platform_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->note_cipher,note_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate note_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupHashingField(&(*account)->username_hash,username_hash)), 
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate username_hash encryption field",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupHashingField(&(*account)->platform_hash,platform_hash)), 
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate platform_hash encryption field",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupHashingField(&(*account)->email_hash,email_hash)), 
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate email_hash encryption field",
      rc,cleanup);
  rc = ERROR_SUCCESS;
  return rc;
cleanup:
  if (*account){
    DestroyEncryptedAccount(*account);
    *account = NULL;
  }
  return rc;
}



int EncryptedAccountGetUsernameHash(const EncryptedAccount_t *eac,
    ByteBuff_t **username_hash)
{
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username_hash,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (HashingFieldGetText(eac->username_hash,username_hash)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "failed to get username_hash buff");
  return ERROR_SUCCESS;
}

int EncryptedAccountGetPlatformHash(const EncryptedAccount_t *eac,
    ByteBuff_t **platform_hash)
{
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(platform_hash,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (HashingFieldGetText(eac->platform_hash,platform_hash)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "failed to get platform_hash buff");
  return ERROR_SUCCESS;
}

int EncryptedAccountGetEmailHash(const EncryptedAccount_t *eac,
    ByteBuff_t **email_hash)
{
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(email_hash,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (HashingFieldGetText(eac->email_hash,email_hash)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "failed to get email_hash buff");
  return ERROR_SUCCESS;
}





int EncryptAccount(Account_t *account
    ,EncryptedAccount_t **eac
    ,user_t *user)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");


  *eac = NULL;
  int rc = 0;
  const EVP_CIPHER *type = NULL;
  const EVP_MD *digest = NULL;
  EncryptionField_t *username_ef = NULL;
  EncryptionField_t *email_ef = NULL;
  EncryptionField_t *password_ef = NULL;
  EncryptionField_t *platform_ef = NULL;
  EncryptionField_t *note_ef = NULL;

  EncryptionField_t *username_cipher = NULL;
  EncryptionField_t *email_cipher = NULL;
  EncryptionField_t *password_cipher = NULL;
  EncryptionField_t *platform_cipher = NULL;
  EncryptionField_t *note_cipher = NULL;

  /*temporary for hashing*/
  HashingField_t *username_hf = NULL;
  HashingField_t *platform_hf = NULL;
  HashingField_t *email_hf = NULL;


  HashingField_t *username_hash = NULL;
  HashingField_t *platform_hash = NULL;
  HashingField_t *email_hash = NULL;
  UserConfig_t *userconfig = NULL  ;
  HashingField_t *key_hf = NULL  ;
  ByteBuff_t *lookup_salt = NULL  ;
  ByteBuff_t *key = NULL  ;


  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetLookupSalt(user,&lookup_salt)),
      ERROR_SUCCESS,
      ERROR_USER_GET_LOOKUPSALT,
      "error getting user lookup_salt byte buffer",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetKey(user,&key_hf)),
      ERROR_SUCCESS,
      ERROR_USER_GET_KEY,
      "error getting user key hashing field",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (HashingFieldGetText(key_hf,&key)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "error getting user key byte buffer",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUserConf(user,&userconfig)),
      ERROR_SUCCESS,
      ERROR_USER_GETUSERCONF_FAILURE,
      "error getting user config struct",
      rc,
      cleanup);
  type = encryption_options_fetchers[userconfig->encryption_option_idx]();
  digest = hashing_options_fetchers[userconfig->lookup_hashing_option_idx]();

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(type,
                              &username_ef,
                              account->username)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create username encryption field",
      rc,
      cleanup);
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(type,
                              &password_ef,
                              account->password)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create password encryption field",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(type,
                              &email_ef,
                              account->email)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create email encryption field",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(type,
                              &platform_ef,
                              account->platform)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create platform encryption field",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(type,
                              &note_ef,
                              account->note)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create note encryption field",
      rc,
      cleanup);
  

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              username_ef,
                              key,
                              &username_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt username byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              password_ef,
                              key,
                              &password_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt password byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              email_ef,
                              key,
                              &email_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt email byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              platform_ef,
                              key,
                              &platform_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt platform byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              note_ef,
                              key,
                              &note_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt note byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitHashingField(&username_hf,
                        account->username,
                        lookup_salt)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to initialize hashing field ",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitHashingField(&email_hf,
                        account->email,
                        lookup_salt)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to initialize hashing field ",
      rc,cleanup);
ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitHashingField(&platform_hf,
                    account->platform,
                    lookup_salt)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to initialize hashing field ",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_HashingField(
       username_hf,
       &username_hash,
       EVP_MD_size(digest),
       digest,
       globalconf->lookup_hash_iters)
     ),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash username for lookup",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_HashingField(
       platform_hf,
       &platform_hash,
       EVP_MD_size(digest),
       digest,
       globalconf->lookup_hash_iters)
     ),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash platform for lookup",
    rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_HashingField(
       email_hf,
       &email_hash,
       EVP_MD_size(digest),
       digest,
       globalconf->lookup_hash_iters)
     ),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash email for lookup",
    rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(

     (InitEncryptedAccount(
       eac,
       username_cipher,
       password_cipher,
       email_cipher,
       platform_cipher,
       note_cipher,
       username_hash,
       platform_hash,
       email_hash)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_INIT_FAILURE,
    "failed to initialize encrypted account",
    rc,cleanup);

  (*eac)->id = account->id;
  rc = ERROR_SUCCESS;
  goto cleanup;

cleanup:
  if (platform_cipher) DestroyEncryptionField(platform_cipher);
  if (password_cipher) DestroyEncryptionField(password_cipher);
  if (email_cipher) DestroyEncryptionField(email_cipher);
  if (username_cipher) DestroyEncryptionField(username_cipher);
  if (note_cipher) DestroyEncryptionField(note_cipher);
  if (platform_ef) DestroyEncryptionField(platform_ef);
  if (password_ef) DestroyEncryptionField(password_ef);
  if (email_ef) DestroyEncryptionField(email_ef);
  if (username_ef) DestroyEncryptionField(username_ef);
  if (note_ef) DestroyEncryptionField(note_ef);
  if (platform_hash) DestroyHashingField(platform_hash);
  if (username_hash) DestroyHashingField(username_hash);
  if (email_hash) DestroyHashingField(email_hash);
  if (platform_hf) DestroyHashingField(platform_hf);
  if (username_hf) DestroyHashingField(username_hf);
  if (email_hf) DestroyHashingField(email_hf);
  if (key_hf) DestroyHashingField(key_hf);
  if (key) DestroyByteBuff_Secure(key);
  if (lookup_salt) DestroyByteBuff_Secure(lookup_salt);
  if (userconfig) free(userconfig);
  return rc;
}


int DecryptAccount(EncryptedAccount_t *eac
    ,Account_t **account
    ,user_t *user)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  *account = NULL;


  const EVP_CIPHER *type = NULL;
  int rc = 0;
  EncryptionField_t *username = NULL;
  EncryptionField_t *email = NULL;
  EncryptionField_t *password = NULL;
  EncryptionField_t *platform = NULL;
  EncryptionField_t *note = NULL;
  UserConfig_t *userconfig = NULL  ;
  HashingField_t *key_hf = NULL  ;
  ByteBuff_t *key = NULL  ;
  ByteBuff_t *username_bb = NULL;
  ByteBuff_t *email_bb = NULL;
  ByteBuff_t *password_bb = NULL;
  ByteBuff_t *platform_bb = NULL;
  ByteBuff_t *note_bb = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetKey(user,&key_hf)),
      ERROR_SUCCESS,
      ERROR_USER_GET_KEY,
      "error getting user key hashing field",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (HashingFieldGetText(key_hf,&key)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "error getting user key byte buffer",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUserConf(user,&userconfig)),
      ERROR_SUCCESS,
      ERROR_USER_GETUSERCONF_FAILURE,
      "error getting user config struct",
      rc,
      cleanup);

  type = encryption_options_fetchers[userconfig->encryption_option_idx]();
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->username_cipher,
                       key,
                       &username)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt username enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->password_cipher,
                       key,
                       &password)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt password enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->email_cipher,
                       key,
                       &email)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt email enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->platform_cipher,
                       key,
                       &platform)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt platform enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->note_cipher,
                       key,
                       &note)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt note enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptionFieldGetText(username,
                       &username_bb)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get username bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptionFieldGetText(password,
                       &password_bb)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get password bytebuffer",
      rc,
      cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptionFieldGetText(platform,
                       &platform_bb)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get platform bytebuffer",
      rc,
      cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptionFieldGetText(email,
                       &email_bb)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get email bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptionFieldGetText(note,
                       &note_bb)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get note bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(

     (InitAccount(
       account,
       username_bb,
       password_bb,
       email_bb,
       platform_bb,
       note_bb)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_INIT_FAILURE,
    "failed to initialize encrypted account",
    rc,cleanup);

  (*account)->id = eac->id;
  rc = ERROR_SUCCESS;
  goto cleanup;

cleanup:
  if (platform) DestroyEncryptionField(platform);
  if (password) DestroyEncryptionField(password);
  if (email) DestroyEncryptionField(email);
  if (username) DestroyEncryptionField(username);
  if (note) DestroyEncryptionField(note);
  if (key) DestroyByteBuff_Secure(key);
  if (username_bb) DestroyByteBuff_Secure(username_bb);
  if (password_bb) DestroyByteBuff_Secure(password_bb);
  if (platform_bb) DestroyByteBuff_Secure(platform_bb);
  if (email_bb) DestroyByteBuff_Secure(email_bb);
  if (note_bb) DestroyByteBuff_Secure(note_bb);
  if (key_hf) DestroyHashingField(key_hf);
  if (userconfig) free(userconfig);
  return rc;
}

int InsertEncryptedAccount(user_t *user
    ,EncryptedAccount_t *eac )
{

  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  int rc = 0;
  sqlite3 *userdb = NULL;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
     (UserOpenDb(
       user,
       &userdb)
     ),
    ERROR_SUCCESS,
    ERROR_USER_OPENDDB,
    "failed to open user db",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
     (insert_account(
       userdb,
       eac->username_cipher,
       eac->email_cipher,
       eac->password_cipher,
       eac->platform_cipher,
       eac->note_cipher,
       eac->username_hash,
       eac->platform_hash,
       eac->email_hash
       )
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_INSERT_FAILURE,
    "failed to insert encrypted account",
    rc,cleanup);

cleanup:

  if (userdb)
    sqlite3_close(userdb);
  return rc;
  
}

int FetchEncryptedAccount(user_t *user
    ,EncryptedAccount_t **eac 
    ,uint64_t id)
{

  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  *eac = NULL;
  int rc = 0;

  uint64_t fetchedid;
  EncryptionField_t *username_cipher = NULL;
  EncryptionField_t *email_cipher = NULL;
  EncryptionField_t *password_cipher = NULL;
  EncryptionField_t *platform_cipher = NULL;
  EncryptionField_t *note_cipher = NULL;
  HashingField_t *username_hash = NULL;
  HashingField_t *platform_hash = NULL;
  HashingField_t *email_hash = NULL;
  sqlite3 *userdb = NULL;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
     (UserOpenDb(
       user,
       &userdb)
     ),
    ERROR_SUCCESS,
    ERROR_USER_OPENDDB,
    "failed to open user db",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
     (fetch_account(
       userdb,
       id,
       &username_cipher,
       &email_cipher,
       &password_cipher,
       &platform_cipher,
       &note_cipher,
       &username_hash,
       &platform_hash,
       &email_hash,
       &fetchedid
       )
     ),
    ERROR_SUCCESS,
    ERROR_FETCHACCOUNT_FAILURE,
    "failed to fetch account",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(

     (InitEncryptedAccount(
       eac,
       username_cipher,
       password_cipher,
       email_cipher,
       platform_cipher,
       note_cipher,
       username_hash,
       platform_hash,
       email_hash)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_INIT_FAILURE,
    "failed to initialize encrypted account",
    rc,cleanup);
  (*eac)->id = fetchedid;
cleanup:

  if (userdb)
    sqlite3_close(userdb);
  if (username_cipher)    DestroyEncryptionField(username_cipher);
  if (password_cipher)    DestroyEncryptionField(password_cipher);
  if (email_cipher)       DestroyEncryptionField(email_cipher);
  if (platform_cipher)    DestroyEncryptionField(platform_cipher);
  if (note_cipher)        DestroyEncryptionField(note_cipher);
  if (username_hash)    DestroyHashingField(username_hash);
  if (platform_hash)    DestroyHashingField(platform_hash);
  if (email_hash)       DestroyHashingField(email_hash);
  return rc;
  
}
int FetchAccount(user_t *user
    ,Account_t **acc 
    ,uint64_t id)
{

  ERROR_CHECK_NULL_LOG(acc,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  *acc = NULL;
  int rc = 0;
  EncryptedAccount_t *eac = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
     (FetchEncryptedAccount(user, &eac, id)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_FETCH_FAILURE,
    "failed to fetch encrypted account from db",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
     (DecryptAccount(eac, acc, user)
     ),
    ERROR_SUCCESS,
    ERROR_ACCOUNT_DECRYPT_FAILURE,
    "failed to decrypt account",
    rc,cleanup);

cleanup:
  if (eac)       DestroyEncryptedAccount(eac);
  return rc;
}


int InsertAccount(user_t *user
    ,Account_t *acc)
{

  ERROR_CHECK_NULL_LOG(acc,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  int rc = 0;
  EncryptedAccount_t *eac = NULL;


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
     (EncryptAccount(acc,&eac, user)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_ENCRYPTION_FAILURE,
    "failed to encrypt account",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
     (InsertEncryptedAccount(user, eac)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_INSERT_FAILURE,
    "failed to insert encrypted account to db",
    rc,cleanup);
cleanup:
  if (eac)       DestroyEncryptedAccount(eac);
  return rc;
}



