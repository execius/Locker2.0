#ifndef SQLTINTR
#define SQLTINTR
#include "includes.h"
#include "globalconfig.h"
#include "bytebuffer.h" 
#include "user.h"

int OpenDb(sqlite3 **db,const ByteBuff_t *path);
int CloseDb(sqlite3 *db);
int open_master_db(void);
int init_master_db(void);
int init_user_db(ByteBuff_t *user_db_filepath);
enum SqliteInterErrors{
  ERROR_CANNOT_OPEN_DB = -4000,
  ERROR_SQLITE_FAILURE = -4001,
  ERROR_FETCHACCOUNT_FAILURE = -4002,
  ERROR_SQL_FETCHUSERDB_FAILURE = -4003,
  ERROR_SQL_FETCHCONFIG_FAILURE = -4004
};

int insert_config(sqlite3 *userdb
    ,const ByteBuff_t *username
    ,const HashingField_t *hashed_pass
    ,const ByteBuff_t *lookup_salt
    ,const UserConfig_t *userconfig
    ,const ByteBuff_t *key_derivation_salt);
int insert_user_db( const ByteBuff_t *username,
    const ByteBuff_t *user_db_filepath_str);

int insert_account(sqlite3 *userdb,
    EncryptionField_t *username_cipher,
    EncryptionField_t *email_cipher,
    EncryptionField_t *password_cipher,
    EncryptionField_t *platform_cipher,
    EncryptionField_t *note_cipher,
    HashingField_t *username_hash,
    HashingField_t *platform_hash,
    HashingField_t *email_hash);

int fetch_account(sqlite3 *userdb,
    uint64_t id,
    EncryptionField_t **username_cipher,
    EncryptionField_t **email_cipher,
    EncryptionField_t **password_cipher,
    EncryptionField_t **platform_cipher,
    EncryptionField_t **note_cipher,
    HashingField_t **username_hash,
    HashingField_t **platform_hash,
    HashingField_t **email_hash,
    uint64_t *acc_id);

int fetch_config(ByteBuff_t *username,
    ByteBuff_t **lookup_salt,
    HashingField_t **hashed_pass,
    UserConfig_t **userconfig,
    ByteBuff_t **key_derivation_salt);

#endif /* ifndef MACRO */
