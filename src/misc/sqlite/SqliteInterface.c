#include "SqliteInterface.h"



int OpenDb(sqlite3 **db,const char *path){

  ERROR_CHECK_NULL_LOG(path,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_SUCCESS_LOG(
    (sqlite3_open(path,db)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    sqlite3_errmsg(*db));

  return ERROR_SUCCESS;
}

int make_master_db(void){
  char *err = NULL;
  char *master_db_filepath_str = NULL;
  ByteBuff_t *master_db_filepath = NULL;
  int rc = 0;
  sqlite3 *master;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&master_db_filepath,
                    globalconf->master_db_dir_path)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to duplicate byte buff while building master db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(master_db_filepath,"/master.db")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/master.db' while building master db path",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff_NullTerminated(master_db_filepath
                                      ,(unsigned char **)&master_db_filepath_str)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to get master db path null terminated str from byte buff",
      rc,cleanup);
  


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (OpenDb(&master,master_db_filepath_str)),
  ERROR_SUCCESS,
  ERROR_CANNOT_OPEN_DB,
  "cannot open db",
  rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_exec(master,
                  master_db_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    rc,cleanup);

  rc = ERROR_SUCCESS;
cleanup:
  if (master_db_filepath) DestroyByteBuff_Secure(master_db_filepath);
  if (master_db_filepath_str){ 
    OPENSSL_cleanse(master_db_filepath_str,strlen(master_db_filepath_str));
    free(master_db_filepath_str);
    }
  if (err) free(err);
  return rc;

}
int make_user_db(user_t *user){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  char *err = NULL  ;
  ByteBuff_t *username = NULL;
  ByteBuff_t *user_db_filepath = NULL;
  char *user_db_filepath_str = NULL;
  sqlite3 *user_db;
  int rc = 0;
  ERROR_CHECK_SUCCESS_LOG(
      (UserGetUsername(user,&username)),
      ERROR_SUCCESS,
      ERROR_USER_GET_USERNAME,
      "failed to get username from user");


  ERROR_CHECK_SUCCESS_LOG(
      (UserGetDbPath(user,&user_db_filepath)),
      ERROR_SUCCESS,
      ERROR_USER_GET_DBPATH,
      "failed to get user db filepath from user");
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff_NullTerminated(user_db_filepath
                                      ,(unsigned char **)&user_db_filepath_str)
       ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_NL_FAILURE,
      "failed to get user db path null terminated str from byte buff",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (OpenDb(&user_db,user_db_filepath_str)),
      ERROR_SUCCESS,
      ERROR_CANNOT_OPEN_DB,
      "cannot open user db",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_exec(user_db,
                  creds_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_exec(user_db,
                  configs_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    rc,cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (username) DestroyByteBuff_Secure(username);
  if (user_db_filepath) DestroyByteBuff_Secure(user_db_filepath);
  if (user_db_filepath_str) {
    OPENSSL_cleanse(user_db_filepath_str,strlen(user_db_filepath_str));
    free(user_db_filepath_str);
    }
  if (err) free(err);
  return rc;

}

int CloseDb(sqlite3 *db){

  ERROR_CHECK_NULL_LOG(db,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  sqlite3_close(db);

  return ERROR_SUCCESS;
}



int insert_user_db(sqlite3 *master,user_t *user){
  ERROR_CHECK_NULL_LOG(master,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ByteBuff_t *username = NULL,
             *user_db_filepath = NULL;
  unsigned char *username_serialized = NULL,
                *user_db_filepath_serialized = NULL;
  size_t user_db_filepath_serialized_length = 0 ,
         username_serialized_length = 0;
  int rc = 0;
  sqlite3_stmt *stmt;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_prepare_v2(master
                        ,insert_user_db_sql
                        ,-1
                        ,&stmt
                        ,NULL)
     ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "filed to preapare stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUsername(user,&username)),
      ERROR_SUCCESS,
      ERROR_USER_GET_USERNAME,
      "failed to get username from user",
     rc,cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetDbPath(user,&user_db_filepath)),
      ERROR_SUCCESS,
      ERROR_USER_GET_DBPATH,
      "failed to get user db filepath from user",
     rc,cleanup);
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(username
                         ,&username_serialized
                         ,&username_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize username",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(user_db_filepath
                         ,&user_db_filepath_serialized
                         ,&user_db_filepath_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize user_db_filepath",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       1,
                       username_serialized,
                       username_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind username to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       2,
                       user_db_filepath_serialized,
                       user_db_filepath_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind user_db_filepath to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_step(stmt)),
    SQLITE_DONE,
    ERROR_SQLITE_FAILURE,
    "failed to step stmt",
    rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_finalize(stmt)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    "failed to finalize stmt",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (username) 
    DestroyByteBuff_Secure(username);
  if (user_db_filepath) 
    DestroyByteBuff_Secure(user_db_filepath);
  if (username_serialized) {
    OPENSSL_cleanse(username_serialized
        ,username_serialized_length);
    free(username_serialized);
  }
  if (user_db_filepath_serialized) {
    OPENSSL_cleanse(user_db_filepath_serialized,
        user_db_filepath_serialized_length);
    free(user_db_filepath_serialized);
  }
  return rc;
}

int insert_config(sqlite3 *userdb
    ,const ByteBuff_t *username
    ,const HashingField_t *hashed_pass
    ,const ByteBuff_t *lookup_salt
    ,const UserConfig_t *userconfig){
  ERROR_CHECK_NULL_LOG(userdb,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hashed_pass,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(lookup_salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;
  ByteBuff_t *hashed_pass_serialized_bb = NULL;
  unsigned char *username_serialized = NULL,
                *lookup_salt_serialized = NULL,
                *hashed_pass_serialized_bb_serialized = NULL;
  size_t username_serialized_length = 0,
         lookup_salt_serialized_length = 0,
         hashed_pass_serialized_bb_serialized_length = 0;

  sqlite3_stmt *stmt;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_prepare_v2(userdb
                        ,insert_config_sql
                        ,-1
                        ,&stmt
                        ,NULL)
     ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "filed to preapare stmt",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeHashingField(hashed_pass
                         ,&hashed_pass_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEHASHINGFIELD_FAILURE,
      "failed to serialize hashed_pass",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(hashed_pass_serialized_bb
                         ,&hashed_pass_serialized_bb_serialized
                         ,&hashed_pass_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize hashedpass_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(username
                         ,&username_serialized
                         ,&username_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize username",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(lookup_salt
                         ,&lookup_salt_serialized
                         ,&lookup_salt_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize lookup_salt",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       1,
                       username_serialized,
                       username_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind username to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       2,
                       hashed_pass_serialized_bb_serialized,
                       hashed_pass_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind hashedpass_bb to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       3,
                       lookup_salt_serialized,
                       lookup_salt_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind lookup_salt to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_step(stmt)),
    SQLITE_DONE,
    ERROR_SQLITE_FAILURE,
    "failed to step stmt",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
   sqlite3_finalize(stmt);
  if (hashed_pass_serialized_bb) 
    DestroyByteBuff_Secure(hashed_pass_serialized_bb);

  if (username_serialized) {
    OPENSSL_cleanse(username_serialized
        ,username_serialized_length);
    free(username_serialized);
  }
  if (lookup_salt_serialized) {
    OPENSSL_cleanse(lookup_salt_serialized
        ,lookup_salt_serialized_length);
    free(lookup_salt_serialized);
  }
  if (hashed_pass_serialized_bb_serialized) {
    OPENSSL_cleanse(hashed_pass_serialized_bb_serialized
        ,hashed_pass_serialized_bb_serialized_length);
    free(hashed_pass_serialized_bb_serialized);
  }
  return rc;
}


int insert_account(sqlite3 *userdb,
    EncryptionField_t *username_cipher,
    EncryptionField_t *email_cipher,
    EncryptionField_t *password_cipher,
    EncryptionField_t *platform_cipher,
    EncryptionField_t *note_cipher,
    HashingField_t *username_hash,
    HashingField_t *platform_hash,
    HashingField_t *email_hash)
{
  ERROR_CHECK_NULL_LOG(userdb,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;
  ByteBuff_t *username_cipher_serialized_bb = NULL,
                *email_cipher_serialized_bb = NULL,
                *password_cipher_serialized_bb = NULL,
                *platform_cipher_serialized_bb = NULL,
                *note_cipher_serialized_bb = NULL,
                *username_hash_serialized_bb = NULL,
                *email_hash_serialized_bb = NULL,
                *platform_hash_serialized_bb = NULL;

  unsigned char *username_cipher_serialized_bb_serialized = NULL,
                *email_cipher_serialized_bb_serialized = NULL,
                *password_cipher_serialized_bb_serialized = NULL,
                *platform_cipher_serialized_bb_serialized = NULL,
                *note_cipher_serialized_bb_serialized = NULL,
                *username_hash_serialized_bb_serialized = NULL,
                *email_hash_serialized_bb_serialized = NULL,
                *platform_hash_serialized_bb_serialized = NULL;

  size_t  username_cipher_serialized_bb_serialized_length = 0,
          email_cipher_serialized_bb_serialized_length = 0,
          password_cipher_serialized_bb_serialized_length = 0,
          platform_cipher_serialized_bb_serialized_length = 0,
          note_cipher_serialized_bb_serialized_length = 0,
          username_hash_serialized_bb_serialized_length = 0,
          email_hash_serialized_bb_serialized_length = 0,
          platform_hash_serialized_bb_serialized_length = 0;

  sqlite3_stmt *stmt;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_prepare_v2(userdb
                        ,insert_config_sql
                        ,-1
                        ,&stmt
                        ,NULL)
     ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "filed to preapare stmt",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeEncryptionField(username_cipher
                         ,&username_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to serialize username_cipher",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeEncryptionField(email_cipher
                         ,&email_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to serialize email_cipher",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeEncryptionField(password_cipher
                         ,&password_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to serialize password_cipher",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeEncryptionField(platform_cipher
                         ,&platform_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to serialize platform_cipher",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeEncryptionField(note_cipher
                         ,&note_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to serialize note_cipher",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeHashingField(username_hash
                         ,&username_hash_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEHASHINGFIELD_FAILURE,
      "failed to serialize username_hash",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeHashingField(email_hash
                         ,&email_hash_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEHASHINGFIELD_FAILURE,
      "failed to serialize email_hash",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeHashingField(platform_hash
                         ,&platform_hash_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEHASHINGFIELD_FAILURE,
      "failed to serialize platform_hash",
      rc,cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(username_cipher_serialized_bb
                         ,&username_cipher_serialized_bb_serialized
                         ,&username_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize username_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(password_cipher_serialized_bb
                         ,&password_cipher_serialized_bb_serialized
                         ,&password_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize password_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(email_cipher_serialized_bb
                         ,&email_cipher_serialized_bb_serialized
                         ,&email_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize email_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(platform_cipher_serialized_bb
                         ,&platform_cipher_serialized_bb_serialized
                         ,&platform_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize platform_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(note_cipher_serialized_bb
                         ,&note_cipher_serialized_bb_serialized
                         ,&note_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize note_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(username_hash_serialized_bb
                         ,&username_hash_serialized_bb_serialized
                         ,&username_hash_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize username_hash_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(platform_hash_serialized_bb
                         ,&platform_hash_serialized_bb_serialized
                         ,&platform_hash_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize platform_hash_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(email_hash_serialized_bb
                         ,&email_hash_serialized_bb_serialized
                         ,&email_hash_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize email_hash_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       1,
                       username_cipher_serialized_bb_serialized,
                       username_cipher_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind username_cipher_serialized_bb_serialized to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       2,
                       email_cipher_serialized_bb_serialized,
                       email_cipher_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind email_cipher_serialized_bb_serialized to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       3,
                       password_cipher_serialized_bb_serialized,
                       password_cipher_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind password_cipher_serialized_bb_serialized to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       4,
                       platform_cipher_serialized_bb_serialized,
                       platform_cipher_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind platform_cipher_serialized_bb_serialized to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       5,
                       note_cipher_serialized_bb_serialized,
                       note_cipher_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind note_cipher_serialized_bb_serialized to sql stmt",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       6,
                       username_hash_serialized_bb_serialized,
                       username_hash_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind username_hash_serialized_bb_serialized to sql stmt",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       7,
                       platform_hash_serialized_bb_serialized,
                       platform_hash_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind platform_hash_serialized_bb_serialized to sql stmt",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       8,
                       email_hash_serialized_bb_serialized,
                       email_hash_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind email_hash_serialized_bb_serialized to sql stmt",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_step(stmt)),
    SQLITE_DONE,
    ERROR_SQLITE_FAILURE,
    "failed to step stmt",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
   sqlite3_finalize(stmt);
  if (username_cipher_serialized_bb) 
    DestroyByteBuff_Secure(username_cipher_serialized_bb);
  if (email_cipher_serialized_bb) 
    DestroyByteBuff_Secure(email_cipher_serialized_bb);
  if (password_cipher_serialized_bb) 
    DestroyByteBuff_Secure(password_cipher_serialized_bb);
  if (platform_cipher_serialized_bb) 
    DestroyByteBuff_Secure(platform_cipher_serialized_bb);
  if (note_cipher_serialized_bb) 
    DestroyByteBuff_Secure(note_cipher_serialized_bb);
  if (username_hash_serialized_bb) 
    DestroyByteBuff_Secure(username_hash_serialized_bb);
  if (email_hash_serialized_bb) 
    DestroyByteBuff_Secure(email_hash_serialized_bb);
  if (platform_hash_serialized_bb) 
    DestroyByteBuff_Secure(platform_hash_serialized_bb);

  if (username_hash_serialized_bb_serialized) {
    OPENSSL_cleanse(username_hash_serialized_bb_serialized
        ,username_hash_serialized_bb_serialized_length);
    free(username_hash_serialized_bb_serialized);
  }
  if (email_hash_serialized_bb_serialized) {
    OPENSSL_cleanse(email_hash_serialized_bb_serialized
        ,email_hash_serialized_bb_serialized_length);
    free(email_hash_serialized_bb_serialized);
  }
  if (platform_hash_serialized_bb_serialized) {
    OPENSSL_cleanse(platform_hash_serialized_bb_serialized
        ,platform_hash_serialized_bb_serialized_length);
    free(platform_hash_serialized_bb_serialized);
  }
  if (username_cipher_serialized_bb_serialized) {
    OPENSSL_cleanse(username_cipher_serialized_bb_serialized
        ,username_cipher_serialized_bb_serialized_length);
    free(username_cipher_serialized_bb_serialized);
  }
  if (password_cipher_serialized_bb_serialized) {
    OPENSSL_cleanse(password_cipher_serialized_bb_serialized
        ,password_cipher_serialized_bb_serialized_length);
    free(password_cipher_serialized_bb_serialized);
  }
  if (email_cipher_serialized_bb_serialized) {
    OPENSSL_cleanse(email_cipher_serialized_bb_serialized
        ,email_cipher_serialized_bb_serialized_length);
    free(email_cipher_serialized_bb_serialized);
  }
  if (platform_cipher_serialized_bb_serialized) {
    OPENSSL_cleanse(platform_cipher_serialized_bb_serialized
        ,platform_cipher_serialized_bb_serialized_length);
    free(platform_cipher_serialized_bb_serialized);
  }
  if (note_cipher_serialized_bb_serialized) {
    OPENSSL_cleanse(note_cipher_serialized_bb_serialized
        ,note_cipher_serialized_bb_serialized_length);
    free(note_cipher_serialized_bb_serialized);
  }
  return rc;
}

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
    uint64_t *acc_id)
{
  ERROR_CHECK_NULL_LOG(userdb,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;
  ByteBuff_t *username_cipher_serialized_bb = NULL,
                *email_cipher_serialized_bb = NULL,
                *password_cipher_serialized_bb = NULL,
                *platform_cipher_serialized_bb = NULL,
                *note_cipher_serialized_bb = NULL,
                *username_hash_serialized_bb = NULL,
                *email_hash_serialized_bb = NULL,
                *platform_hash_serialized_bb = NULL;

  const unsigned char *username_cipher_serialized_bb_serialized = NULL,
                *email_cipher_serialized_bb_serialized = NULL,
                *password_cipher_serialized_bb_serialized = NULL,
                *platform_cipher_serialized_bb_serialized = NULL,
                *note_cipher_serialized_bb_serialized = NULL,
                *username_hash_serialized_bb_serialized = NULL,
                *email_hash_serialized_bb_serialized = NULL,
                *platform_hash_serialized_bb_serialized = NULL;

  size_t  username_cipher_serialized_bb_serialized_length = 0,
          email_cipher_serialized_bb_serialized_length = 0,
          password_cipher_serialized_bb_serialized_length = 0,
          platform_cipher_serialized_bb_serialized_length = 0,
          note_cipher_serialized_bb_serialized_length = 0,
          username_hash_serialized_bb_serialized_length = 0,
          email_hash_serialized_bb_serialized_length = 0,
          platform_hash_serialized_bb_serialized_length = 0;

  sqlite3_stmt *stmt;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_prepare_v2(userdb
                        ,get_account_by_id_sql
                        ,-1
                        ,&stmt
                        ,NULL)
     ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "filed to preapare stmt",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_int64(stmt,
                       1,
                       id)
    ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind username_cipher_serialized_bb_serialized to sql stmt",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_step(stmt)),
    SQLITE_DONE,
    ERROR_SQLITE_FAILURE,
    "failed to step stmt",
    rc,cleanup);

  ERROR_CHECK_NULL_SET_RC_GOTO(
      (username_cipher_serialized_bb_serialized = sqlite3_column_blob(stmt, 1)),
      
      ERROR_SQLITE_FAILURE,
      "failed to get username_cipher from db",
      rc,cleanup);
      username_cipher_serialized_bb_serialized_length = sqlite3_column_bytes(stmt, 1);
  ERROR_CHECK_NULL_SET_RC_GOTO(
      (email_cipher_serialized_bb_serialized = sqlite3_column_blob(stmt, 2)),
      
      ERROR_SQLITE_FAILURE,
      "failed to get email_cipher from db",
      rc,cleanup);
      email_cipher_serialized_bb_serialized_length = sqlite3_column_bytes(stmt, 2);
  ERROR_CHECK_NULL_SET_RC_GOTO(
      (password_cipher_serialized_bb_serialized = sqlite3_column_blob(stmt, 3)),
      
      ERROR_SQLITE_FAILURE,
      "failed to get password_cipher from db",
      rc,cleanup);
      password_cipher_serialized_bb_serialized_length = sqlite3_column_bytes(stmt, 3);
  ERROR_CHECK_NULL_SET_RC_GOTO(
      (platform_cipher_serialized_bb_serialized = sqlite3_column_blob(stmt, 4)),
      
      ERROR_SQLITE_FAILURE,
      "failed to get platform_cipher from db",
      rc,cleanup);
      platform_cipher_serialized_bb_serialized_length = sqlite3_column_bytes(stmt, 4);
  ERROR_CHECK_NULL_SET_RC_GOTO(
      (note_cipher_serialized_bb_serialized = sqlite3_column_blob(stmt, 5)),
      
      ERROR_SQLITE_FAILURE,
      "failed to get note_cipher from db",
      rc,cleanup);
      note_cipher_serialized_bb_serialized_length = sqlite3_column_bytes(stmt, 5);
    ERROR_CHECK_NULL_SET_RC_GOTO(
      (username_hash_serialized_bb_serialized = sqlite3_column_blob(stmt, 6)),
      
      ERROR_SQLITE_FAILURE,
      "failed to get username_hash from db",
      rc,cleanup);
      username_hash_serialized_bb_serialized_length = sqlite3_column_bytes(stmt, 6);
    ERROR_CHECK_NULL_SET_RC_GOTO(
      (platform_hash_serialized_bb_serialized = sqlite3_column_blob(stmt, 7)),
      
      ERROR_SQLITE_FAILURE,
      "failed to get platform_hash from db",
      rc,cleanup);
      platform_hash_serialized_bb_serialized_length = sqlite3_column_bytes(stmt, 7);

    ERROR_CHECK_NULL_SET_RC_GOTO(
      (email_hash_serialized_bb_serialized = sqlite3_column_blob(stmt, 8)),
      
      ERROR_SQLITE_FAILURE,
      "failed to get email_hash from db",
      rc,cleanup);
      email_hash_serialized_bb_serialized_length = sqlite3_column_bytes(stmt, 8);


      *acc_id = sqlite3_column_int64(stmt, 9);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&username_cipher_serialized_bb
                         ,username_cipher_serialized_bb_serialized
                         ,username_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to deserialize username_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&password_cipher_serialized_bb
                         ,password_cipher_serialized_bb_serialized
                         ,password_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to deserialize password_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&email_cipher_serialized_bb
                         ,email_cipher_serialized_bb_serialized
                         ,email_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to deserialize email_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&platform_cipher_serialized_bb
                         ,platform_cipher_serialized_bb_serialized
                         ,platform_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to deserialize platform_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&note_cipher_serialized_bb
                         ,note_cipher_serialized_bb_serialized
                         ,note_cipher_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to deserialize note_cipher_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&username_hash_serialized_bb
                         ,username_hash_serialized_bb_serialized
                         ,username_hash_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to deserialize username_hash_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&platform_hash_serialized_bb
                         ,platform_hash_serialized_bb_serialized
                         ,platform_hash_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to deserialize platform_hash_serialized_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeByteBuff(&email_hash_serialized_bb
                         ,email_hash_serialized_bb_serialized
                         ,email_hash_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to deserialize email_hash_serialized_bb",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeEncryptionField(username_cipher
                         ,username_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to deserialize username_cipher",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeEncryptionField(email_cipher
                         ,email_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to deserialize email_cipher",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeEncryptionField(password_cipher
                         ,password_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to deserialize password_cipher",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeEncryptionField(platform_cipher
                         ,platform_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to deserialize platform_cipher",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeEncryptionField(note_cipher
                         ,note_cipher_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEENCRYPTIONFIELD_FAILURE,
      "failed to deserialize note_cipher",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeHashingField(username_hash
                         ,username_hash_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEHASHINGFIELD_FAILURE,
      "failed to deserialize username_hash",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeHashingField(email_hash
                         ,email_hash_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEHASHINGFIELD_FAILURE,
      "failed to deserialize email_hash",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DeserializeHashingField(platform_hash
                         ,platform_hash_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEHASHINGFIELD_FAILURE,
      "failed to deserialize platform_hash",
      rc,cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
   sqlite3_finalize(stmt);
  if (username_cipher_serialized_bb) 
    DestroyByteBuff_Secure(username_cipher_serialized_bb);
  if (email_cipher_serialized_bb) 
    DestroyByteBuff_Secure(email_cipher_serialized_bb);
  if (password_cipher_serialized_bb) 
    DestroyByteBuff_Secure(password_cipher_serialized_bb);
  if (platform_cipher_serialized_bb) 
    DestroyByteBuff_Secure(platform_cipher_serialized_bb);
  if (note_cipher_serialized_bb) 
    DestroyByteBuff_Secure(note_cipher_serialized_bb);
  if (username_hash_serialized_bb) 
    DestroyByteBuff_Secure(username_hash_serialized_bb);
  if (email_hash_serialized_bb) 
    DestroyByteBuff_Secure(email_hash_serialized_bb);
  if (platform_hash_serialized_bb) 
    DestroyByteBuff_Secure(platform_hash_serialized_bb);

  return rc;
}
