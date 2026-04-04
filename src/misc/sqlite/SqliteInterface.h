#ifndef SQLTINTR
#define SQLTINTR
#include "includes.h"
#include "globalconfig.h"
#include "bytebuffer.h" 
#include "user.h"

int OpenDb(sqlite3 **db,const char *path);
int CloseDb(sqlite3 *db);
int make_master_db(void);
int make_user_db(user_t *user);
enum SqliteInterErrors{
  ERROR_CANNOT_OPEN_DB = -4000,
  ERROR_SQLITE_FAILURE = -4001,
};

int insert_config(sqlite3 *userdb
    ,const ByteBuff_t *username
    ,const HashingField_t *hashed_pass
    ,const ByteBuff_t *lookup_salt
    ,const UserConfig_t *userconfig);
int insert_account(sqlite3 *userdb,
    EncryptionField_t *username_cipher,
    EncryptionField_t *email_cipher,
    EncryptionField_t *password_cipher,
    EncryptionField_t *platform_cipher,
    EncryptionField_t *note_cipher,
    HashingField_t *username_hash,
    HashingField_t *platform_hash,
    HashingField_t *email_hash);


  const char *master_db_template =
    "\
CREATE TABLE master (\
id INTEGER PRIMARY KEY,\
username TEXT NOT NULL UNIQUE,\
db_path TEXT NOT NULL UNIQUE);";

  const char *creds_template =
    "\
CREATE TABLE credentials (\
id INTEGER PRIMARY KEY,\
username_cipher BLOB NOT NULL ,\
email_cipher BLOB NOT NULL ,\
password_cipher BLOB NOT NULL ,\
platform_cipher BLOB NOT NULL ,\
note_cipher BLOB NOT NULL,\
username_hash BLOB NOT NULL ,\
platform_hash BLOB NOT NULL ,\
email_hash BLOB NOT NULL);\
CREATE INDEX idx_username_hash ON credentials(username_hash);\
CREATE INDEX idx_email_hash ON credentials(email_hash);\
CREATE INDEX idx_platform_hash ON credentials(platform_hash)";


  const char *configs_template =
    "\
CREATE TABLE configs (\
id INTEGER PRIMARY KEY CHECK (id = 1),\
username TEXT NOT NULL ,\
hashed_pass BLOB NOT NULL ,\
lookup_salt BLOB NOT NULL ,\
userconfig BLOB NOT NULL );WITHOUT ROWID";

const char *insert_user_db_sql = "\
INSERT INTO master (username, db_path)\
VALUES (?, ?);";

const char *insert_acccount_sql = "\
INSERT INTO credentials (\
    username_cipher,\
    email_cipher,\
    password_cipher,\
    platform_cipher,\
    note_cipher,\
    username_hash,\
    platform_hash,\
    email_hash\
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
const char *insert_config_sql = "\
INSERT INTO configs (\
    username,\
    hashed_pass,\
    lookup_salt,\
    userconfig\
) VALUES (?, ?, ?, ?);";

const char *get_account_by_id_sql = "\
SELECT \
    username_cipher,\
    email_cipher,\
    password_cipher,\
    platform_cipher,\
    note_cipher,\
    username_hash,\
    platform_hash,\
    email_hash,\
    id\
FROM credentials \
WHERE id = ?;";
#endif /* ifndef MACRO */
