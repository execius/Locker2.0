#include "globalconfig.h"


GlobalConf_t *globalconf = NULL;

int InitGlobalConf(void){

  char *home = getenv("HOME");
  ERROR_CHECK_NULL_LOG(home,ERROR_NULL_VALUE_GIVEN,"could not fetch $HOME");


  MALLOC_CHECK_NULL_LOG(globalconf,
      sizeof(GlobalConf_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate global config struct");


  ERROR_CHECK_SUCCESS_LOG(
      (InitByteBuff(&globalconf->master_db_dir_path,
                    (unsigned char *)home,
                    strlen(home)
                   )),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer master db dir path");

  ERROR_CHECK_SUCCESS_LOG(
      (AppendStrByteBuff(globalconf->master_db_dir_path,"/")
      ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/' while building master db dir path");

    ERROR_CHECK_SUCCESS_LOG(
      (AppendStrByteBuff(globalconf->master_db_dir_path,
                    CECRET_ROOT
                   )),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to construct byte buffer master db dir path");


  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(&globalconf->backup_dir_path,
                   globalconf->master_db_dir_path)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate master db dir path buff");

  ERROR_CHECK_SUCCESS_LOG(
      (AppendStrByteBuff(globalconf->backup_dir_path,"/backup/")
      ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/backup' while building backup db dir path");
    ERROR_CHECK_SUCCESS_LOG(
      (open_master_db()
      ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/backup' while building backup db dir path");

  globalconf->version = CECRET_VERSION;
  globalconf->key_derivation_iters = CECRET_KDF_ITR;
  globalconf->password_hashing_iters = CECRET_PASSWORD_HASH_IT;
  globalconf->lookup_hash_iters = CECRET_LOOKUP_HASH_IT;
  return ERROR_SUCCESS;

}

int DestroyGlobalConf(void){
  ERROR_CHECK_NULL_LOG(globalconf,ERROR_NULL_VALUE_GIVEN,"NULL parameter");

  CloseDb(globalconf->master);
  if (globalconf->master_db_dir_path) 
    DestroyByteBuff_Secure(globalconf->master_db_dir_path);
  if (globalconf->backup_dir_path) 
    DestroyByteBuff_Secure(globalconf->backup_dir_path);
  OPENSSL_cleanse(globalconf, sizeof(GlobalConf_t));
  free(globalconf);
  return ERROR_SUCCESS;
}

