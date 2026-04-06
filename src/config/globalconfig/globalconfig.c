#include "globalconfig.h"


GlobalConf_t *globalconf = NULL;

int InitGlobal(ByteBuff_t *cecretroot){


  ERROR_CHECK_NULL_LOG(cecretroot,ERROR_NULL_VALUE_GIVEN,"could not fetch $HOME");

  struct rlimit rl = {0, 0};
  setrlimit(RLIMIT_CORE, &rl);

  ERROR_CHECK_SUCCESS_LOG(
      (mlockall(MCL_CURRENT | MCL_FUTURE)),
      0,//success return
      ERROR_STDLIB_FAILURE,
      "failed to mlock memory , stoped not to risk leaks");

  ERROR_CHECK_SUCCESS_LOG(
      (AccessPathByteBuff( cecretroot)),
      ERROR_SUCCESS,
      ERROR_BYTEBUFF_ACCESSPATH_FAILURE,
      "failed to access cecret root path");


  MALLOC_CHECK_NULL_LOG(globalconf,
      sizeof(GlobalConf_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate global config struct");

  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(&globalconf->master_db_dir_path,
                   cecretroot)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to initalize master db dir path");

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
  

  globalconf->version = CECRET_VERSION;
  globalconf->key_derivation_iters = CECRET_KDF_ITR;
  globalconf->password_hashing_iters = CECRET_PASSWORD_HASH_IT;
  globalconf->lookup_hash_iters = CECRET_LOOKUP_HASH_IT;
  return ERROR_SUCCESS;

}

int DestroyGlobal(void){
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

