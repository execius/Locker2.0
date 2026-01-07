#include "includes.h"
/*
 * since we need something to start , the user loader and saver 
 * will assume the path to the user file is :
 * [users folder from the globalconfig struct]/[username]
 * */


typedef struct user_s {
  char username[STRMAX];
  char hashed_pass[STRMAX];
  char user_vault[STRMAX];
  char user_backup_vault[STRMAX];
  UserConfig_t userconf;
} user_t;



int InitUser(user_t *user,const char *username,const char *password,UserConfig_t userconfig){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG((strlen(username) >= STRMAX),
                          1,
                          LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
                          "username lenght is larger than string lenght limit");
  
  ERROR_CHECK_SUCCESS_LOG((strlen(password) >= STRMAX),
                          1,
                          LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
                          "password lenght is larger than string lenght limit");
  ERROR_CHECK_SUCCESS_LOG((snprintf(user->username, STRMAX, "%s",username) > 0),
                          1,
                          ERROR_STDLIB_FAILURE,
                          "failed to copy username into its field in the user struct");
  //TODO : hash then strore the password , the hashing algo is in the globalconfig
  // ERROR_CHECK_SUCCESS_LOG((snprintf(user->password, STRMAX, "%s",password) > 0),
  //                         1,
  //                         ERROR_STDLIB_FAILURE,
  //                         "failed to copy password into its field in the user struct");
  ERROR_CHECK_SUCCESS_LOG((snprintf(user->user_vault,
                                    STRMAX,
                                    "%s/%s",
                                    globalconf->vaults_dir,
                                    password) > 0),
                          1,
                          ERROR_STDLIB_FAILURE,
                          "failed to construct user vault path in its field inside user struct");
  memcpy(&user->userconf,&userconfig,sizeof(UserConfig_t));
  return ERROR_SUCCESS;
}
int LoadUser(user_t *user,const char *username){
  return ERROR_SUCCESS;
};
int SaveUser(user_t *user){
  return ERROR_SUCCESS;
}
int ChangeUserPass(user_t *user){
  return ERROR_SUCCESS;
}
