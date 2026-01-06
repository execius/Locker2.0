#include "errorhandling.h"
#include <stdio.h>
#include <string.h>

typedef struct ErrorConfig_s {
  int do_log;//0 no , 1 yes
  FILE *log_file;
}ErrorConfig_t;

typedef struct ErrorStruct_s {
  int error_code;
  size_t line_number;
  char function_name[FUNCTION_NAME_MAX];
  char file_name[FILE_NAME_MAX];
  char error_description[ERROR_DESCRIPTION_MAX];
}ErrorStruct_t;


static _Thread_local ErrorConfig_t *global_ctx = NULL;


int Error_InitGlobalCtx(void){
  if(NULL != global_ctx){
    return  ERROR_GLOBALCTX_DOUBLEINIT;
  }
  MALLOC_CHECK_NULL_RET(global_ctx, sizeof(ErrorConfig_t),ERROR_MEMORY_ALLOCATION);
  global_ctx->do_log = LOG_OFF;
  global_ctx->log_file = NULL;
  return ERROR_SUCCESS;
} 
int Error_CleanupGlobalCtx(void){
  ERROR_CHECK_NULL_RET(global_ctx, ERROR_NULL_VALUE_GIVEN);
  global_ctx->do_log = LOG_OFF;
  if(global_ctx->log_file)
    fclose(global_ctx->log_file);
  global_ctx->log_file = NULL;
  free(global_ctx);
  global_ctx = NULL;
  return ERROR_SUCCESS;
} 

int Error_InitErrorStruct(ErrorStruct_t **errstct,
                          int errorcode,
                          size_t line_number,
                          const char *function_name,
                          const char *file_name,
                          const char *error_description){

  int retval;
  ERROR_CHECK_NULL_RET(errstct,ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(function_name,ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(file_name,ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(error_description, ERROR_NULL_VALUE_GIVEN);
  MALLOC_CHECK_NULL_RET(*errstct,
                        sizeof(ErrorStruct_t),
                        ERROR_MEMORY_ALLOCATION);
  (*errstct)->line_number = line_number;
  (*errstct)->error_code = errorcode;
  retval  = snprintf((*errstct)->function_name, 
                     FUNCTION_NAME_MAX,
                     "%s",
                     function_name);
  if (retval < 0 || retval >= FUNCTION_NAME_MAX){
    retval = ERROR_ERRORSTRUCT_INIT;
    goto clean_exit;
  }
  retval  = snprintf((*errstct)->file_name,
                     FILE_NAME_MAX,
                     "%s",
                     file_name);

  if (retval < 0 || retval >= FILE_NAME_MAX){
    retval = ERROR_ERRORSTRUCT_INIT;
    goto clean_exit;
  }

  retval  = snprintf((*errstct)->error_description,
                     ERROR_DESCRIPTION_MAX,
                     "%s",
                     error_description);
  if (retval < 0 || retval >= ERROR_DESCRIPTION_MAX){
    retval = ERROR_ERRORSTRUCT_INIT;
    goto clean_exit;
  }
  
  return ERROR_SUCCESS;

clean_exit:
  free(*errstct);
  return retval;

}

int Error_DestroyErrorStruct(ErrorStruct_t *errstct){
  ERROR_CHECK_NULL_RET(errstct,ERROR_NULL_VALUE_GIVEN);
  free(errstct);
  return ERROR_SUCCESS;
}

int Error_SetLogFile(const char *log_file_path){
  ERROR_CHECK_NULL_RET(global_ctx, ERROR_GLOBALCTX_NULL);
  ERROR_CHECK_NULL_RET(log_file_path, ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET((global_ctx->log_file = fopen(log_file_path,"a")),
                       ERROR_NULL_VALUE_GIVEN);
  return ERROR_SUCCESS;
}
int Error_SetLogON(void){
  ERROR_CHECK_NULL_RET(global_ctx, ERROR_GLOBALCTX_NULL);
  global_ctx->do_log = LOG_ON;
  return ERROR_SUCCESS;
}
int Error_SetLogOff(void){
  ERROR_CHECK_NULL_RET(global_ctx, ERROR_GLOBALCTX_NULL);
  global_ctx->do_log = LOG_OFF;
  return ERROR_SUCCESS;
}

int Error_LogError(const ErrorStruct_t *error_stct){
  int retval;
  ERROR_CHECK_NULL_RET(global_ctx, ERROR_NULL_VALUE_GIVEN);
  ERROR_CHECK_NULL_RET(global_ctx->log_file,ERROR_NULL_VALUE_GIVEN);
  if(LOG_OFF == global_ctx->do_log){
    return ERROR_SUCCESS;
  }

  retval = fprintf(global_ctx->log_file,"FUNCTION [%s] :\n\t\
  [IN FILE]     : %s\n\t\
  [AT LINE]     : %zu\n\t\
  [ERROR CODE]  : %d\n\t\
  [DESCRIPTION] : %s\n",
                   error_stct->function_name,
                   error_stct->file_name,
                   error_stct->line_number,
                   error_stct->error_code,
                   error_stct->error_description);
  if(0 > retval){
    return ERROR_LOGERROR;
  }
  fflush(global_ctx->log_file);
  return ERROR_SUCCESS;
}
