#ifndef ERROR_HANDLER_H
#define ERROR_HANDLER_H
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#define FUNCTION_NAME_MAX 256
#define FILE_NAME_MAX 4098
#define ERROR_DESCRIPTION_MAX 4098
#define LOG_ON 1
#define LOG_OFF 0

/*
 * Thread-safety notes:
 *
 * - Each thread has its own error context.
 * - Each thread must call Error_InitGlobalCtx() before use.
 * - Each thread must call Error_CleanupGlobalCtx() before exit.
 *
 * - Logging to the same file path from multiple threads is allowed,
 *   but log output may interleave and ordering is unspecified.
 *
 * - For serialized logs, users must provide their own synchronization
 *   or use distinct log files per thread.
 */


/*opaque typing*/
typedef struct ErrorConfig_s ErrorConfig_t;
typedef struct ErrorStruct_s ErrorStruct_t;

/*always check if function calls return ERROR_SUCCESS
 * all error codes and what they signify are in this h 
 * file here :*/

enum ERROR_ErrorCodes {
  LIBSSL_SUCCESS = 1,
  ERROR_SUCCESS = 0,
  ERROR_MEMORY_ALLOCATION = -2,
  ERROR_NULL_VALUE_GIVEN = -6,
  ERROR_GLOBALCTX_NULL=-200,
  ERROR_GLOBALCTX_DOUBLEINIT= -204,
  ERROR_INVALID_ERROR =-201,
  ERROR_LOGERROR=-202,
  ERROR_ERRORSTRUCT_INIT = -203,
  LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX= -300,
  ERROR_STDLIB_FAILURE = -301,
  ERROR_LIBSSL_FAILURE = -302,
  ERROR_BUF_OVERFLOW = -306,
  ERROR_LIBSTR_FAILURE = -309,
  ERROR_LEN_VAR_LARGER_THAN_STRMAX = -310
};


/*expects a non null [errstct] ideally you'd 
 * declare a ErrorStruct_t* and reference it */

/*any errstct passes to this must be destroyed with 
 * Error_DestroyErrorStruct , or else you'll have a 
 * memory leak*/

/*all fields are necessary, no optional NULLs
 * since this library is meant to provide a chained 
 * error log , all info are needed*/
int Error_InitErrorStruct(ErrorStruct_t **errstct,
                          int errorcode,
                          size_t line_number,
                          const char *function_name,
                          const char *file_name,
                          const char *error_description);


/*simply destroys the structs initlialized with 
 * Error_InitErrorStruct*/
int Error_DestroyErrorStruct(ErrorStruct_t *errstct);


/*inilializes a global context to be maniputaled and 
 * then destroyed with other api funcs*/
int Error_InitGlobalCtx(void);

/*destroys the global context*/
int Error_CleanupGlobalCtx(void);

/*these three do exactly what their names say*/
int Error_SetLogFile(const char *log_file_path);
int Error_SetLogON(void);
int Error_SetLogOff(void);


int Error_LogError(const ErrorStruct_t *error_stct);



/*to avoid logging code repetition in the following code*/
static inline void Error_LogHelper(int errcode, const char *desc,
    size_t line, const char *func, const char *file)
{
  ErrorStruct_t *errstct;
  if (Error_InitErrorStruct(&errstct,
        errcode,
        line,
        func,
        file,
        desc) == ERROR_SUCCESS) 
  {
    Error_LogError(errstct);
    Error_DestroyErrorStruct(errstct);
  }
}

/*checks if the expression  is successfull , if not it returns an error code */
#define ERROR_CHECK_SUCCESS_RET(exp,successcode,errcode) \
do {\
  if((successcode) != (exp)){\
    return errcode;\
  }\
} while (0)


/*like ERROR_CHECK_SUCCESS_RET but logs*/
#define ERROR_CHECK_SUCCESS_LOG(exp,successcode,errcode,desc) \
do {\
  if((successcode) != (exp)){\
    Error_LogHelper(errcode, desc, __LINE__, __func__, __FILE__);\
    return errcode;\
  }\
} while (0)

/*checks if the expression  is successfull , if not it does goto label;*/
#define ERROR_CHECK_SUCCESS_GOTO(exp,successcode,label) \
do {\
  if((successcode) != (exp)){\
    goto label;\
  }\
} while (0)
/*like ERROR_CHECK_SUCCESS_GOTO but logs*/
#define ERROR_CHECK_SUCCESS_GOTO_LOG(exp,successcode,errcode,desc,label) \
do {\
  if((successcode) != (exp)){\
    Error_LogHelper(errcode, desc, __LINE__, __func__, __FILE__);\
    goto label;\
  }\
} while (0)
/*checks if the expression  is successfull , if not it :
 * sets rc to errorcode
 * does goto label;*/
#define ERROR_CHECK_SUCCESS_SET_RC_GOTO(exp,successcode,errcode,rc,label) \
do {\
  if((successcode) != (exp)){\
    (rc) = (errcode);\
    goto label;\
  }\
} while (0)
/*like ERROR_CHECK_SUCCESS_SET_RC_GOTO but logs*/
#define ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(exp,successcode,errcode,desc,rc,label) \
do {\
  if((successcode) != (exp)){\
    Error_LogHelper(errcode, desc, __LINE__, __func__, __FILE__);\
    (rc) = (errcode);\
    goto label;\
  }\
} while (0)

/*checks for null pointers and return errcode if yes*/
#define ERROR_CHECK_NULL_RET(ptr,errcode) \
do {\
  if(NULL == (ptr)){\
    return errcode;\
  }\
} while (0)

/*like ERROR_CHECK_NULL_RET but logs*/
#define ERROR_CHECK_NULL_LOG(ptr,errcode,desc) \
do {\
  if(NULL == (ptr)){\
    Error_LogHelper(errcode, desc, __LINE__, __func__, __FILE__);\
    return errcode;\
  }\
} while (0)

#define ERROR_CHECK_NULL_SET_RC_GOTO(ptr,errcode,desc,rc,label) \
do {\
  if(NULL == (ptr)){\
    Error_LogHelper(errcode, desc, __LINE__, __func__, __FILE__);\
    (rc) = (errcode);\
    goto label;\
  }\
} while (0)
/*mallocs the requested size into ptr and checks if 
 * the allocation is successfull*/
#define MALLOC_CHECK_NULL_RET(ptr,size,MemAllocError) \
do {\
  (ptr) = malloc(size);\
  if(NULL == (ptr)){\
    return MemAllocError;\
  }\
} while (0)

/*like MALLOC_CHECK_NULL_RET but logs*/
#define MALLOC_CHECK_NULL_LOG(ptr,size,MemAllocError,desc) \
do {\
  (ptr) = malloc(size);\
  if(NULL == (ptr)){\
    Error_LogHelper(MemAllocError, desc, __LINE__, __func__, __FILE__);\
    return MemAllocError;\
  }\
} while (0)

#define MALLOC_CHECK_NULL_SET_RC_GOTO(ptr,size,MemAllocError,desc,rc,label) \
do {\
  (ptr) = malloc(size);\
  if(NULL == (ptr)){\
    Error_LogHelper(MemAllocError, desc, __LINE__, __func__, __FILE__);\
    (rc) = (MemAllocError);\
    goto label;\
  }\
} while (0)
#endif 
