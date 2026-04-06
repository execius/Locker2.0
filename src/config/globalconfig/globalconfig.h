#ifndef GLOBALCONF_H
#define GLOBALCONF_H

#include "includes.h" 
#include "encryption.h" 
#include "hashing.h" 
#include "bytebuffer.h" 
typedef struct GlobalConf_s {

  uint16_t version;
  
  /*for easy and configurable access*/
  ByteBuff_t *master_db_dir_path;
  ByteBuff_t *backup_dir_path;

  sqlite3 *master;
  uint32_t key_derivation_iters;  
  uint32_t lookup_hash_iters;  
  uint32_t password_hashing_iters;
}GlobalConf_t ;
extern GlobalConf_t *globalconf;

int InitGlobal(ByteBuff_t *cecretroot);
int DestroyGlobal(void);

#endif /* ifdef GLOBALCONF_H */
