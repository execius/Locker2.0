#ifndef GLOBAL_H
#define GLOBAL_H

#define CECRET_ROOT "tech/coding/c/Cecret/src/"//"/.config/Cecret/"
#define CECRET_VERSION 1 
#define CECRET_KDF_ITR 1000000
#define CECRET_PASSWORD_HASH_IT 10000
#define CECRET_LOOKUP_HASH_IT 10000

#define STRMAX 4098
#define SALT_SIZE 32
#define TAG_SIZE 16

_Static_assert(STRMAX >= 512, "STRMAX must be at least 512 bytes for security");
_Static_assert(CECRET_PASSWORD_HASH_IT <= CECRET_KDF_ITR , "Password hashing iterations exceed safe limit");
_Static_assert(CECRET_LOOKUP_HASH_IT <= CECRET_KDF_ITR , "Password hashing iterations exceed safe limit");
_Static_assert(SALT_SIZE >= 16, "Salt size must be at least 16 bytes");
#endif
