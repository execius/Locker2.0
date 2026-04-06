
#include "main.h" 
//demo , don't code like this 
// helper to make a ByteBuff from string
ByteBuff_t *make_bb(const char *s)
{
    ByteBuff_t *bb = NULL;
    InitByteBuff(&bb, (unsigned char *)s,(size_t) strlen(s));
    return bb;
}

int main(void)
{
    int rc = 0;

    Error_InitGlobalCtx();
    Error_SetLogON();
    Error_SetLogFile("./log");
    ByteBuff_t *cecretroot = make_bb("/tmp/");
    rc = InitGlobal(cecretroot);
    if (rc != ERROR_SUCCESS) {
        printf(" InitGlobalConf failed\n");
        return -1;
    }
    user_t *user = NULL;

    // --- create user fields ---
    ByteBuff_t *username = make_bb("tstuser");
    ByteBuff_t *password = make_bb("password123");
    ByteBuff_t *password_fake = make_bb("password123");

    ByteBuff_t *email    = make_bb("test@mail.com");
    ByteBuff_t *platform = make_bb("github");
    ByteBuff_t *note     = make_bb("my note");

    UserConfig_t userconf = {.encryption_option_idx = AES_256_GCM,
      .hashing_option_idx =SHA_512 ,
      .key_hashing_option_idx = SHA_512,
      .lookup_hashing_option_idx = SHA_512
    };


    // ERROR_CHECK_SUCCESS_LOG(
    //   (init_master_db()
    //   ),
    //   ERROR_SUCCESS,
    //   ERROR_APPENDSTRBUFF_FAILED,
    //   "failed to initialize master db");
    // ERROR_CHECK_SUCCESS_LOG(
    //   (open_master_db()
    //   ),
    //   ERROR_SUCCESS,
    //   ERROR_APPENDSTRBUFF_FAILED,
    //   "failed to open master db");
    // // --- init user ---
    // rc = CreateUser(&user,
    //               username,
    //               password,
    //               &userconf);
    // if (rc != ERROR_SUCCESS) {
    //     printf("InitUser failed\n");
    //     return -1;
    // }
    //
    // // --- setup user db ---
    // rc = UserDbSetUp(user);
    // if (rc != ERROR_SUCCESS) {
    //     printf("UserDbSetUp failed\n");
    //     return -1;
    // }
    //
    //

    ERROR_CHECK_SUCCESS_LOG(
      (open_master_db()
      ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to open master db");

    rc = UserLoadFromDb(&user,username,password);
    if (rc != ERROR_SUCCESS) {
        printf("failed to load user\n");
        return -1;
    }

    rc = UserAuth(user,password_fake);
    if (rc != ERROR_SUCCESS) {
        printf("failed to auth user\n");
        return -1;
    }
    Account_t *acc = NULL;
    rc = InitAccount(&acc ,username ,password ,email ,platform ,note);
    if (rc != ERROR_SUCCESS) {
        printf("failed to init account\n");
        return -1;
    }
    rc = InsertAccount(user , acc );

    if (rc != ERROR_SUCCESS) {
        printf("failed to insert account\n");
        return -1;
    }


    uint64_t id = 1;// sqlite3_last_insert_rowid(userdb);

    // --- fetch account ---
    rc = FetchAccount(user, &acc, id);

    if (rc != ERROR_SUCCESS) {
        printf("FetchAccount failed\n");
        return -1;
    }


    printacc(acc);

    DestroyGlobal();
      // --- cleanup ---
      DestroyAccount(acc);
    DestroyUser(user);

    return 0;
}
