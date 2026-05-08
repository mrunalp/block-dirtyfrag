#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/netlink.h>

#define NETLINK_XFRM 6

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("uid=%d pid=%d\n", getuid(), getpid());

    pid_t pid = fork();
    if (pid < 0) { printf("fork: %s\n", strerror(errno)); return 1; }
    if (pid == 0) {
        printf("Step 1: unshare(NEWUSER|NEWNET)\n");
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
            printf("  FAILED: %s (errno=%d)\n", strerror(errno), errno);
            _exit(1);
        }
        printf("  OK — userns level > 0\n\n");

        printf("Step 2: socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM)\n");
        int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
        if (s < 0) {
            printf("  BLOCKED: %s (errno=%d)\n", strerror(errno), errno);
            printf("  Layer 2b is working!\n");
            _exit(0);
        }
        close(s);
        printf("  ALLOWED — Layer 2b NOT blocking!\n");
        _exit(2);
    }
    int status;
    waitpid(pid, &status, 0);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    printf("Child exit code: %d\n", rc);
    return rc;
}
