#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <fcntl.h>
#include <utmp.h>
#include <sys/stat.h>

#define MAX_BUFFER_SIZE 100

int main()
{
    mknod("srv-cli.fifo", S_IFIFO | 0666, 0);
    mknod("cli-srv.fifo", S_IFIFO | 0666, 0);

    char command_buffer[MAX_BUFFER_SIZE];

    int no_sent_bytes;
    do
    {
        int srv_cli_fd = open("srv-cli.fifo", O_RDONLY);
        int cli_srv_fd = open("cli-srv.fifo", O_WRONLY);
        fgets(command_buffer, sizeof(command_buffer), stdin);
        no_sent_bytes = write(cli_srv_fd, command_buffer, strlen(command_buffer));

        char rcv_msg[MAX_BUFFER_SIZE];
        rcv_msg[0] = '\0';
        int rcv_len = read(srv_cli_fd, rcv_msg, sizeof(rcv_msg));
        rcv_msg[rcv_len] = '\0';
        printf("%s\n", rcv_msg);

        if(strncmp("You've been disconnected", rcv_msg, 24) == 0)
        {
            return 0;
        }

        close(srv_cli_fd);
        close(cli_srv_fd);

    } while (1);

    exit(EXIT_SUCCESS);
}