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

#define MAX_BUFFER_SIZE 1000

int main()
{
    //####### Creating fifos ######
    if (access("srv-cli.fifo", F_OK) == -1)
    {
        mknod("srv-cli.fifo", S_IFIFO | 0666, 0);
    }
    if (access("cli-srv.fifo", F_OK) == -1)
    {
        mknod("cli-srv.fifo", S_IFIFO | 0666, 0);
    }
    //#############################################

    char command_buffer[MAX_BUFFER_SIZE];

    int no_sent_bytes;
    do
    {
        int srv_cli_fd = open("srv-cli.fifo", O_RDONLY);
        int cli_srv_fd = open("cli-srv.fifo", O_WRONLY);
        fgets(command_buffer, sizeof(command_buffer), stdin);
        if(strlen(command_buffer) > 1) 
        {
            no_sent_bytes = write(cli_srv_fd, command_buffer, strlen(command_buffer));
            sleep(0.2);
            char rcv_msg[MAX_BUFFER_SIZE];
            rcv_msg[0] = '\0';
            int rcv_len = read(srv_cli_fd, rcv_msg, sizeof(rcv_msg));
            if (rcv_len < 0)
            {
                printf("Error reading message from server! (%d)\n", errno);
                printf("%s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            rcv_msg[rcv_len] = '\0';
            printf("%s\n", rcv_msg);

            if(strncmp("You've been disconnected", rcv_msg, 24) == 0) //Break client at disconnect (quit command)
            {
                return 0;
            }
        }

    } while (1);

    exit(EXIT_SUCCESS);
}