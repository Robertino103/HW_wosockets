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
#include <sys/stat.h>
#include <utmp.h>

#define READ 0
#define WRITE 1
#define MAX_BUFFER_SIZE 100

bool check_message(char buf[MAX_BUFFER_SIZE], int len)
{
    if (strncmp("login : ", buf, 8) == 0) return true;
    if (strncmp("get-logged-users", buf, len-1) == 0) return true;
    if (strncmp("get-proc-info : ", buf, 16) == 0) return true;
    if (strncmp("logout", buf, len-1) == 0) return true;
    if (strncmp("quit", buf, len-1) == 0) return true;
    return false;
}

bool is_logged = false;

char* exec_login(char *user)
{   
    int found = 0;
    FILE *login_fd;
    char *line = NULL;
    size_t len_line = 0;
    ssize_t read;
    login_fd = fopen("users.cfg", "r");
    
    if (login_fd == NULL)
    {
        printf("No config file found ! (%d)", errno);
        exit(EXIT_FAILURE);
    }
    while ((read = getline(&line, &len_line, login_fd)) != -1)
    {
        if(strncmp(user, line, strlen(user)) == 0) found = 1;
    }
    fclose(login_fd);
    if(line) free(line);
    
    
    if(found == 0) return "User not found!\n";
    else 
    {
        if(is_logged == false) return "CONNECTED\n";
        else return "Already connected\n";
    }
}

char* exec_get_logged_users()
{
    if(is_logged == true)
    {
        char *msg = malloc(sizeof (char) * MAX_BUFFER_SIZE);
        struct utmp *info;
        setutent();
        info = getutent();
        FILE *fd = fopen("userinfo.txt", "w");

        while(info)
        {
            if(info->ut_type==USER_PROCESS) 
            {
                fprintf(fd, "%s - %s - %d:%d\n", info->ut_user, info->ut_host, info->ut_tv.tv_sec, info->ut_tv.tv_usec);
            }
            info = getutent();
        }

        fclose(fd);

        FILE *fd_read = fopen("userinfo.txt", "r");

        char usr_buff[1000];

        while(fgets(usr_buff, sizeof(usr_buff), fd_read))
        {
            strcat(msg, usr_buff);
            strcat(msg, "\n");
        }

        fclose(fd_read);
        return msg;
    }
    else return "User not connected. Please connect to run this command\n";
}

char* exec_get_proc_info()
{
    return "Not implemented\n";
}

char* exec_logout()
{
    return "Logout successful\n";
}

char* handle_command(char command[MAX_BUFFER_SIZE], int len)
{
    if (strncmp("login : ", command, 8) == 0)
    {
        char *user = command + 8;
        return exec_login(user);
    }
    if (strncmp("get-logged-users", command, len-1) == 0)
    {
        return exec_get_logged_users();
    }
    if (strncmp("get-proc-info : ", command, 16) == 0)
    {
        return exec_get_proc_info();
    }
    if (strncmp("logout", command, len-1) == 0)
    {
        return exec_logout();
    }
    return "\n";
}

int main()
{
    fflush(stdout);
    mknod("srv-cli.fifo", S_IFIFO | 0666, 0);
    mknod("cli-srv.fifo", S_IFIFO | 0666, 0);

    while (1)
    {
        int srv_cli_fd = open("srv-cli.fifo", O_WRONLY);
        int cli_srv_fd = open("cli-srv.fifo", O_RDONLY);
        char buf[MAX_BUFFER_SIZE];
        int no_received_bytes;
        if((no_received_bytes = read(cli_srv_fd, buf, sizeof(buf))) < 0)
        {
            printf("Error receiving message %d\n", errno);
            printf("%s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        buf[no_received_bytes] = '\0';

        if(strncmp("quit", buf, 4) == 0)
        {
            write(srv_cli_fd, "You've been disconnected", 24);
            break;
        }

        if(check_message(buf, no_received_bytes) != true)
        {   
            // If message is not a command -> send message to client and don't execute it on server
            write(srv_cli_fd, "Unrecognized command!", 21);
        }
        else // available command
        {
            // Sending commands to childs through pipes : 
            int cmd_pipe_fds[2];
            int login_pipe[2];

            pipe(cmd_pipe_fds);
            pipe(login_pipe);
            pid_t pid_cmd = fork();

            int sockets[2];
            socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);

            if(pid_cmd > 0) // parent
            {
                close(cmd_pipe_fds[READ]);
                close(login_pipe[WRITE]);
                write(cmd_pipe_fds[WRITE], buf, no_received_bytes);
                char buff[10];
                int login_len = read(login_pipe[READ], buff, 10);
                buff[login_len] = '\0';
                if(buff[0] == '1') is_logged = true;
                else if(buff[0] == '0') is_logged = false;

                wait(NULL);
            }

            else // child (that executes commands)
            {
                close(cmd_pipe_fds[WRITE]);
                close(login_pipe[READ]);

                char cmd_buffer[MAX_BUFFER_SIZE];
                int len_cmd_buffer = read(cmd_pipe_fds[READ], cmd_buffer, sizeof(cmd_buffer));
                cmd_buffer[len_cmd_buffer] = '\0';
                
                char *handler_msg = handle_command(cmd_buffer, len_cmd_buffer);
                if(strncmp(handler_msg, "CONNECTED", 9) == 0) write(login_pipe[WRITE], "1", 1);
                if(strncmp(handler_msg, "Logout successful", 17) == 0) write(login_pipe[WRITE], "0", 1);
                
                //printf("%s", handler_msg);
                write(srv_cli_fd, handler_msg, strlen(handler_msg)); // Server sends back RCE message
                break;
            }
        }
        
        close(srv_cli_fd);
        close(cli_srv_fd);
    }

    exit(EXIT_SUCCESS);
}