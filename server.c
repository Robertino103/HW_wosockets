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
#include <time.h>

#define READ 0
#define WRITE 1
#define MAX_BUFFER_SIZE 1000

bool check_message(char buf[MAX_BUFFER_SIZE], int len) //Checking if message is really a command
{
    if (strncmp("login : ", buf, 8) == 0)
        return true;
    if (strncmp("get-logged-users", buf, len - 1) == 0)
        return true;
    if (strncmp("get-proc-info : ", buf, 16) == 0)
        return true;
    if (strncmp("logout", buf, len-1) == 0)
        return true;
    if (strncmp("quit", buf, len - 1) == 0)
        return true;
    return false;
}

bool is_logged = false; // flag to set if user is logged

char *exec_login(char *user)
{
    int found = 0;
    FILE *login_fd;
    char *line = NULL;
    size_t len_line = 0;
    ssize_t read;
    login_fd = fopen("users.cfg", "r");

    if (login_fd == NULL)
    {
        printf("No config file found ! (%d)\n", errno);
        exit(EXIT_FAILURE);
    }
    while ((read = getline(&line, &len_line, login_fd)) != -1)
    {
        if (strncmp(user, line, strlen(user)) == 0)
            found = 1;
    }
    fclose(login_fd);
    if (line)
        free(line);

    if (found == 0)
        return "User not found!";
    else
    {
        if (is_logged == false)
            return "CONNECTED";
        else
            return "Already connected";
    }
}

char *exec_get_logged_users()
{
    if (is_logged == true)
    {
        char *msg = malloc(sizeof(char) * MAX_BUFFER_SIZE);
        struct utmp *info;
        setutent();
        info = getutent();
        FILE *fd = fopen("userinfo.txt", "w");

        while (info)
        {
            if (info->ut_type == USER_PROCESS)
            {
                fprintf(fd, "%s - %s - %d:%d\n", info->ut_user, info->ut_host, info->ut_tv.tv_sec, info->ut_tv.tv_usec);
            }
            info = getutent();
        }
        
        fclose(fd);

        FILE *fd_read = fopen("userinfo.txt", "r");

        char usr_buff[MAX_BUFFER_SIZE];

        while (fgets(usr_buff, sizeof(usr_buff), fd_read))
        {
            strcat(msg, usr_buff);
            strcat(msg, ".");
        }

        fclose(fd_read);
        return msg;
    }
    else
        return "User not connected. Please connect to run this command";
}

char *exec_get_proc_info(char *pid)
{
    if (is_logged == true)
    {
        char path[MAX_BUFFER_SIZE];
        path[0] = '\0';
        strcat(path, "/proc/");
        strncat(path, pid, strlen(pid) - 1);
        strcat(path, "/status");

        FILE *proc_fd = fopen(path, "r");

        char *msg = malloc(sizeof(char) * MAX_BUFFER_SIZE);
        msg[0] = '\0';

        size_t len = 0;
        char *read;
        char line[MAX_BUFFER_SIZE];

        while ((read = fgets(line, sizeof(line), proc_fd)))
        {
            line[(int)strlen(line) - 1] = '\0';
            if (strstr(line, "Name") != NULL 
            || strstr(line, "State") != NULL 
            || strstr(line, "VmSize") != NULL 
            || strstr(line, "PPid") != NULL 
            || strstr(line, "Uid") != NULL) 
            {
                strcat(msg, line);
                strcat(msg, "\n");
            }
        }
        msg[strlen(msg) - 1] = '\0';
        return msg;
    }
    else
        return "User not connected. Please connect to run this command";
}

char *exec_logout()
{
    return "Logout successful";
}

char *handle_command(char command[MAX_BUFFER_SIZE], int len)
{
    if (strncmp("login : ", command, 8) == 0)
    {
        char *user = command + 8;
        return exec_login(user);
    }
    if (strncmp("get-logged-users", command, len - 1) == 0)
    {
        return exec_get_logged_users();
    }
    if (strncmp("get-proc-info : ", command, 16) == 0)
    {
        char *pidstr = command + 16;
        return exec_get_proc_info(pidstr);
    }
    if (strncmp("logout", command, len - 1) == 0)
    {
        return exec_logout();
    }
    return NULL;
}

int main()
{
    fflush(stdout);

    //####### Creating fifos : ######
    if (access("srv-cli.fifo", F_OK) == -1)
    {
        mknod("srv-cli.fifo", S_IFIFO | 0666, 0);
    }
    if (access("cli-srv.fifo", F_OK) == -1)
    {
        mknod("cli-srv.fifo", S_IFIFO | 0666, 0);
    }
    //###############################################

    while (1)
    {
        int srv_cli_fd = open("srv-cli.fifo", O_WRONLY);
        if (srv_cli_fd < 0)
        {
            printf("Error opening server to client fifo. (%d)\n", errno);
            printf("%s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        int cli_srv_fd = open("cli-srv.fifo", O_RDONLY);
        if (cli_srv_fd < 0)
        {
            printf("Error opening client to server fifo. (%d)\n", errno);
            printf("%s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        char buf[MAX_BUFFER_SIZE];
        int no_received_bytes;
        if ((no_received_bytes = read(cli_srv_fd, buf, sizeof(buf))) < 0)
        {
            printf("Error receiving message %d\n", errno);
            printf("%s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        buf[no_received_bytes] = '\0';

        if (strncmp("quit", buf, 4) == 0)
        {
            write(srv_cli_fd, "You've been disconnected", 24);
            break;
        }

        if (check_message(buf, no_received_bytes) != true)
        {
            // If message is not a command -> send message to client and don't execute it on server
            write(srv_cli_fd, "Unrecognized command!", 21);
        }
        else // available command
        {
            //###### Creating sockets for parent->child, child->parent communication ######
            int sockets[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1)
            {
                printf("Error creating socketpair (%d)\n", errno);
                printf("%s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            //#############################################################################

            int login_pipe[2]; // Pipe used by child to return log in state (Child cannot change the global flag (is_logged var))
            if (pipe(login_pipe) == -1)
            {
                printf("Error piping (%d)\n", errno);
                printf("%s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }

            pid_t pid_cmd = fork();
            if (pid_cmd > 0) // parent
            {
                close(login_pipe[WRITE]);
                close(sockets[0]);

                write(sockets[1], buf, no_received_bytes);
                char msg[MAX_BUFFER_SIZE];
                int no_bytes_msg = read(sockets[1], msg, sizeof(msg));

                write(srv_cli_fd, msg, no_bytes_msg);
                write(srv_cli_fd, "\n", 1);
                close(sockets[1]);

                char buff[10];
                int login_len = read(login_pipe[READ], buff, 10);
                buff[login_len] = '\0';
                if (buff[0] == '1')
                    is_logged = true;
                else if (buff[0] == '0')
                    is_logged = false;

                sleep(1);
                wait(NULL);
            }

            else if (pid_cmd == 0) // child (that executes commands)
            {
                printf("%d - %d\n", getpid(), getppid());
                close(login_pipe[READ]);
                close(sockets[1]);

                char cmd_buffer[MAX_BUFFER_SIZE];
                int len_cmd_buffer = read(sockets[0], cmd_buffer, sizeof(cmd_buffer));
                cmd_buffer[len_cmd_buffer] = '\0';

                // handler_msg will hold the response to be sent back to client :
                char *handler_msg = handle_command(cmd_buffer, len_cmd_buffer);

                if (strncmp(handler_msg, "CONNECTED", 9) == 0)
                    write(login_pipe[WRITE], "1", 1);
                if (strncmp(handler_msg, "Logout successful", 17) == 0)
                    write(login_pipe[WRITE], "0", 1);

                write(sockets[0], handler_msg, strlen(handler_msg)); // Server sends back message to parent
                close(sockets[0]);

                break;
            }

            else
            {
                printf("Error forking child in server (%d)", errno);
                printf("%s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
    }

    exit(EXIT_SUCCESS);
}