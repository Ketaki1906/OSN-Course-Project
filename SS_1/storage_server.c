#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <semaphore.h>

#define MAX_FILES 50
#define BUFFER_SIZE 1024
#define BASE_DIR "." // Base directory for storage
int client_sock;     // Anyone who is connecting to the storage_server is called client
int nm_sock;

void *send_heartbeat(void *arg)
{
    char **args = (char **)arg;
    const char *nm_ip = args[0];
    int nm_port = atoi(args[1]);
    const char *ss_ip = args[2];
    int ss_port = atoi(args[3]);

    while (1)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            perror("Socket creation failed");
            sleep(5);
            continue;
        }

        struct sockaddr_in nm_addr;
        nm_addr.sin_family = AF_INET;
        nm_addr.sin_port = htons(nm_port);
        if (inet_pton(AF_INET, nm_ip, &nm_addr.sin_addr) <= 0)
        {
            perror("Invalid NM IP address");
            close(sock);
            sleep(5);
            continue;
        }

        if (connect(sock, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) == 0)
        {
            char heartbeat_msg[BUFFER_SIZE];
            snprintf(heartbeat_msg, BUFFER_SIZE, "HEARTBEAT %s %d", ss_ip, ss_port);
            send(sock, heartbeat_msg, strlen(heartbeat_msg), 0);
        }
        else
        {
            perror("Connection to NM failed");
        }

        close(sock);
        sleep(5); // Send heartbeat every 5 seconds
    }

    // Free memory allocated for heartbeat arguments
    free(args[0]);
    free(args[1]);
    free(args[2]);
    free(args[3]);
    free(args);
    return NULL;
}

void create_file_or_directory(const char *path, char *response)
{
    char full_path[BUFFER_SIZE];
    memset(full_path, 0, sizeof(full_path));
    printf("%s\n", path);
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, path);
    printf("%s\n", full_path);

    // Ensure path is within BASE_DIR
    if (strncmp(full_path, BASE_DIR, strlen(BASE_DIR)) != 0)
    {
        snprintf(response, BUFFER_SIZE, "Error: Path traversal detected\n");
        return;
    }

    // Check if the path ends with '/'
    if (full_path[strlen(full_path) - 1] == '/')
    {
        // Create directory recursively
        char command[BUFFER_SIZE];
        memset(command, 0, sizeof(command));
        snprintf(command, sizeof(command), "mkdir -p %s", full_path);
        // mkdir(full_path,0755);
        if (system(command) == 0)
        {
            snprintf(response, BUFFER_SIZE, "Directory '%s' created successfully\n", path);
            char confirmation[] = "CREATE SUCCESS, DIRECTORY SUCCESFULLY CREATED";
            send(nm_sock, confirmation, strlen(confirmation), 0);
            //  insert_into_trie(trie_root, path, 0,1);
        }
        else
        {
            snprintf(response, BUFFER_SIZE, "Error creating directory '%s'\n", path);
        }
    }
    else
    {
        // Create file
        FILE *file = fopen(full_path, "w");
        if (file)
        {
            fclose(file);
            snprintf(response, BUFFER_SIZE, "File '%s' created successfully\n", path);
            char confirmation[] = "CREATE SUCCESS, FILE SUCCESFULLY CREATED";
            send(nm_sock, confirmation, strlen(confirmation), 0);
            // insert_into_trie(trie_root, path, 0,0);
        }
        else
        {
            snprintf(response, BUFFER_SIZE, "Error creating file '%s'\n", path);
        }
    }
}

// Function to handle partial sends
ssize_t send_all(int sock, const char *buffer, size_t length)
{
    size_t total_sent = 0;
    while (total_sent < length)
    {
        ssize_t bytes_sent = send(sock, buffer + total_sent, length - total_sent, 0);
        if (bytes_sent < 0)
        {
            // perror("Failed to send data");
            return -1; // Return error
        }
        total_sent += bytes_sent;
    }
    return total_sent; // Return total bytes successfully sent
}

void read_and_send_file(int client_sock, const char *file_path, char *response)
{
    char full_path[BUFFER_SIZE];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, file_path);

    FILE *file = fopen(full_path, "r");
    if (!file)
    {
        perror("Failed to open file");
        snprintf(response, BUFFER_SIZE, "Error: Unable to open file '%s'\n", file_path);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    // Buffer for reading file chunks
    char file_buffer[BUFFER_SIZE];
    size_t bytes_read;

    // Read and send file in chunks
    while ((bytes_read = fread(file_buffer, 1, BUFFER_SIZE, file)) > 0)
    {
        if (send_all(client_sock, file_buffer, bytes_read) < 0)
        {
            // fprintf(stderr, "Failed to send file content completely.\n");
            fclose(file);
            return; // Exit on send failure
        }
    }

    if (ferror(file))
    {
        perror("Error reading the file");
        snprintf(response, BUFFER_SIZE, "Error: Unable to read file '%s'\n", file_path);
        send(client_sock, response, strlen(response), 0);
    }
    else
    {
        printf("File content sent successfully.\n");
    }

    fclose(file);

    // Notify the client that the transmission is complete
    const char *end_message = "EOF"; // End-of-file indicator
    if (send_all(client_sock, end_message, strlen(end_message)) < 0)
    {
        perror("Failed to send EOF message");
    }
}

ssize_t recv_all(int sock, char *buffer, size_t length)
{
    size_t total_received = 0;
    while (total_received < length)
    {
        ssize_t bytes_received = recv(sock, buffer + total_received, length - total_received, 0);
        if (bytes_received < 0)
        {
            perror("Failed to receive data");
            return -1;
        }
        if (bytes_received == 0)
        {
            break; // No more data
        }
        total_received += bytes_received;
    }
    return total_received;
}

void write_to_file(int client_sock, const char *file_path, char *response)
{

    char full_path[BUFFER_SIZE];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, file_path);

    FILE *file = fopen(full_path, "w");
    if (!file)
    {
        perror("Failed to open file");
        snprintf(response, BUFFER_SIZE, "Error: Unable to open file '%s'\n", file_path);
        send(client_sock, response, strlen(response), 0);
        return;
    }

    ssize_t bytes_received;
    char buffer[BUFFER_SIZE];
    while ((bytes_received = recv_all(client_sock, buffer, sizeof(buffer) - 1)) > 0)
    {
        buffer[bytes_received] = '\0'; // Null-terminate the received data

        // Check for EOF marker
        if (strncmp(buffer, "EOF", 3) == 0)
        {
            break;
        }

        // Write to the file
        if (fwrite(buffer, 1, bytes_received, file) != (size_t)bytes_received)
        {
            perror("Failed to write to file");
            fclose(file);
            return;
        }
    }

    if (bytes_received < 0)
    {
        perror("Failed to receive file content");
    }
    else
    {
        printf("File content received and written to '%s'.\n", file_path);
    }

    fclose(file);
}

// Function to delete a file or folder
void delete_file_or_directory(const char *path, char *response)
{
    char full_path[BUFFER_SIZE];
    memset(full_path, 0, sizeof(full_path));
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, path);

    // Ensure path is within BASE_DIR
    if (strncmp(full_path, BASE_DIR, strlen(BASE_DIR)) != 0)
    {
        snprintf(response, BUFFER_SIZE, "Error: Path traversal detected\n");
        return;
    }

    struct stat path_stat;
    if (stat(full_path, &path_stat) == 0)
    {
        if (S_ISDIR(path_stat.st_mode))
        {

            char command[BUFFER_SIZE];
            memset(command, 0, sizeof(command));
            snprintf(command, sizeof(command), "rm -rf %s", full_path); // Caution: rm -rf for directories
            if (system(command) == 0)
            {
                snprintf(response, BUFFER_SIZE, "Directory '%s' deleted successfully\n", path);
                char confirmation[] = "DELETE SUCCESS, DIRECTORY SUCCESFULLY DELETED";
                send(nm_sock, confirmation, strlen(confirmation), 0);
                // delete_from_trie(path);
            }
            else
            {
                snprintf(response, BUFFER_SIZE, "Error deleting directory '%s'\n", path);
            }
        }
        else
        {
            if (unlink(full_path) == 0)
            {
                snprintf(response, BUFFER_SIZE, "File '%s' deleted successfully\n", path);
                char confirmation[] = "DELETE SUCCESS, FILE SUCCESFULLY DELETED";
                send(nm_sock, confirmation, strlen(confirmation), 0);
            } // delete_from_trie(path);
            else
            {
                snprintf(response, BUFFER_SIZE, "Error deleting file '%s'\n", path);
            }
        }
    }
    else
    {
        snprintf(response, BUFFER_SIZE, "Error: '%s' not found\n", path);
    }
}

void get_file_metadata(const char *path, char *response)
{
    char full_path[BUFFER_SIZE];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, path);

    struct stat path_stat;
    if (stat(full_path, &path_stat) == 0)
    {
        snprintf(response, BUFFER_SIZE, "Size: %lu bytes, Permissions: %o\n",
                 path_stat.st_size, path_stat.st_mode & 0777);
    }
    else
    {
        snprintf(response, BUFFER_SIZE, "Error: '%s' not found\n", path);
    }
}

void send_music_file(int client_sock, const char *file_path)
{
    FILE *file = fopen(file_path, "rb");
    if (!file)
    {
        perror("Failed to open music file");
        const char *error_message = "ERROR: Unable to open file.\n";
        send(client_sock, error_message, strlen(error_message), 0);
        return;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    printf("Sending music file: %s\n", file_path);

    // Read file in chunks and send to client
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        if (send(client_sock, buffer, bytes_read, 0) < 0)
        {
            perror("Failed to send music data");
            fclose(file);
            return;
        }
    }

    fclose(file);

    // Notify the client that the file transfer is complete
    const char *end_message = "EOF"; // End-of-file indicator
    if (send(client_sock, end_message, strlen(end_message), 0) < 0)
    {
        perror("Failed to send EOF message");
    }

    printf("File transfer completed: %s\n", file_path);
}

void send_file(int server_sock, char *path)
{
    int file = open(path, O_RDONLY);
    if (file == -1)
    {
        perror("File open failed");
        return;
    }

    ssize_t bytes_read;
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    while ((bytes_read = read(file, buffer, BUFFER_SIZE)) > 0)
    {
        ssize_t total_sent = 0;

        while (total_sent < bytes_read)
        {
            ssize_t bytes_sent = send(server_sock, buffer + total_sent, bytes_read - total_sent, 0);

            if (bytes_sent < 0)
            {
                perror("send failed");
                return;
            }

            total_sent += bytes_sent;
        }
    }

    close(file);
}

void copy_file_directories(int server_sock, char *path, char *response)
{
    char full_path[BUFFER_SIZE];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, path);
    printf("FULL PATH: %s\n", full_path);

    // struct stat path_stat;
    // stat(full_path, &path_stat);

    // if (S_ISDIR(path_stat.st_mode))
    // {
    //     send_directory(server_sock, full_path, response);
    // }
    // else if (S_ISREG(path_stat.st_mode))
    // {
    send_file(server_sock, full_path);
    // }
    // else
    // {
    //     snprintf(response, BUFFER_SIZE, "Error: '%s' not found\n", path);
    //     return;
    // }
    // response = "";
}
void extract_filename(const char *input, char *filename)
{
    const char *last_slash = strrchr(input, '/'); // Find the last '/'
    if (!last_slash)
    {
        strcpy(filename, input);
        return;
    }

    strcpy(filename, last_slash + 1);
}

void paste_file_contents(int server_socket, char *file_path, char *response, const char *content)
{
    char full_path[BUFFER_SIZE];
    char filename[BUFFER_SIZE] = {0};
    extract_filename(file_path, filename);
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, filename);
    printf("Full path: %s\n", full_path);
    printf("Received file path %s\n", file_path);
    printf("Received file name %s\n", filename);

    FILE *file = fopen(full_path, "w");
    printf("%s\n", content);
    printf("%d\n", strlen(content));
    if (file)
    {
        size_t written = fwrite(content, 1, 10000, file);

        // Ensure the entire content is written
        if (written == strlen(content))
        {
            snprintf(response, BUFFER_SIZE, "File '%s' written successfully\n", filename);
        }
        else
        {
            snprintf(response, BUFFER_SIZE, "Error: Only %zu bytes written to file '%s'\n", written, filename);
        }

        fclose(file);
    }
    else
    {
        snprintf(response, BUFFER_SIZE, "Error writing to file '%s'\n", file_path);
    }
}
void paste_file_directories(int server_sock, char *file_path, char *response, char *content)
{
    char type[5];
    printf("%s\n", file_path);
    printf("%s\n", content);
    char content_copy[BUFFER_SIZE] = {0};
    strcpy(content_copy, content);
    printf("%s\n", content_copy);

    // paste_file_contents(server_sock, path, response, content);
    char full_path[BUFFER_SIZE];
    char filename[BUFFER_SIZE] = {0};
    extract_filename(file_path, filename);
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, filename);
    printf("Full path: %s\n", full_path);
    printf("Received file path %s\n", file_path);
    printf("Received file name %s\n", filename);

    FILE *file = fopen(full_path, "w");
    printf("%s\n", content_copy);
    printf("%d\n", strlen(content_copy));
    if (file)
    {
        size_t written = fwrite(content_copy, 1, 10000, file);

        // Ensure the entire content is written
        if (written == strlen(content_copy))
        {
            snprintf(response, BUFFER_SIZE, "File '%s' written successfully\n", filename);
        }
        else
        {
            snprintf(response, BUFFER_SIZE, "Error: Only %zu bytes written to file '%s'\n", written, filename);
        }

        fclose(file);
    }
    else
    {
        snprintf(response, BUFFER_SIZE, "Error writing to file '%s'\n", file_path);
    }
}

// Function to handle client commands
void handle_client_command(void *arg)
{
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    printf("%d\n", client_sock);
    recv(client_sock, buffer, sizeof(buffer), 0);
    printf("%s\n", buffer);

    char command[BUFFER_SIZE], path[BUFFER_SIZE], content[BUFFER_SIZE];
    char type[BUFFER_SIZE];
    memset(type, sizeof(type), 0);
    memset(command, 0, sizeof(command));
    memset(path, 0, sizeof(path));
    memset(content, 0, sizeof(content));

    sscanf(buffer, "%s %s", command, path);

    char *content_start = strchr(buffer, ' ');      // Skip first token (command)
    content_start = strchr(content_start + 1, ' '); // Skip second token (path)
    if (content_start)
    {
        content_start++; // Move past the space
    }

    if (content_start)
    {
        strncpy(content, content_start, sizeof(content) - 1);
        content[sizeof(content) - 1] = '\0'; // Null-terminate to avoid overflow
    }
    else
    {
        strcpy(content, "");
    }

    // Print results
    printf("Command: %s\n", command);
    printf("Path: %s\n", path);
    printf("Content:\n%s\n", content);

    if (strcmp(command, "CREATE") == 0)
    {
        create_file_or_directory(path, response);
    }
    else if (strcmp(command, "DELETE") == 0)
    {
        delete_file_or_directory(path, response);
    }
    else if (strcmp(command, "READ") == 0)
    {
        read_and_send_file(client_sock, path, response); // reads file and sends it to the client (connection is already established)
        close(client_sock);
        return;
    }
    else if (strcmp(command, "WRITE") == 0)
    {
        write_to_file(client_sock, path, response);
        close(client_sock);
        return;
    }
    else if (strcmp(command, "INFO") == 0)
    {
        get_file_metadata(path, response);
        printf("%s\n", response);
    }
    else if (strcmp(command, "STREAM") == 0)
    {
        send_music_file(client_sock, path);
    }
    else if (strcmp(command, "COPY_FROM") == 0)
    {
        copy_file_directories(client_sock, path, response);
    }
    else if (strcmp(command, "COPY_TO") == 0) // As only file implemented, the dest path here is also a file
    {
        paste_file_directories(client_sock, path, response, content);
    }
    else
    {
        snprintf(response, BUFFER_SIZE, "Error: Unknown command '%s'\n", command);
    }
    send(client_sock, response, strlen(response), 0);
    close(client_sock);
}

void register_with_naming_server(const char *nm_ip, int nm_port, const char *self_ip, int nm_conn_port, int client_port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in nm_addr;
    nm_addr.sin_family = AF_INET;
    nm_addr.sin_port = htons(nm_port);
    inet_pton(AF_INET, nm_ip, &nm_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) < 0)
    {
        perror("Connection to Naming Server failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Prepare the registration message
    char message[BUFFER_SIZE] = {0};
    snprintf(message, sizeof(message), "REGISTER %s %d %d", self_ip, nm_conn_port, client_port);

    // Send the registration message
    send(sock, message, strlen(message), 0);

    // Wait for acknowledgment
    char response[BUFFER_SIZE];
    recv(sock, response, sizeof(response), 0);

    printf("Response from Naming Server: %s\n", response);
    if (strncmp(response, "ACK", 3) == 0)
    {
        printf("Enter the Number of Accessible paths for the NFS: ");
        int num_paths;
        scanf("%d", &num_paths);
        int network_num_paths = htonl(num_paths);
        if (send(sock, &network_num_paths, sizeof(network_num_paths), 0) < 0)
        {
            perror("Send failed");
            exit(EXIT_FAILURE);
        }
        for (int i = 0; i < num_paths; i++)
        {
            char path_to_file[BUFFER_SIZE];
            printf("Enter Path %d: ", i + 1);
            scanf("%s", path_to_file);
            int path_length = strlen(path_to_file) + 1; // +1 for null terminator
            int network_path_length = htonl(path_length);
            // Send the length of the path
            if (send(sock, &network_path_length, sizeof(network_path_length), 0) < 0)
            {
                perror("Send failed");
                exit(EXIT_FAILURE);
            }
            // Send the path itself
            if (send(sock, path_to_file, path_length, 0) < 0)
            {
                perror("Send failed");
                exit(EXIT_FAILURE);
            }
        }
        printf("All paths sent successfully.\n");
    }
    close(sock);
}

int main(int argc, char *argv[])
{
    if (argc != 6)
    {
        fprintf(stderr, "Usage: %s <IP> <NM_Port> <Client_Port> <Naming_Server_IP> <Naming_Server_Port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *self_ip = argv[1];    // IP address of the storage server
    int nm_conn_port = atoi(argv[2]); // Port to establish direct connection between NM and SS
    int client_port = atoi(argv[3]);  // Port to connect client directly with the storage server
    const char *nm_ip = argv[4];      // IP address of the Naming Server
    int nm_port = atoi(argv[5]);      // Port of the Naming Server

    // Register the server with the Naming Server
    register_with_naming_server(nm_ip, nm_port, self_ip, nm_conn_port, client_port);

    // Allocate memory for heartbeat arguments
    char **heartbeat_args = malloc(4 * sizeof(char *));
    if (!heartbeat_args)
    {
        perror("Memory allocation for heartbeat_args failed");
        return EXIT_FAILURE;
    }

    heartbeat_args[0] = strdup(nm_ip);   // Naming Server IP
    heartbeat_args[1] = strdup(argv[5]); // Naming Server Port
    heartbeat_args[2] = strdup(self_ip); // Self IP
    heartbeat_args[3] = strdup(argv[2]); // Client Port

    // Start the heartbeat thread
    pthread_t heartbeat_thread;
    if (pthread_create(&heartbeat_thread, NULL, send_heartbeat, heartbeat_args) != 0)
    {
        perror("Failed to create heartbeat thread");
        return EXIT_FAILURE;
    }
    pthread_detach(heartbeat_thread); // Detach to free resources when thread completes

    // Initialize server socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(nm_conn_port);
    inet_pton(AF_INET, self_ip, &server_addr.sin_addr);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        close(server_sock);
        return EXIT_FAILURE;
    }

    if (listen(server_sock, 10) < 0)
    {
        perror("Listen failed");
        close(server_sock);
        return EXIT_FAILURE;
    }

    printf("Storage Server initialized and registered with Naming Server.\n");
    printf("Ready to handle client connections on port %d.\n", client_port);
    // NM Socket
    nm_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (nm_sock < 0)
    {
        perror("Socket creation failed");
    }

    struct sockaddr_in nm_addr;
    nm_addr.sin_family = AF_INET;
    nm_addr.sin_port = htons(nm_port);
    if (inet_pton(AF_INET, nm_ip, &nm_addr.sin_addr) <= 0)
    {
        perror("Invalid NM IP address");
        close(nm_sock);
    }

    if (connect(nm_sock, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) == 0)
    {
        // char heartbeat_msg[BUFFER_SIZE];
        // snprintf(heartbeat_msg, BUFFER_SIZE, "HEARTBEAT %s %d", ss_ip, ss_port);
        // send(nm_sock, heartbeat_msg, strlen(heartbeat_msg), 0);
    }
    else
    {
        perror("Connection to NM failed");
    }
    // NM Socket
    // Server loop to accept and handle client connections
    while (1)
    {
        client_sock = accept(server_sock, NULL, NULL);
        printf("%d\n", client_sock);
        if (client_sock < 0)
        {
            perror("Client connection failed");
            continue;
        }

        printf("Client connected. Handling client request...\n");

        // Create a thread to handle the client request
        pthread_t thread_id;
        int *client_sock_ptr = malloc(sizeof(int));
        if (!client_sock_ptr)
        {
            perror("Memory allocation failed");
            close(client_sock);
            continue;
        }
        *client_sock_ptr = client_sock;

        if (pthread_create(&thread_id, NULL, handle_client_command, client_sock_ptr) != 0)
        {
            perror("Thread creation failed");
            close(client_sock);
            free(client_sock_ptr);
            continue;
        }

        // Detach the thread to free resources after it completes
        pthread_detach(thread_id);
    }

    close(server_sock);
    return 0;
}