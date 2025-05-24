#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>
#include "trie.c"
#include "cache.c"

#define MAX_SERVERS 100
#define MAX_STORAGE_SERVERS 100
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024
#define MAX_FILES 20
#define LOG_FILE "naming_server.log"
#define HEARTBEAT_TIMEOUT 10
#define HASHMAP_SIZE 1024
#define MAX_PATHS_PER_SERVER 20
#define NUM_STORAGE_SERVERS 5
#define MAX_PATH_LENGTH 256

// Struct to store Storage Server information
struct StorageServerInfo
{
    char ip_address[INET_ADDRSTRLEN];
    int port;        // port for direct connection between NM and SS
    int client_port; // port connection between SS and client
    size_t total_space;
    size_t used_space;
    char active_paths[BUFFER_SIZE];
    char paths[MAX_FILES][BUFFER_SIZE]; // accessible paths for the SS
    int num_paths;                      // number of accessible paths
    time_t last_heartbeat;              // Track the last heartbeat time
    int is_active;                      // Active status flag (1 for active, 0 for failed)
};

// Global storage server registry
struct StorageServerInfo storage_servers[MAX_SERVERS];
int server_count = 0;
int total_paths = 0;

void handle_signal(int sig)
{
    printf("\nShutting down Naming Server...\n");
    exit(EXIT_SUCCESS);
}

// Mutex for thread-safe operations
pthread_mutex_t server_mutex = PTHREAD_MUTEX_INITIALIZER;

int hash(const char *key)
{
    size_t hash = 5381;
    int c;
    while ((c = *key++))
    {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % HASHMAP_SIZE;
}

struct TrieNode *create_trie_node()
{
    struct TrieNode *node = calloc(1, sizeof(struct TrieNode));
    return node;
}
struct TrieNode *trie_root = NULL;
struct CacheQueue *cache = NULL;

void get_timestamp(char *buffer, size_t size)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

void get_client_info(int client_sock, char *ip_buffer, int *port)
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_sock, (struct sockaddr *)&client_addr, &addr_len);

    inet_ntop(AF_INET, &client_addr.sin_addr, ip_buffer, INET_ADDRSTRLEN);
    *port = ntohs(client_addr.sin_port);
}

// Function to log messages to file and console
void log_message(const char *ip, int port, const char *message, const char *status)
{
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    // Format the log message
    char log_entry[512];
    snprintf(log_entry, sizeof(log_entry), "[%s] IP: %s, Port: %d, Status: %s, Message: %s\n",
             timestamp, ip, port, status, message);

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file)
    {
        fprintf(log_file, "%s", log_entry);
        fclose(log_file);
    }
    else
    {
        perror("Error opening log file");
    }
}

// Function to register a new Storage Server
void handle_register_request(const char *message, char *response)
{
    char ip[BUFFER_SIZE];
    int port;
    if (sscanf(message, "REGISTER %s %d", ip, &port) != 2)
    {
        snprintf(response, BUFFER_SIZE, "ERROR: Invalid registration message\n");
        return;
    }
    log_message(ip, port, message, "RECEIVED");

    // Log the new storage server registration
    printf("New Storage Server attempting to register: IP = %s, Port = %d\n", ip, port);
    pthread_mutex_lock(&server_mutex);
    if (server_count < MAX_SERVERS)
    {
        snprintf(response, BUFFER_SIZE, "ACK: Storage Server registration accepted.\n");
    }
    else
    {
        snprintf(response, BUFFER_SIZE, "ERROR: Max server limit reached\n");
    }
    pthread_mutex_unlock(&server_mutex);
}

void register_storage_server(int client_sock, char *buffer)
{
    char response[BUFFER_SIZE] = {0};
    handle_register_request(buffer, response);

    if (strncmp(response, "ACK", 3) == 0)
    {
        char ip[INET_ADDRSTRLEN] = {0};
        memset(ip, 0, sizeof(ip));
        int port = 0;
        int client_port = 0;

        // Parse the IP address and port from the input string
        if (sscanf(buffer, "REGISTER %s %d %d", ip, &port, &client_port) != 3)
        {
            snprintf(response, BUFFER_SIZE, "ERROR: Invalid registration format\n");
            log_message(ip, port, "Failed to register storage server.", "ERROR");
            send(client_sock, response, strlen(response), 0);
            return;
        }
        printf("Storage Server is here: %s %d\n", ip, port);

        struct StorageServerInfo server_info = {0};
        strncpy(server_info.ip_address, ip, sizeof(server_info.ip_address) - 1);
        server_info.port = port;
        server_info.total_space = 0; // Set defaults if unused
        server_info.used_space = 0;
        server_info.active_paths[0] = '\0';
        server_info.is_active = 1;
        server_info.last_heartbeat = time(NULL);
        server_info.client_port = client_port;
        memset(server_info.paths, '\0', sizeof(server_info.paths));
        server_info.num_paths = 0;

        // Add server to the global registry
        pthread_mutex_lock(&server_mutex);
        if (server_count < MAX_SERVERS)
        {
            storage_servers[server_count++] = server_info;
            printf("Registered Storage Server: %s:%d\n", server_info.ip_address, server_info.port);
            log_message(ip, port, "Storage server registered successfully.", "SUCCESS");
        }
        else
        {
            snprintf(response, BUFFER_SIZE, "ERROR: Max server limit reached\n");
            log_message(ip, port, "Failed to register storage server.", "ERROR");
            pthread_mutex_unlock(&server_mutex);
            send(client_sock, response, strlen(response), 0);
            return;
        }
        pthread_mutex_unlock(&server_mutex);
    }

    // Send the response (ACK)
    send(client_sock, response, strlen(response), 0);
    int network_num_paths;
    if (recv(client_sock, &network_num_paths, sizeof(network_num_paths), 0) < 0)
    {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }
    storage_servers[server_count - 1].num_paths = ntohl(network_num_paths);
    total_paths += storage_servers[server_count - 1].num_paths;
    for (int i = 0; i < storage_servers[server_count - 1].num_paths; i++)
    {
        int network_path_length;
        if (recv(client_sock, &network_path_length, sizeof(network_path_length), 0) < 0)
        {
            perror("Receive failed");
            exit(EXIT_FAILURE);
        }
        int path_length = ntohl(network_path_length);
        if (recv(client_sock, storage_servers[server_count - 1].paths[i], path_length, 0) < 0)
        {
            perror("Receive failed");
            exit(EXIT_FAILURE);
        }

        char server_info[BUFFER_SIZE];
        snprintf(server_info, BUFFER_SIZE, "%s:%d", storage_servers[server_count - 1].ip_address, storage_servers[server_count - 1].port);
        insert_into_trie(trie_root, storage_servers[server_count - 1].paths[i], server_info, 0);
        printf("Server Info .%s.\n", server_info);
        printf("Received Path %d: %s\n", i + 1, storage_servers[server_count - 1].paths[i]);
    }
    printf("All paths stored successfully.\n");
}

void handle_heartbeat(const char *message, char *response)
{
    char ip[BUFFER_SIZE];
    memset(ip, 0, sizeof(ip));
    int port = 0;

    if (sscanf(message, "HEARTBEAT %s %d", ip, &port) != 2)
    {
        snprintf(response, BUFFER_SIZE, "ERROR: Invalid heartbeat message\n");
        return;
    }
    // printf("%s %d\n",ip,port);

    pthread_mutex_lock(&server_mutex);
    int found = 0;
    for (int i = 0; i < server_count; i++)
    {
        if (strcmp(storage_servers[i].ip_address, ip) == 0 && storage_servers[i].port == port)
        {
            storage_servers[i].last_heartbeat = time(NULL); // Update last heartbeat time
            storage_servers[i].is_active = 1;               // Mark as active
            found = 1;
            // printf("tt: %ld\n",storage_servers[i].last_heartbeat);
            break;
        }
    }
    pthread_mutex_unlock(&server_mutex);
    // printf("tt: %ld\n",storage_servers[0].last_heartbeat);

    if (found)
    {
        snprintf(response, BUFFER_SIZE, "ACK: Heartbeat received\n");
    }
    else
    {
        snprintf(response, BUFFER_SIZE, "ERROR: Storage Server not registered\n");
    }
}

void *detect_failures(void *arg)
{
    while (1)
    {
        time_t now = time(NULL);
        pthread_mutex_lock(&server_mutex);

        for (int i = 0; i < server_count; i++)
        {
            // If heartbeat timeout occurs
            if (now - storage_servers[i].last_heartbeat > HEARTBEAT_TIMEOUT)
            {
                log_message(storage_servers[i].ip_address,
                            storage_servers[i].port,
                            "Storage Server marked as FAILED due to timeout.",
                            "ERROR");

                // Mark server as failed
                storage_servers[i].used_space = 0; // Reset state
                storage_servers[i].total_space = 0;
                strcpy(storage_servers[i].active_paths, "FAILED");
            }
        }

        pthread_mutex_unlock(&server_mutex);
        sleep(HEARTBEAT_TIMEOUT); // Run detection periodically
    }
    return NULL;
}

int ends_with_forward_slash(const char *src)
{
    if (src != NULL && strlen(src) > 0 && src[strlen(src) - 1] == '/')
    {
        return 1; // Returns 1 if it ends with '/'
    }
    return 0; // Returns 0 if it does not end with '/'
}

void copy_file(const char *path, char *response, int src_port, int dst_port, char *src_ip, char *dst_ip, char *source, char *dest)
{
    printf("SRC IP: %s\n", src_ip);
    char command[BUFFER_SIZE];
    int src_socket, dst_socket;
    memset(command, 0, sizeof(command));
    struct sockaddr_in src_addr, dst_addr;
    src_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (src_socket == -1)
    {
        perror("Source socket creation failed");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(src_port);
    if (inet_pton(AF_INET, src_ip, &src_addr.sin_addr) <= 0)
    {
        perror("Invalid source IP address");
        close(src_socket);
        return -1;
    }

    if (connect(src_socket, (struct sockaddr *)&src_addr, sizeof(src_addr)) == -1)
    {
        perror("Connection to source server failed");
        close(src_socket);
        return -1;
    }

    snprintf(command, BUFFER_SIZE, "COPY_FROM %s ", path);
    if (send(src_socket, command, strlen(command) + 1, 0) == -1)
    {
        perror("Failed to send file path to source server");
        close(dst_socket);
        return -1;
    }

    dst_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (dst_socket == -1)
    {
        perror("Destination socket creation failed");
        close(dst_socket);
        close(src_socket);
        return -1;
    }

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst_addr.sin_addr) <= 0)
    {
        perror("Invalid destination IP address");
        close(src_socket);
        close(dst_socket);
        return -1;
    }

    if (connect(dst_socket, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) == -1)
    {
        perror("Connection to destination server failed");
        close(src_socket);
        close(dst_socket);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    size_t bytesRead;
    size_t type;
    printf("Destination before file copying %s", dest);
    if (ends_with_forward_slash(dest))
    {
        while ((bytesRead = recv(src_socket, buffer, BUFFER_SIZE, 0)) > 0)
        {
            buffer[bytesRead] = '\0';
            printf("BUFFER %s\n", buffer);
            char copied_data[BUFFER_SIZE + 100];
            int prefix_len = snprintf(copied_data, sizeof(copied_data), "COPY_TO %s ", path);

            memcpy(copied_data + prefix_len, buffer, bytesRead);

            // Send the complete message (prefix + data)
            ssize_t total_len = prefix_len + bytesRead;

            ssize_t sent = send(dst_socket, copied_data, total_len, 0);
            if (sent == -1)
            {
                perror("Failed to send data");
                break;
            }
        }
        if (bytesRead == -1)
        {
            perror("Failed to read data from source server");
            snprintf(response, BUFFER_SIZE, "Error: No response from storage server\n");
        }
        printf("COPY completed-1\n");
    }
    else
    {
        while ((bytesRead = recv(src_socket, buffer, BUFFER_SIZE, 0)) > 0)
        {
            buffer[bytesRead] = '\0';
            printf("%s\n", buffer);
            char copied_data[BUFFER_SIZE + 100];
            int prefix_len = snprintf(copied_data, sizeof(copied_data), "COPY_TO %s ", dest);

            memcpy(copied_data + prefix_len, buffer, bytesRead);

            // Send the complete message (prefix + data)
            ssize_t total_len = prefix_len + bytesRead;
            ssize_t sent = send(dst_socket, copied_data, total_len, 0);
            if (sent == -1)
            {
                perror("Failed to send data");
                break;
            }
        }

        if (bytesRead == -1)
        {
            perror("Failed to read data from source server");
            snprintf(response, BUFFER_SIZE, "Error: No response from storage server\n");
        }
    }
    printf("Response %s\n", response);
    close(src_socket);
    close(dst_socket);
    printf("COPY completed-2\n");
}

void extract_between_last_two_slashes(const char *input, char *between)
{
    const char *last_slash = strrchr(input, '/'); // Find the last '/'
    if (!last_slash || last_slash == input)
    {
        // strcpy(between, "Error: Less than two '/' found");
        return;
    }

    // Find the second last slash
    const char *second_last_slash = last_slash - 1;
    while (second_last_slash >= input && *second_last_slash != '/')
    {
        second_last_slash--;
    }

    if (second_last_slash < input)
    {
        strcpy(between, input);
        return;
    }

    // Copy the string between the last two slashes
    size_t len = last_slash - second_last_slash - 1;
    strncpy(between, second_last_slash + 1, len);
    between[len] = '\0'; // Null-terminate the string
}

// Function to extract the filename after the last slash
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

void get_ip_in_trie(const struct TrieNode *trie_root, char *command, char *path)
{
    struct TrieNode *current = trie_root;
    // struct TrieNode *current = root;
    while (*path)
    {
        if (!current->children[(unsigned char)*path])
        {
            return 0; // Path not found
        }
        current = current->children[(unsigned char)*path];
        path++;
    }
    if (current->is_directory)
    {
        // *is_directory = 1;
        if (current->storage_server_id)
        {
            strncpy(command, current->storage_server_id, BUFFER_SIZE - 1);
            command[BUFFER_SIZE - 1] = '\0'; // Null-terminate the string
            return;
        }
        else
        {
            command[0] = '\0'; // No server ID found
        }
        // server_info[0] = '\0'; // Directories do not have a server ID
        return; // Directory found
    }
    if (current->is_end_of_file)
    {
        // *is_directory = 0;
        if (current->storage_server_id)
        {
            strncpy(command, current->storage_server_id, BUFFER_SIZE - 1);
            command[BUFFER_SIZE - 1] = '\0'; // Null-terminate the string
        }
        else
        {
            command[0] = '\0'; // No server ID found
        }
        return; // File found
    }
    return;
}

void copy_file_directory(int client_sock, const char *paths, char *response)
{
    char *source = (char *)malloc(BUFFER_SIZE);
    char *dest = (char *)malloc(BUFFER_SIZE);

    memset(source, 0, sizeof(source));
    memset(dest, 0, sizeof(dest));

    if (sscanf(paths, "%s %s", source, dest) == 2)
    {
        printf("Source Path: %s\n", source);
        printf("Destination Path: %s\n", dest);
    }
    else
    {
        printf("Error: Could not parse input.\n");
    }

    char src_id[32];
    char dst_id[32];
    get_ip_in_trie(trie_root, src_id, source);
    get_ip_in_trie(trie_root, dst_id, dest);
    // strncpy(src_ip, "127.0.0.1", BUFFER_SIZE - 1);
    // strncpy(dst_ip, "127.0.0.1", BUFFER_SIZE - 1);
    printf("Source ID: %s\n", src_id);
    printf("Destination ID: %s\n", dst_id);
    char src_ip[BUFFER_SIZE];
    char dst_ip[BUFFER_SIZE];
    int src_port;
    int dst_port;
    sscanf(src_id, "%15[^:]:%d", src_ip, &src_port);
    sscanf(dst_id, "%15[^:]:%d", dst_ip, &dst_port);

    char src_ip_dummy[BUFFER_SIZE];
    char dst_ip_dummy[BUFFER_SIZE];
    strncpy(src_ip_dummy, src_ip, BUFFER_SIZE - 1);
    strncpy(dst_ip_dummy, dst_ip, BUFFER_SIZE - 1);

    src_ip_dummy[BUFFER_SIZE - 1] = '\0';
    dst_ip_dummy[BUFFER_SIZE - 1] = '\0';

    int src_flag = 0;
    int dest_flag = 0;
    if (ends_with_forward_slash(source) == 1)
    {
        src_flag = 1;
    }
    if (ends_with_forward_slash(dest) == 1)
    {
        dest_flag = 1;
    }

    char extracted_paths[100][BUFFER_SIZE]; // Adjust size as needed
    int path_count = 0;
    printf("%s\n", source);
    if (search_trie(trie_root, source, src_id, &src_flag))
    {
        if (trie_root == NULL)
        {
            printf("hi\n");
        }
        printf("hello\n");
        printf("BEFORE CALL %s\n", src_ip_dummy);
        if (ends_with_forward_slash(source))
        {
            extract_all_paths(trie_root, source, extracted_paths, &path_count);
        }
        else
        {
            char filename[1024] = {0};
            extract_filename(source, filename);
            printf("Filename: %s\n", filename);
            printf("Destination:%s\n", dest);
            copy_file(source, response, src_port, dst_port, src_ip_dummy, dst_ip_dummy, source, dest);
            strcat(dest, filename);
            insert_into_trie(trie_root, dest, dst_id, 0);
            snprintf(response, BUFFER_SIZE, "Copy Completed of %s to %s", source, dest);
            printf("[DEBUG] Response inside function: %s\n", response);
            free(source);
            free(dest);
            return;
        }
    }
    printf("BEFORE CALL SRC ID %s\n", src_id);
    char filename[1024] = {0};
    extract_between_last_two_slashes(source, filename);
    printf("Dir name: %s\n", filename);
    strcat(dest, filename);
    printf("%s\n", dest);

    for (int i = 1; i < path_count; i++)
    {
        printf("%d\n", i);
        if (ends_with_forward_slash(extracted_paths[i]))
        {
            int flag = 1;
            char dest_dummy[BUFFER_SIZE];
            strncpy(dest_dummy, dest, BUFFER_SIZE - 1);
            dest_dummy[BUFFER_SIZE - 1] = '\0';
            strcat(dest_dummy, extracted_paths[i]);
            printf("Compelte path %s\n", dest_dummy);
            insert_into_trie(trie_root, dest_dummy, dst_id, 1);
            int status = search_trie(trie_root, dest_dummy, dst_id, &flag);
            printf("STATUS %d\n", status);
        }
        else
        {
            printf("FILE NAME %s\n", extracted_paths[i]);
            int flag = 0;
            char dest_dummy[BUFFER_SIZE];
            strncpy(dest_dummy, dest, BUFFER_SIZE - 1);
            dest_dummy[BUFFER_SIZE - 1] = '\0';
            strcat(dest_dummy, extracted_paths[i]);
            printf("Compelte path %s\n", dest_dummy);
            insert_into_trie(trie_root, dest_dummy, dst_id, 0);

            int status = search_trie(trie_root, dest_dummy, dst_id, &flag);

            printf("STATUS %d\n", status);
            char source_dummy[1024] = {0};
            strcpy(source_dummy, source);
            strcat(source_dummy, extracted_paths[i]);
            printf("Filename to be created :%s\n", source_dummy);
            copy_file(source_dummy, response, src_port, dst_port, src_ip_dummy, dst_ip_dummy, source, dest);
            printf("COPY FILE COMPLETED\n");
        }
    }
    snprintf(response, BUFFER_SIZE, "Copy Completed of %s to %s\n", source, dest);
    printf("[DEBUG] Response inside function: %s\n", response);
    free(source);
    free(dest);
    return;
}

int connect_to_server(const char *ip, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Error creating socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error connecting to server");
        close(sock);
        return -1;
    }

    return sock;
}

void forward_to_storage_server(const char *command, const char *path, char *response)
{
    // Prepare the command buffer
    char command_buffer[BUFFER_SIZE];
    snprintf(command_buffer, BUFFER_SIZE, "%s %s", command, path);
    int selected_server = -1;

    // Handle CREATE command
    if (strcmp(command, "CREATE") == 0)
    {
        // Select a storage server based on availability
        for (int i = 0; i < server_count; i++)
        {
            for (int j = 0; j < storage_servers[i].num_paths; j++)
            {
                if (strcmp(storage_servers[i].paths[j], path) == 0)
                {
                    snprintf(response, BUFFER_SIZE, "Path already exists, try some other name\n");
                    return;
                }
            }
        }
        for (int i = 0; i < server_count; i++)
        {
            if (storage_servers[i].num_paths < MAX_PATHS_PER_SERVER)
            {
                selected_server = i;
                break;
            }
        }
        if (selected_server == -1)
        {
            snprintf(response, BUFFER_SIZE, "Error: All storage servers are full\n");
            return;
        }
        // Connect to the selected storage server
        strcpy(storage_servers[selected_server].paths[storage_servers[selected_server].num_paths], path);
        storage_servers[selected_server].num_paths++;
        total_paths += 1;

        char server_info[BUFFER_SIZE];
        snprintf(server_info, BUFFER_SIZE, "%s:%d", storage_servers[selected_server].ip_address, storage_servers[selected_server].port);
        insert_into_trie(trie_root, path, server_info, 0);
    }

    // Handle DELETE command
    else if (strcmp(command, "DELETE") == 0)
    {
        int found_file = -1;
        for (int i = 0; i < server_count; i++)
        {
            for (int j = 0; j < storage_servers[i].num_paths; j++)
            {
                if (strcmp(storage_servers[i].paths[j], path) == 0)
                {
                    selected_server = i;
                    found_file = j;
                    break;
                }
            }
        }
        if (selected_server != -1 && found_file != -1)
        {
            for (int j = found_file; j < storage_servers[selected_server].num_paths - 1; j++)
            {
                strcpy(storage_servers[selected_server].paths[j], storage_servers[selected_server].paths[j + 1]);
            }
            storage_servers[selected_server].num_paths--;
            total_paths -= 1;
            delete_from_trie(trie_root, path);
        }
        if (selected_server == -1)
        {
            snprintf(response, BUFFER_SIZE, "File/Directory Not Found\n");
            return;
        }
    }

    int storage_sock = connect_to_server(storage_servers[selected_server].ip_address, storage_servers[selected_server].port);
    if (storage_sock < 0)
    {
        snprintf(response, BUFFER_SIZE, "Error: Unable to connect to storage server\n");
        return;
    }
    // Send the command to the storage server
    ssize_t bytes_sent = send(storage_sock, command_buffer, strlen(command_buffer), 0);
    if (bytes_sent <= 0 || bytes_sent < strlen(command_buffer))
    {
        snprintf(response, BUFFER_SIZE, "Error: Failed to send command to storage server\n");
        close(storage_sock);
        return;
    }

    // Receive the response from the storage server
    int bytes_received = recv(storage_sock, response, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0)
    {
        response[bytes_received] = '\0'; // Null-terminate the response
    }
    else if (bytes_received == 0)
    {
        snprintf(response, BUFFER_SIZE, "Error: Storage server closed the connection\n");
    }
    else
    {
        perror("Error receiving data from storage server");
        snprintf(response, BUFFER_SIZE, "Error: Failed to receive data from storage server\n");
    }

    // Close the connection
    close(storage_sock);
}

void view_accessible_paths(int client_sock)
{
    int network_num_paths = htonl(total_paths);
    if (send(client_sock, &network_num_paths, sizeof(network_num_paths), 0) < 0)
    {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < server_count; i++)
    {
        for (int j = 0; j < storage_servers[i].num_paths; j++)
        {
            int path_length = strlen(storage_servers[i].paths[j]) + 1;
            int network_path_length = htonl(path_length);
            if (send(client_sock, &network_path_length, sizeof(network_path_length), 0) < 0)
            {
                perror("Send failed");
                exit(EXIT_FAILURE);
            }
            if (send(client_sock, storage_servers[i].paths[j], path_length, 0) < 0)
            {
                perror("Send failed");
                exit(EXIT_FAILURE);
            }
        }
    }
    printf("All accessible paths sent successfully.\n");
    // logging
    char client_ip[INET_ADDRSTRLEN];
    int client_port;
    get_client_info(client_sock, client_ip, &client_port);
    log_message(client_ip, client_port, "Received INFO Request", "RECEIVED");
}

void handle_client_connection(int client_sock)
{
    char client_ip[INET_ADDRSTRLEN];
    int client_port;
    get_client_info(client_sock, client_ip, &client_port);
    while (1)
    {
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, sizeof(buffer));

        // Receive data from the client
        int bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received == 0)
        {
            // Client disconnected gracefully
            // printf("Client disconnected.\n");
            close(client_sock);
            break; // Exit the loop and end the thread
        }
        else if (bytes_received < 0)
        {
            perror("Error receiving data");
            close(client_sock);
            break; // Exit the loop and end the thread
        }

        buffer[bytes_received] = '\0'; // Null-terminate the received data

        // Process commands
        if (strncmp(buffer, "REGISTER", 8) == 0)
        {
            printf("Storage Connection accepted\n");
            register_storage_server(client_sock, buffer);
        }
        else if (strncmp(buffer, "Client", 6) == 0)
        {
            log_message(client_ip, client_port, "Client connected.", "INFO");
            printf("Client Connected Successfully\n");
        }
        else if (strncmp(buffer, "CREATE", 6) == 0)
        {
            char response[BUFFER_SIZE] = {0};
            // check success
            if (strncmp(buffer, "CREATE SUCCESS", 14) == 0)
            {
                log_message(client_ip, client_port, buffer, "SUCCESS");
            }
            else
            {
                log_message(client_ip, client_port, "File/Directory Creation Request Sent.", "SENT");
                forward_to_storage_server("CREATE", buffer + 7, response); // Skip "CREATE"
                send(client_sock, response, strlen(response), 0);
                char *file_path = buffer + 7; // The path is passed in the buffer after "CREATE"
            }
        }
        else if (strncmp(buffer, "DELETE", 6) == 0)
        {
            if (strncmp(buffer, "DELETE SUCCESS", 14) == 0)
            {
                log_message(client_ip, client_port, buffer, "SUCCESS");
            }
            else
            {
                char response[BUFFER_SIZE] = {0};
                log_message(client_ip, client_port, "File/Directory Deletion Request Sent.", "SENT");
                forward_to_storage_server("DELETE", buffer + 7, response); // Skip "DELETE "
                send(client_sock, response, strlen(response), 0);
            }
        }
        else if (strncmp(buffer, "COPY", 4) == 0)
        {
            char response[BUFFER_SIZE];
            memset(response, 0, BUFFER_SIZE);
            char message[BUFFER_SIZE];
            memset(message, 0, BUFFER_SIZE);
            printf("[DEBUG] Response buffer address in handler: %p\n", response);
            copy_file_directory(client_sock, buffer + 5, response);
            send(client_sock, response, strlen(response) + 1, 0);
            printf("HELLLO\n");
        }
        else if (strncmp(buffer, "HEARTBEAT", 9) == 0)
        {
            char response[BUFFER_SIZE] = {0};
            handle_heartbeat(buffer, response);
            send(client_sock, response, strlen(response), 0);
        }
        else if (strncmp(buffer, "PATHS", 5) == 0)
        {
            log_message(client_ip, client_port, "Received Request for listing the paths", "RECEIVED");
            view_accessible_paths(client_sock);
        }
        else if (strncmp(buffer, "INFO", 4) == 0)
        {
            char file_path[BUFFER_SIZE];
            char response[BUFFER_SIZE] = {0};
            char server_info[BUFFER_SIZE] = {0};
            int is_directory;

            // Extract file path from the INFO command
            if (sscanf(buffer + 5, "%s", file_path) != 1)
            { // Skip "INFO "
                snprintf(response, sizeof(response), "ERROR Invalid request format\n");
                send(client_sock, response, strlen(response), 0);
                continue;
            }
            log_message(client_ip, client_port, "Received INFO Request", "RECEIVED");
            printf("Received INFO request for file path: %s\n", file_path);
            struct CacheNode *cached_node = handle_cache_access(cache, file_path, server_info);
            if (cached_node)
            {
                // printf("ayush: %s",cached_node->file_path);
                snprintf(response, sizeof(response), "SS_DETAILS %s\n", cached_node->storage_server_id);
                send(client_sock, response, strlen(response), 0);
                continue;
            }
            if (search_trie(trie_root, file_path, server_info, &is_directory))
            {
                if (is_directory)
                {
                    snprintf(response, sizeof(response), "ERROR Path is a directory\n");
                }
                else if (server_info[0] != '\0')
                {
                    printf("SS_DETAILS: .%s.\n", server_info);
                    snprintf(response, sizeof(response), "SS_DETAILS %s\n", server_info);
                }
                else
                {
                    snprintf(response, sizeof(response), "ERROR No storage server found\n");
                }
            }
            else
            {
                snprintf(response, sizeof(response), "ERROR Path not found\n");
            }
            add_to_cache(cache, file_path, server_info);
            send(client_sock, response, strlen(response), 0);
            log_message(client_ip, client_port, "Sent INFO Request Details", "SENT");
        }
        else if (strncmp(buffer, "STREAM", 6) == 0)
        {
            // INFO request handling
            char file_path[BUFFER_SIZE];
            char response[BUFFER_SIZE] = {0};
            char server_info[BUFFER_SIZE] = {0};
            int is_directory;

            // Extract file path from the INFO command
            if (sscanf(buffer + 7, "%s", file_path) != 1)
            { // Skip "INFO "
                snprintf(response, sizeof(response), "ERROR Invalid request format\n");
                send(client_sock, response, strlen(response), 0);
                continue;
            }

            printf("Received STREAM request for file path: %s\n", file_path);
            log_message(client_ip, client_port, "Received STREAM Request", "RECEIVED");
            struct CacheNode *cached_node = handle_cache_access(cache, file_path, server_info);
            if (cached_node)
            {
                snprintf(response, sizeof(response), "SS_DETAILS %s\n", cached_node->storage_server_id);
                send(client_sock, response, strlen(response), 0);
                continue;
            }

            // Search in the Trie
            if (search_trie(trie_root, file_path, server_info, &is_directory))
            {
                if (is_directory)
                {
                    snprintf(response, sizeof(response), "ERROR Path is a directory\n");
                }
                else if (server_info[0] != '\0')
                {
                    snprintf(response, sizeof(response), "SS_DETAILS %s\n", server_info);
                }
                else
                {
                    snprintf(response, sizeof(response), "ERROR No storage server found\n");
                }
            }
            else
            {
                snprintf(response, sizeof(response), "ERROR Path not found\n");
            }

            // Send response to client
            add_to_cache(cache, file_path, server_info);
            send(client_sock, response, strlen(response), 0);
            log_message(client_ip, client_port, "Sent STREAM Details", "SENT");
        }
        else if (strncmp(buffer, "READ", 4) == 0)
        {
            char file_path[BUFFER_SIZE];
            char response[BUFFER_SIZE] = {0};
            char server_info[BUFFER_SIZE] = {0};
            int is_directory;

            // Extract file path from the INFO command
            if (sscanf(buffer + 5, "%s", file_path) != 1)
            { // Skip "INFO "
                snprintf(response, sizeof(response), "ERROR Invalid request format\n");
                send(client_sock, response, strlen(response), 0);
                continue;
            }

            printf("Received READ request for file path: %s\n", file_path);
            struct CacheNode *cached_node = handle_cache_access(cache, file_path, server_info);
            if (cached_node)
            {
                // printf("ayush: %s",cached_node->file_path);
                snprintf(response, sizeof(response), "SS_DETAILS %s\n", cached_node->storage_server_id);
                send(client_sock, response, strlen(response), 0);
                continue;
            }
            if (search_trie(trie_root, file_path, server_info, &is_directory))
            {
                if (is_directory)
                {
                    snprintf(response, sizeof(response), "ERROR Path is a directory\n");
                }
                else if (server_info[0] != '\0')
                {
                    printf("SS_DETAILS: .%s.\n", server_info);
                    snprintf(response, sizeof(response), "SS_DETAILS %s\n", server_info);
                }
                else
                {
                    snprintf(response, sizeof(response), "ERROR No storage server found\n");
                }
            }
            else
            {
                snprintf(response, sizeof(response), "ERROR Path not found\n");
            }
            add_to_cache(cache, file_path, server_info);
            send(client_sock, response, strlen(response), 0);
        }
        else if (strncmp(buffer, "WRITE", 5) == 0)
        {
            char file_path[BUFFER_SIZE];
            char response[BUFFER_SIZE] = {0};
            char server_info[BUFFER_SIZE] = {0};
            int is_directory;

            if (sscanf(buffer + 5, "%s", file_path) != 1)
            {
                snprintf(response, sizeof(response), "ERROR Invalid request format\n");
                send(client_sock, response, strlen(response), 0);
                continue;
            }

            printf("Received WRITE request for file path: %s\n", file_path);
            struct CacheNode *cached_node = handle_cache_access(cache, file_path, server_info);
            if (cached_node)
            {
                // printf("ayush: %s",cached_node->file_path);
                snprintf(response, sizeof(response), "SS_DETAILS %s\n", cached_node->storage_server_id);
                send(client_sock, response, strlen(response), 0);
                continue;
            }
            if (search_trie(trie_root, file_path, server_info, &is_directory))
            {
                if (is_directory)
                {
                    snprintf(response, sizeof(response), "ERROR Path is a directory\n");
                }
                else if (server_info[0] != '\0')
                {
                    printf("SS_DETAILS: .%s.\n", server_info);
                    snprintf(response, sizeof(response), "SS_DETAILS %s\n", server_info);
                }
                else
                {
                    snprintf(response, sizeof(response), "ERROR No storage server found\n");
                }
            }
            else
            {
                snprintf(response, sizeof(response), "ERROR Path not found\n");
            }
            add_to_cache(cache, file_path, server_info);
            send(client_sock, response, strlen(response), 0);
        }
        else
        {
            char error[] = "Error: Unknown command\n";
            send(client_sock, error, strlen(error), 0);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP Address> <Port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ip_address = argv[1];
    int port = atoi(argv[2]);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert and set the IP address
    if (inet_pton(AF_INET, ip_address, &server_addr.sin_addr) <= 0)
    {
        fprintf(stderr, "Invalid IP address: %s\n", ip_address);
        close(server_sock);
        return EXIT_FAILURE;
    }

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

    printf("Naming Server is running on IP %s and port %d...\n", ip_address, port);

    // Setup signal handler for graceful shutdown
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    trie_root = create_trie_node();
    cache = init_cache_queue(10);

    pthread_t failure_detection_thread;
    if (pthread_create(&failure_detection_thread, NULL, detect_failures, NULL) != 0)
    {
        perror("Failed to create detect_failures thread");
        exit(EXIT_FAILURE);
    }
    pthread_detach(failure_detection_thread); // Make it a detached thread

    printf("Failure detection thread started.\n");
    while (1)
    {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock < 0)
        {
            perror("Accept failed");
            continue;
        }
        char client_ip[INET_ADDRSTRLEN];
        int client_port;
        get_client_info(client_sock, client_ip, &client_port);

        // Log connection
        // log_message(client_ip, client_port, "Client connected.", "INFO");
        // printf("Connection accepted\n");

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, (void *(*)(void *))handle_client_connection, (void *)(long)client_sock) != 0)
        {
            perror("Thread creation failed");
            close(client_sock);
        }
        else
        {
            pthread_detach(thread_id);
        }
    }
    close(server_sock);
    return 0;
}