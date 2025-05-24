#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/select.h>
#include "errorcode.h"

#define BUFFER_SIZE 1024
#define FLUSH_CHUNK_SIZE 512

void handle_error(int error_code)
{
    switch (error_code)
    {
    case ERR_INVALID_ARGUMENTS:
        fprintf(stderr, "Error: Invalid arguments provided.\n");
        break;
    case ERR_SOCKET_CREATION:
        fprintf(stderr, "Error: Failed to create socket.\n");
        break;
    case ERR_INVALID_IP:
        fprintf(stderr, "Error: Invalid IP address format.\n");
        break;
    case ERR_CONNECTION_FAILED:
        fprintf(stderr, "Error: Failed to connect to server.\n");
        break;
    case ERR_SEND_FAILED:
        fprintf(stderr, "Error: Failed to send data to server.\n");
        break;
    case ERR_RECEIVE_FAILED:
        fprintf(stderr, "Error: Failed to receive data from server.\n");
        break;
    case ERR_FILE_NOT_FOUND:
        fprintf(stderr, "Error: Requested file not found on server.\n");
        break;
    case ERR_INVALID_RESPONSE:
        fprintf(stderr, "Error: Invalid response received from server.\n");
        break;
    case ERR_PIPE_FAILURE:
        fprintf(stderr, "Error: Failed to open pipe for audio playback.\n");
        break;
    case ERR_SERVER_DISCONNECT:
        fprintf(stderr, "Error: Server disconnected unexpectedly.\n");
        break;
    case ERR_MEMORY_ALLOCATION:
        fprintf(stderr, "Error: Memory allocation failure.\n");
        break;
    case ERR_UNSUPPORTED_ACTION:
        fprintf(stderr, "Error: Unsupported user action.\n");
        break;
    case ERR_WRITE_FAILURE:
        fprintf(stderr, "Error: Failed to write data to storage server.\n");
        break;
    case ERR_READ_FAILURE:
        fprintf(stderr, "Error: Failed to read data from storage server.\n");
        break;
    default:
        fprintf(stderr, "Error: Unknown error occurred (Code: %d).\n", error_code);
        break;
    }

    exit(error_code);
}

int copy_files_or_directories(naming_sock)
{
    char source[BUFFER_SIZE];
    char c;
    printf("Enter source path:");
    scanf("%s", &source);
    while ((c = getchar()) != '\n' && c != EOF)
        ; // Clear input buffer

    char destination[BUFFER_SIZE];
    printf("Enter destination path:");
    scanf("%s", &destination);
    while ((c = getchar()) != '\n' && c != EOF)
        ; // Clear input buffer

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "COPY %s %s", source, destination);
    send(naming_sock, message, strlen(message), 0);
    char response[BUFFER_SIZE];
    int bytes_received = recv(naming_sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0)
    {
        response[bytes_received] = '\0'; // Null-terminate response
    }
    printf("Response from Naming Server: %s\n", response);
}

void create_or_delete_file_folder(int sock)
{
    char action[BUFFER_SIZE], path[BUFFER_SIZE], name[BUFFER_SIZE];
    char c;

    printf("Enter Action (create/delete): ");
    scanf("%s", action);
    while ((c = getchar()) != '\n' && c != EOF)
        ; // Clear input buffer

    if (strcmp(action, "create") == 0)
    {
        printf("Enter Name of File/Folder to Create: ");
        scanf("%s", name);
        while ((c = getchar()) != '\n' && c != EOF)
            ; // Clear input buffer
    }

    char message[BUFFER_SIZE];
    memset(message, 0, sizeof(message));
    if (strcmp(action, "create") == 0)
    {
        snprintf(message, sizeof(message), "CREATE %s", name);
    }
    else
    {
        printf("Enter Name of File/Folder to Delete: ");
        scanf("%s", name);
        while ((c = getchar()) != '\n' && c != EOF)
            ;
        snprintf(message, sizeof(message), "DELETE %s", name);
    }

    send(sock, message, strlen(message), 0);

    char response[BUFFER_SIZE];
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0)
    {
        response[bytes_received] = '\0'; // Null-terminate response
    }
    printf("Response from Naming Server: %s\n", response);
}

int connect_to_storage_server(const char *ip, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0)
    {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection to Storage Server failed");
        close(sock);
        return -1;
    }

    printf("Connected to Storage Server at %s:%d\n", ip, port);
    return sock;
}

int parse_and_connect(const char *server_info)
{
    char ip_address[BUFFER_SIZE];
    int port;

    // Parse IP address and port from the string
    if (sscanf(server_info, "%[^:]:%d", ip_address, &port) != 2)
    {
        fprintf(stderr, "Error: Invalid server info format. Expected ip_add:port\n");
        return -1;
    }

    printf("Parsed IP Address: %s, Port: %d\n", ip_address, port);

    // Connect to the storage server
    return connect_to_storage_server(ip_address, port);
}

void receive_and_print_file(int server_sock)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    while (1)
    {
        // Receive data from the server
        bytes_received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received < 0)
        {
            perror("Failed to receive data from server");
            return; // Exit on error
        }

        // Null-terminate the buffer to safely print as a string
        buffer[bytes_received] = '\0';

        // Check for the "EOF" marker indicating the end of the file
        if (strstr(buffer, "EOF") != NULL)
        {
            // Remove the "EOF" marker before printing the last chunk
            char *eof_position = strstr(buffer, "EOF");
            if (eof_position != NULL)
            {
                *eof_position = '\0';
            }
            printf("%s", buffer);
            break;
        }

        // Print the received chunk
        printf("%s", buffer);
    }

    printf("\nFile received and printed successfully.\n");
}

void read_file(int naming_sock)
{
    char file_path[BUFFER_SIZE];
    char c;

    // Step 1: Get the file path to query information about
    printf("Enter the file path to read from: ");
    scanf("%s", file_path);
    while ((c = getchar()) != '\n' && c != EOF)
        ; // Clear input buffer

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "READ %s", file_path);
    printf("Request: %s\n", message);

    // Step 2: Send the INFO request to the Naming Server
    if (send(naming_sock, message, strlen(message), 0) < 0)
    {
        perror("Failed to send READ request to Naming Server");
        return;
    }

    // Step 3: Receive the response from the Naming Server
    char response[BUFFER_SIZE];
    int bytes_received = recv(naming_sock, response, sizeof(response) - 1, 0);
    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            printf("Connection to Naming Server closed.\n");
        }
        else
        {
            perror("Failed to receive response from Naming Server");
        }
        return;
    }

    response[bytes_received] = '\0'; // Null-terminate the response
    printf("Response from Naming Server: %s\n", response);

    // Step 4: Parse response to get storage server details
    char file_info[BUFFER_SIZE];
    if (sscanf(response, "SS_DETAILS %[^\n]", file_info) != 1)
    {
        printf("Invalid response from Naming Server.\n");
        return;
    }

    printf("Connecting to Storage Server with details: %s\n", file_info);

    // Step 5: Connect to the Storage Server
    int storage_sock = parse_and_connect(file_info);
    if (storage_sock < 0)
    {
        fprintf(stderr, "Error: Failed to connect to the Storage Server.\n");
        return;
    }

    // Step 6: Send the STREAM request to the Storage Server
    if (send(storage_sock, message, strlen(message), 0) < 0)
    {
        perror("Failed to send READ request to Storage Server");
        close(storage_sock);
        return;
    }
    receive_and_print_file(storage_sock);
    close(storage_sock);
}

ssize_t send_all(int sock, const char *buffer, size_t length)
{
    size_t total_sent = 0;
    while (total_sent < length)
    {
        ssize_t bytes_sent = send(sock, buffer + total_sent, length - total_sent, 0);
        if (bytes_sent < 0)
        {
            perror("Failed to send data");
            return -1;
        }
        total_sent += bytes_sent;
    }
    return total_sent;
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

void write_to_the_given_file(int server_sock, int flag)
{
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    if (flag == 1)
    {
        // Current behavior: send line by line
        printf("Enter content to write to the file (type 'EOF' to finish):\n");
        while ((nread = getline(&line, &len, stdin)) != -1)
        {
            if (strncmp(line, "EOF", 3) == 0)
            {
                break;
            }

            if (send_all(server_sock, line, nread) < 0)
            {
                fprintf(stderr, "Failed to send line content.\n");
                free(line);
                return;
            }
        }

        // Send EOF marker
        const char *end_message = "EOF";
        if (send_all(server_sock, end_message, strlen(end_message)) < 0)
        {
            fprintf(stderr, "Failed to send EOF marker.\n");
        }
    }
    else
    {

        printf("Enter content to write to the file (type 'EOF' to finish):\n");

        size_t total_size = 0;
        char *buffer = NULL;

        fd_set read_fds;
        struct timeval timeout;

        while ((nread = getline(&line, &len, stdin)) != -1)
        {
            if (strncmp(line, "EOF", 3) == 0)
            {
                break;
            }

            // Allocate or reallocate buffer for accumulated input
            char *new_buffer = realloc(buffer, total_size + nread + 1); // +1 for null terminator
            if (!new_buffer)
            {
                fprintf(stderr, "Memory allocation failed.\n");
                free(buffer);
                free(line);
                return;
            }
            buffer = new_buffer;

            // Copy the new line into the buffer
            memcpy(buffer + total_size, line, nread);
            total_size += nread;
            buffer[total_size] = '\0'; // Null-terminate

            // If flag is 0, flush in chunks
            if (flag == 0)
            {
                // If the accumulated size exceeds FLUSH_CHUNK_SIZE, send a chunk
                if (total_size >= FLUSH_CHUNK_SIZE)
                {
                    if (send_all(server_sock, buffer, FLUSH_CHUNK_SIZE) < 0)
                    {
                        fprintf(stderr, "Failed to send chunk.\n");
                        free(buffer);
                        free(line);
                        return;
                    }
                    // Shift the remaining data down by FLUSH_CHUNK_SIZE
                    memmove(buffer, buffer + FLUSH_CHUNK_SIZE, total_size - FLUSH_CHUNK_SIZE);
                    total_size -= FLUSH_CHUNK_SIZE; // Adjust the size
                }

                // Return control to terminal with select() to keep terminal responsive
                FD_ZERO(&read_fds);
                FD_SET(STDIN_FILENO, &read_fds);
                timeout.tv_sec = 0;       // Set timeout for non-blocking
                timeout.tv_usec = 100000; // 100ms timeout

                if (select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &timeout) > 0)
                {
                    // Terminal input is ready, just proceed with next iteration
                    continue;
                }
            }
        }

        // Send any remaining content in the buffer if flag == 0
        if (flag == 0 && total_size > 0)
        {
            if (send_all(server_sock, buffer, total_size) < 0)
            {
                fprintf(stderr, "Failed to send remaining content.\n");
            }
        }

        // Send EOF marker
        const char *end_message = "EOF";
        if (send_all(server_sock, end_message, strlen(end_message)) < 0)
        {
            fprintf(stderr, "Failed to send EOF marker.\n");
        }

        free(buffer);
        free(line);

        printf("Content sent to the server.\n");
    }
}

void write_to_file(int naming_sock, int flag)
{
    char file_path[BUFFER_SIZE];
    char c;

    // Step 1: Get the file path to query information about
    printf("Enter the file path to write to: ");
    scanf("%s", file_path);
    while ((c = getchar()) != '\n' && c != EOF)
        ; // Clear input buffer

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "WRITE %s", file_path);
    printf("Request: %s\n", message);

    // Step 2: Send the INFO request to the Naming Server
    if (send(naming_sock, message, strlen(message), 0) < 0)
    {
        perror("Failed to send WRITE request to Naming Server");
        return;
    }

    // Step 3: Receive the response from the Naming Server
    char response[BUFFER_SIZE];
    int bytes_received = recv(naming_sock, response, sizeof(response) - 1, 0);
    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            printf("Connection to Naming Server closed.\n");
        }
        else
        {
            perror("Failed to receive response from Naming Server");
        }
        return;
    }

    response[bytes_received] = '\0'; // Null-terminate the response
    printf("Response from Naming Server: %s\n", response);

    // Step 4: Parse response to get storage server details
    char file_info[BUFFER_SIZE];
    if (sscanf(response, "SS_DETAILS %[^\n]", file_info) != 1)
    {
        printf("Invalid response from Naming Server.\n");
        return;
    }

    printf("Connecting to Storage Server with details: %s\n", file_info);

    // Step 5: Connect to the Storage Server
    int storage_sock = parse_and_connect(file_info);
    if (storage_sock < 0)
    {
        fprintf(stderr, "Error: Failed to connect to the Storage Server.\n");
        return;
    }

    // Step 6: Send the STREAM request to the Storage Server
    if (send(storage_sock, message, strlen(message), 0) < 0)
    {
        perror("Failed to send WRITE request to Storage Server");
        close(storage_sock);
        return;
    }

    write_to_the_given_file(storage_sock, flag);
    close(storage_sock);
}

void info_file_to_nm(int naming_sock)
{
    char file_path[BUFFER_SIZE];
    char c;

    // Step 1: Get the file path to query information about
    printf("Enter the file path to get information: ");
    scanf("%s", file_path);
    while ((c = getchar()) != '\n' && c != EOF)
        ; // Clear input buffer

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "INFO %s", file_path);
    printf("Request: %s\n", message);

    // Step 2: Send the INFO request to the Naming Server
    if (send(naming_sock, message, strlen(message), 0) < 0)
    {
        perror("Failed to send INFO request to Naming Server");
        return;
    }

    // Step 3: Receive the response from the Naming Server
    char response[BUFFER_SIZE];
    int bytes_received = recv(naming_sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0)
    {
        response[bytes_received] = '\0'; // Null-terminate the response
        printf("Response from Naming Server: %s\n", response);

        // Parse and display the response
        char file_info[BUFFER_SIZE];
        if (sscanf(response, "SS_DETAILS %[^\n]", file_info) == 1)
        {
            printf("Server Details: %s\n", file_info);

            // Step 4: Connect to the Storage Server
            int storage_sock = parse_and_connect(file_info);
            if (storage_sock < 0)
            {
                fprintf(stderr, "Error: Failed to connect to the Storage Server.\n");
                return;
            }

            // Step 5: Send the same request to the Storage Server
            if (send(storage_sock, message, strlen(message), 0) < 0)
            {
                perror("Failed to send request to Storage Server");
                close(storage_sock);
                return;
            }

            // Step 6: Receive the response from the Storage Server
            char storage_response[BUFFER_SIZE];
            int storage_bytes_received = recv(storage_sock, storage_response, sizeof(storage_response) - 1, 0);
            if (storage_bytes_received > 0)
            {
                storage_response[storage_bytes_received] = '\0'; // Null-terminate the response
                printf("Response from Storage Server: %s\n", storage_response);
            }
            else if (storage_bytes_received == 0)
            {
                printf("Connection to Storage Server closed.\n");
            }
            else
            {
                perror("Failed to receive response from Storage Server");
            }

            // Close the connection to the Storage Server
            close(storage_sock);
        }
        else
        {
            printf("Invalid response from Naming Server.\n");
        }
    }
    else if (bytes_received == 0)
    {
        printf("Connection to Naming Server closed.\n");
    }
    else
    {
        perror("Failed to receive response from Naming Server");
    }
}

void receive_and_play_music(int server_sock)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    FILE *pipe = popen("mpv --no-terminal --quiet -", "w"); // Open mpv in pipe mode
    if (!pipe)
    {
        perror("Failed to open mpv");
        handle_error(9);
    }

    printf("Receiving music data and playing with mpv...\n");

    while ((bytes_received = recv(server_sock, buffer, sizeof(buffer), 0)) > 0)
    {
        // Check for EOF
        if (bytes_received >= 3 && strncmp(buffer, "EOF", 3) == 0)
        {
            printf("Received EOF. Stopping playback.\n");
            break;
        }

        // Write to mpv pipe
        if (fwrite(buffer, 1, bytes_received, pipe) != (size_t)bytes_received)
        {
            perror("Failed to write to mpv");
            break;
        }
    }

    if (bytes_received < 0)
    {
        perror("Failed to receive music data");
    }

    pclose(pipe); // Close the pipe to stop playback
}

void stream_audio(int naming_sock)
{
    char file_path[BUFFER_SIZE];
    char c;

    // Step 1: Get the file path to stream
    printf("Enter the file path to stream: ");
    scanf("%s", file_path);
    while ((c = getchar()) != '\n' && c != EOF)
        ; // Clear input buffer

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "STREAM %s", file_path);
    printf("Request: %s\n", message);

    // Step 2: Send the STREAM request to the Naming Server
    if (send(naming_sock, message, strlen(message), 0) < 0)
    {
        perror("Failed to send STREAM request to Naming Server");
        return;
    }

    // Step 3: Receive the response from the Naming Server
    char response[BUFFER_SIZE];
    int bytes_received = recv(naming_sock, response, sizeof(response) - 1, 0);
    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            printf("Connection to Naming Server closed.\n");
        }
        else
        {
            perror("Failed to receive response from Naming Server");
        }
        return;
    }

    response[bytes_received] = '\0'; // Null-terminate the response
    printf("Response from Naming Server: %s\n", response);

    // Step 4: Parse response to get storage server details
    char file_info[BUFFER_SIZE];
    if (sscanf(response, "SS_DETAILS %[^\n]", file_info) != 1)
    {
        printf("Invalid response from Naming Server.\n");
        return;
    }

    printf("Connecting to Storage Server with details: %s\n", file_info);

    // Step 5: Connect to the Storage Server
    int storage_sock = parse_and_connect(file_info);
    if (storage_sock < 0)
    {
        fprintf(stderr, "Error: Failed to connect to the Storage Server.\n");
        return;
    }

    // Step 6: Send the STREAM request to the Storage Server
    if (send(storage_sock, message, strlen(message), 0) < 0)
    {
        perror("Failed to send STREAM request to Storage Server");
        close(storage_sock);
        return;
    }

    // Step 7: Receive and play the music from the Storage Server
    receive_and_play_music(storage_sock);

    // Close the connection to the Storage Server
    close(storage_sock);
}

void list_accessible_paths(int naming_sock)
{
    char message[] = "PATHS";
    send(naming_sock, message, strlen(message), 0);

    int network_num_paths;
    if (recv(naming_sock, &network_num_paths, sizeof(network_num_paths), 0) < 0)
    {
        perror("Receive failed");
        handle_error(6);
    }
    int found_paths = ntohl(network_num_paths);
    printf("Total Accessible Paths = %d\n", found_paths);

    for (int i = 0; i < found_paths; i++)
    {
        int network_path_length;
        if (recv(naming_sock, &network_path_length, sizeof(network_path_length), 0) < 0)
        {
            perror("Receive failed");
            handle_error(6);
        }
        int path_length = ntohl(network_path_length);
        char file_path[BUFFER_SIZE];
        if (recv(naming_sock, file_path, path_length, 0) < 0)
        {
            perror("Receive failed");
            handle_error(6);
        }
        printf("Path %s\n", file_path);
    }
    printf("All accessible paths displayed\n");
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <Naming Server IP> <Naming Server Port>\n", argv[0]);
        handle_error(1);
    }

    const char *naming_server_ip = argv[1];
    int naming_server_port = atoi(argv[2]);

    int naming_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (naming_sock < 0)
    {
        perror("Socket creation failed");
        handle_error(2);
    }

    struct sockaddr_in naming_server_addr = {0};
    naming_server_addr.sin_family = AF_INET;
    naming_server_addr.sin_port = htons(naming_server_port);

    if (inet_pton(AF_INET, naming_server_ip, &naming_server_addr.sin_addr) <= 0)
    {
        fprintf(stderr, "Invalid IP address: %s\n", naming_server_ip);
        close(naming_sock);
        handle_error(3);
    }

    if (connect(naming_sock, (struct sockaddr *)&naming_server_addr, sizeof(naming_server_addr)) < 0)
    {
        perror("Connection to Naming Server failed");
        close(naming_sock);
        handle_error(4);
    }
    
    printf("Connected to Naming Server at %s:%d\n", naming_server_ip, naming_server_port);
    send(naming_sock,"Client Connected Successfully",30,0);

    int storage_sock = -1;

    while (1)
    {
        printf("\nChoose an option:\n");
        printf("1. Copy Files or Directories\n");
        printf("2. Create or Delete Files/Folders\n");
        printf("3. Read a file\n");
        printf("4. Write to a file\n");
        printf("5. Get File Permission and Size\n");
        printf("6. Stream a Audio File\n");
        printf("7. List all Accessible Paths\n");
        printf("8. Exit\n");
        printf("Enter your choice: ");

        int choice;
        scanf("%d", &choice);
        if (choice == 1)
        {
            copy_files_or_directories(naming_sock);
        }
        else if (choice == 2)
        {
            create_or_delete_file_folder(naming_sock);
        }
        else if (choice == 3)
        {
            read_file(naming_sock);
        }
        else if (choice == 4)
        {
            printf("Do you want sync? (y/n): ");
            char response[2];      // Array to store the input ('y' or 'n')
            scanf("%s", response); // Read user input as a string

            // Compare using strcmp (for string comparison)
            if (strcmp(response, "y") == 0)
            {
                write_to_file(naming_sock, 1); // Sync mode
            }
            else if (strcmp(response, "n") == 0)
            {
                write_to_file(naming_sock, 0); // Async mode
            }
            else
            {
                printf("Invalid input. Please enter 'y' or 'n'.\n");
            }
        }
        else if (choice == 5)
        {
            info_file_to_nm(naming_sock);
        }
        else if (choice == 6)
        {
            stream_audio(naming_sock);
        }
        else if (choice == 7)
        {
            list_accessible_paths(naming_sock);
        }
        else if (choice == 8)
        {
            if (storage_sock >= 0)
            {
                close(storage_sock);
                printf("Disconnected from Storage Server\n");
            }
            close(naming_sock);
            printf("Disconnected from Naming Server\n");
            handle_error(10);
        }
        else
        {
            printf("Invalid choice. Please try again.\n");
        }
    }
    return 0;
}