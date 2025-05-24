#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256
#define SERVER_ID_SIZE 256

// Node structure for the linked list
struct CacheNode {
    char file_path[BUFFER_SIZE];
    char storage_server_id[SERVER_ID_SIZE];
    struct CacheNode *next;
};

// Queue structure for caching
struct CacheQueue {
    struct CacheNode *front, *rear;
    size_t capacity, size;
};

// Initialize a cache queue
struct CacheQueue *init_cache_queue(size_t capacity) {
    struct CacheQueue *queue = calloc(1, sizeof(struct CacheQueue));
    if (!queue) {
        perror("Failed to initialize cache queue");
        exit(EXIT_FAILURE);
    }
    queue->capacity = capacity;
    queue->size = 0;
    queue->front = queue->rear = NULL;
    return queue;
}

// Cache hit handler
struct CacheNode *handle_cache_hit(struct CacheQueue *queue, const char *file_path, char *server_id) {
    struct CacheNode *current = queue->front;
    struct CacheNode *prev = NULL;

    while (current) {
        if (strcmp(current->file_path, file_path) == 0) {
            // Copy the server ID and null-terminate
            strncpy(server_id, current->storage_server_id, SERVER_ID_SIZE - 1);
            server_id[SERVER_ID_SIZE - 1] = '\0';

            // If already at the rear, return the node
            if (current == queue->rear) {
                return current;
            }

            // Reorganize the node to the rear
            if (prev) {
                prev->next = current->next;
            } else {
                queue->front = current->next;
            }
            queue->rear->next = current;
            queue->rear = current;
            current->next = NULL;

            return current;
        }
        prev = current;
        current = current->next;
    }

    // Cache miss
    return NULL;
}

void remove_from_cache(struct CacheQueue *queue) {
    if (!queue->front) {
        return; // Cache is already empty
    }

    struct CacheNode *to_remove = queue->front;
    queue->front = queue->front->next;

    if (!queue->front) {
        queue->rear = NULL; // Cache becomes empty
    }

    free(to_remove);
    queue->size--;
}

// Add a new file to the cache
void add_to_cache(struct CacheQueue *queue, const char *file_path, char *server_id) {
    printf("bello :%s\n",server_id);
    struct CacheNode *new_node = calloc(1, sizeof(struct CacheNode));
    if (!new_node) {
        perror("Failed to allocate memory for cache node");
        exit(EXIT_FAILURE);
    }

    // Set the new node's data
    strncpy(new_node->file_path, file_path, BUFFER_SIZE - 1);
    // new_node->file_path[BUFFER_SIZE - 1] = '\0';
    strncpy(new_node->storage_server_id, server_id, SERVER_ID_SIZE - 1);
    printf("solved: %s\n",new_node->storage_server_id);
    
    new_node->next = NULL;

    // Add to the rear of the queue
    if (!queue->rear) {
        // If the queue is empty
        queue->front = queue->rear = new_node;
    } else {
        queue->rear->next = new_node;
        queue->rear = new_node;
    }

    queue->size++;

    // Check capacity and evict if necessary
    if (queue->size > queue->capacity) {
        remove_from_cache(queue);
    }
}

// Remove the least recently used file from the cache


// Cache access handler (main function for clients)
struct CacheNode *handle_cache_access(struct CacheQueue *queue, const char *file_path, char *server_id) {
    // Check if the file is in the cache

    struct CacheNode *hit_node = handle_cache_hit(queue, file_path, server_id);
    if (hit_node) {
        return hit_node; // Cache hit
    }

    // Cache miss: Add the file to the cache
    // add_to_cache(queue, file_path, server_id);
    return NULL; // Return NULL for a cache miss
}

// Print cache contents (for debugging)
void print_cache(struct CacheQueue *queue) {
    printf("Cache contents (front to rear):\n");
    struct CacheNode *current = queue->front;
    while (current) {
        printf("File: %s, Server ID: %s\n", current->file_path, current->storage_server_id);
        current = current->next;
    }
    printf("\n");
}

// Free the cache memory
void free_cache_queue(struct CacheQueue *queue) {
    struct CacheNode *current = queue->front;
    while (current) {
        struct CacheNode *next = current->next;
        free(current);
        current = next;
    }
    free(queue);
}

// int main() {
//     // Initialize the cache with a capacity of 3
//     struct CacheQueue *cache = init_cache_queue(3);

//     // Test Case 1: Add files to the cache
//     char server_id[SERVER_ID_SIZE];
//     printf("Adding files to the cache:\n");
//     strncpy(server_id, "Server1", SERVER_ID_SIZE - 1);
//     handle_cache_access(cache, "/file1.txt", server_id);
//     strncpy(server_id, "Server2", SERVER_ID_SIZE - 1);
//     handle_cache_access(cache, "/file2.txt", server_id);
//     strncpy(server_id, "Server3", SERVER_ID_SIZE - 1);
//     handle_cache_access(cache, "/file3.txt", server_id);
//     print_cache(cache);

//     // Test Case 2: Access a file already in the cache (cache hit)
//     printf("Accessing /file2.txt (cache hit):\n");
//     strncpy(server_id, "", SERVER_ID_SIZE - 1); // Clear server ID
//     handle_cache_access(cache, "/file2.txt", server_id);
//     printf("Updated server_id: %s\n", server_id);
//     print_cache(cache);

//     // Test Case 3: Add a new file (cache miss, triggers eviction)
//     printf("Adding /file4.txt (cache miss, triggers eviction):\n");
//     strncpy(server_id, "Server4", SERVER_ID_SIZE - 1);
//     handle_cache_access(cache, "/file4.txt", server_id);
//     print_cache(cache);

//     // Test Case 4: Access an evicted file (cache miss)
//     printf("Accessing /file1.txt (cache miss):\n");
//     strncpy(server_id, "", SERVER_ID_SIZE - 1); // Clear server ID
//     handle_cache_access(cache, "/file1.txt", server_id);
//     printf("Updated server_id: %s\n", server_id);
//     print_cache(cache);

//     // Test Case 5: Add another file to test the capacity again
//     printf("Adding /file5.txt (another eviction):\n");
//     strncpy(server_id, "Server5", SERVER_ID_SIZE - 1);
//     handle_cache_access(cache, "/file5.txt", server_id);
//     print_cache(cache);

//     // Free cache memory
//     free_cache_queue(cache);

//     return 0;
// }
