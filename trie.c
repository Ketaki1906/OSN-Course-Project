#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHILDREN 256
#define BUFFER_SIZE 1024

// Define TrieNode structure
struct TrieNode
{
    struct TrieNode *children[MAX_CHILDREN];
    char *storage_server_id; // Pointer to the server ID
    int is_end_of_file;      // 1 if this is the end of a file path
    int is_directory;        // 1 if this node represents a directory
};

// Function prototypes
void insert_into_trie(struct TrieNode *root, const char *path, char *server_id, int is_directory);
int search_trie(const struct TrieNode *root, const char *path, char *server_id, int *is_directory);
void delete_from_trie(struct TrieNode *root, const char *path);
void free_trie(struct TrieNode *root);

// Function to insert into the trie
void insert_into_trie(struct TrieNode *root, const char *path, char *server_id, int is_directory)
{
    struct TrieNode *current = root;
    while (*path)
    {
        if (!current->children[(unsigned char)*path])
        {
            current->children[(unsigned char)*path] = calloc(1, sizeof(struct TrieNode));
        }
        current = current->children[(unsigned char)*path];
        path++;
    }
    current->is_end_of_file = !is_directory; // Set file or directory status
    current->is_directory = is_directory;
    current->storage_server_id = strdup(server_id); 
}

// Function to search the trie
int search_trie(const struct TrieNode *root, const char *path, char *server_info, int *is_directory)
{
    const struct TrieNode *current = root;
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
        *is_directory = 1;
        server_info[0] = '\0'; // Directories do not have a server ID
        return 1;              // Directory found
    }
    if (current->is_end_of_file)
    {
        *is_directory = 0;
        if (current->storage_server_id)
        {
            strncpy(server_info, current->storage_server_id, BUFFER_SIZE - 1);
            server_info[BUFFER_SIZE - 1] = '\0'; // Null-terminate the string
        }
        else
        {
            server_info[0] = '\0'; // No server ID found
        }
        return 1; // File found
    }
    return 0; // Not a valid path
}

// Function to delete from the trie
void delete_from_trie(struct TrieNode *root, const char *path)
{
    struct TrieNode *current = root;
    struct TrieNode *stack[strlen(path)];
    int depth = 0;

    // Traverse the path and push nodes onto the stack
    while (*path)
    {
        if (!current->children[(unsigned char)*path])
        {
            return; // Path not found
        }
        stack[depth++] = current;
        current = current->children[(unsigned char)*path];
        path++;
    }

    if (current->is_end_of_file || current->is_directory)
    {
        current->is_end_of_file = 0;
        current->is_directory = 0;
        if (current->storage_server_id)
        {
            free(current->storage_server_id);
            current->storage_server_id = NULL;
        }
        // Clean up unused nodes
        while (depth > 0 && current != root)
        {
            struct TrieNode *parent = stack[--depth];
            unsigned char last_char = (unsigned char)*(--path);
            int has_children = 0;

            for (int i = 0; i < MAX_CHILDREN; i++)
            {
                if (current->children[i])
                {
                    has_children = 1;
                    break;
                }
            }

            if (!has_children && !current->is_end_of_file && !current->is_directory)
            {
                free(current);
                parent->children[last_char] = NULL;
                current = parent;
            }
            else
            {
                break;
            }
        }
    }
}

// Function to free the entire trie
void free_trie(struct TrieNode *root)
{
    if (!root)
        return;

    for (int i = 0; i < MAX_CHILDREN; i++)
    {
        if (root->children[i])
        {
            free_trie(root->children[i]);
        }
    }
    if (root->storage_server_id)
    {
        free(root->storage_server_id);
        root->storage_server_id = NULL;
    }
    free(root);
}

void extract_paths(struct TrieNode *node, char *current_path, int depth, char paths[][BUFFER_SIZE], int *path_count)
{
    if (!node)
        return;

    // Check if current node marks a directory or file
    if (node->is_directory || node->is_end_of_file)
    {
        current_path[depth] = '\0'; // Null-terminate the current path
        strncpy(paths[*path_count], current_path, BUFFER_SIZE - 1);
        paths[*path_count][BUFFER_SIZE - 1] = '\0'; // Null-terminate safely
        (*path_count)++;
    }

    // Recursively traverse each child
    for (int i = 0; i < MAX_CHILDREN; i++)
    {
        if (node->children[i])
        {
            current_path[depth] = (char)i; // Append current character
            extract_paths(node->children[i], current_path, depth + 1, paths, path_count);
        }
    }
}

void extract_all_paths(struct TrieNode *trie_root, const char *source, char paths[][BUFFER_SIZE], int *path_count)
{
    struct TrieNode *current = trie_root;
    // Traverse the trie to the node corresponding to 'source'
    while (*source)
    {
        if (!current->children[(unsigned char)*source])
        {
            printf("Source path not found in trie.\n");
            return;
        }
        current = current->children[(unsigned char)*source];
        source++;
    }

    // Start collecting paths from the source node
    char current_path[BUFFER_SIZE];
    strncpy(current_path, source, BUFFER_SIZE - 1);
    extract_paths(current, current_path, strlen(source), paths, path_count);
}

// Test cases
// int main() {
//     struct TrieNode *trie_root = calloc(1, sizeof(struct TrieNode));

//     // Insert files and directories
//     insert_into_trie(trie_root, "/file1", "server1", 0);
//     insert_into_trie(trie_root, "/dir1", NULL, 1);
//     insert_into_trie(trie_root, "/dir1/file2", "server2", 0);

//     // Search for paths
//     char *server_id;
//     int is_directory;

//     if (search_trie(trie_root, "/file1", &server_id, &is_directory)) {
//         printf("Found: /file1, Server ID: %s, Is Directory: %d\n", server_id, is_directory);
//     } else {
//         printf("/file1 not found.\n");
//     }

//     if (search_trie(trie_root, "/dir1", &server_id, &is_directory)) {
//         printf("Found: /dir1, Is Directory: %d\n", is_directory);
//     } else {
//         printf("/dir1 not found.\n");
//     }

//     if (search_trie(trie_root, "/dir1/file2", &server_id, &is_directory)) {
//         printf("Found: /dir1/file2, Server ID: %s, Is Directory: %d\n", server_id, is_directory);
//     } else {
//         printf("/dir1/file2 not found.\n");
//     }

//     // Delete paths
//     delete_from_trie(trie_root, "/file1");
//     if (!search_trie(trie_root, "/file1", &server_id, &is_directory)) {
//         printf("/file1 successfully deleted.\n");
//     }

//     delete_from_trie(trie_root, "/dir1/file2");
//     if (!search_trie(trie_root, "/dir1/file2", &server_id, &is_directory)) {
//         printf("/dir1/file2 successfully deleted.\n");
//     }

//     // Free the trie
//     free_trie(trie_root);
//     return 0;
// }
