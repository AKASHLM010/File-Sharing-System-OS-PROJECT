// File Sharing System in C with Chunk-Based Upload, Authentication, Metadata
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h> // For password hashing
#include <pthread.h> // For concurrency

#define CHUNK_SIZE 4096  // 4 KB
#define MAX_USERS 10
#define MAX_META_LEN 256
#define META_FILE "metadata.txt"
#define USER_FILE "users.txt"

// User structure for authentication
typedef struct {
    char username[50];
    char password_hash[SHA256_DIGEST_LENGTH * 2 + 1]; // Hex representation of hash
} User;

// Metadata structure
typedef struct {
    char filename[256];
    char meta[MAX_META_LEN];
} FileMeta;

// Function prototypes
void hash_password(const char *password, char *output);
int authenticate(const char *username, const char *password);
void share_file(const char *source, const char *destination);
void add_metadata(const char *filename, const char *metadata);
void *handle_upload(void *args);
void save_user(const char *username, const char *password);

// Password hashing
void hash_password(const char *password, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password, strlen(password), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// User authentication
int authenticate(const char *username, const char *password) {
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_password(password, hash);

    FILE *user_file = fopen(USER_FILE, "r");
    if (!user_file) {
        perror("Error opening user file");
        return 0;
    }

    char file_username[50], file_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    while (fscanf(user_file, "%s %s", file_username, file_hash) != EOF) {
        if (strcmp(username, file_username) == 0 && strcmp(hash, file_hash) == 0) {
            fclose(user_file);
            return 1;
        }
    }

    fclose(user_file);
    return 0;
}

// Save new user
void save_user(const char *username, const char *password) {
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_password(password, hash);

    FILE *user_file = fopen(USER_FILE, "a");
    if (!user_file) {
        perror("Error opening user file");
        return;
    }

    fprintf(user_file, "%s %s\n", username, hash);
    fclose(user_file);
}

// File sharing function
void share_file(const char *source, const char *destination) {
    int src_fd = open(source, O_RDONLY);
    if (src_fd < 0) {
        perror("Error opening source file");
        return;
    }

    int dest_fd = open(destination, O_WRONLY | O_CREAT, 0644);
    if (dest_fd < 0) {
        perror("Error opening destination file");
        close(src_fd);
        return;
    }

    char buffer[CHUNK_SIZE];
    ssize_t bytes_read, bytes_written;

    while ((bytes_read = read(src_fd, buffer, CHUNK_SIZE)) > 0) {
        bytes_written = write(dest_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            perror("Error writing to file");
            break;
        }
    }

    close(src_fd);
    close(dest_fd);
}

// Add metadata to a file
void add_metadata(const char *filename, const char *metadata) {
    FILE *meta_file = fopen(META_FILE, "a");
    if (!meta_file) {
        perror("Error opening metadata file");
        return;
    }

    fprintf(meta_file, "%s: %s\n", filename, metadata);
    fclose(meta_file);
}

// Threaded file upload handler
void *handle_upload(void *args) {
    char **filenames = (char **)args;
    const char *source = filenames[0];
    const char *destination = filenames[1];

    share_file(source, destination);
    printf("File upload completed: %s -> %s\n", source, destination);

    pthread_exit(NULL);
}

int main() {
    printf("1. Register\n2. Login\nChoose an option: ");
    int choice;
    scanf("%d", &choice);

    char username[50], password[50];
    if (choice == 1) {
        printf("Register\nEnter username: ");
        scanf("%s", username);
        printf("Enter password: ");
        scanf("%s", password);

        save_user(username, password);
        printf("User registered successfully!\n");
    } else if (choice == 2) {
        printf("Login\nEnter username: ");
        scanf("%s", username);
        printf("Enter password: ");
        scanf("%s", password);

        if (!authenticate(username, password)) {
            printf("Authentication failed!\n");
            return 1;
        }
        printf("Authenticated successfully!\n");

        // File upload example
        char source[256], destination[256];
        printf("Enter source file path: ");
        scanf("%s", source);
        printf("Enter destination file path: ");
        scanf("%s", destination);

        pthread_t upload_thread;
        char *filenames[] = {source, destination};
        pthread_create(&upload_thread, NULL, handle_upload, filenames);
        pthread_join(upload_thread, NULL);

        char metadata[MAX_META_LEN];
        printf("Enter metadata for the file: ");
        scanf("%s", metadata);
        add_metadata(destination, metadata);

        printf("File upload and metadata addition completed.\n");
    } else {
        printf("Invalid option!\n");
    }

    return 0;
}

