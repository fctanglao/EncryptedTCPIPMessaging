#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 256

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    unsigned char buffer[BUFFER_SIZE] = {0};
    unsigned char encrypted[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];

    // Load server's private key
    FILE *private_key_file = fopen("private.pem", "rb");
    if (!private_key_file) {
        perror("Unable to open private key file");
        return -1;
    }
    RSA *private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);

    // Load client's public key
    FILE *public_key_file = fopen("client_public.pem", "rb");
    if (!public_key_file) {
        perror("Unable to open client's public key file");
        return -1;
    }
    RSA *client_public_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);

    if (!private_key || !client_public_key) {
        fprintf(stderr, "Error loading keys\n");
        return -1;
    }

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return -1;
    }

    // Listen for connections
    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        close(server_fd);
        return -1;
    }

    printf("Server is listening on port %d...\n", PORT);

    if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("Accept failed");
        close(server_fd);
        return -1;
    }

    printf("Client connected.\n");

    // Communication loop
    while (1) {
        // Receive encrypted message
        int encrypted_len = recv(client_socket, encrypted, sizeof(encrypted), 0);
        if (encrypted_len <= 0) {
            printf("Client disconnected.\n");
            break;
        }

        // Decrypt the message
        int decrypted_len = RSA_private_decrypt(encrypted_len, encrypted, decrypted, private_key, RSA_PKCS1_OAEP_PADDING);
        if (decrypted_len == -1) {
            fprintf(stderr, "Decryption error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        printf("Client: %s\n", decrypted);

        // Check for "disconnect" message
        if (strcmp((char *)decrypted, "disconnect") == 0) {
            printf("Disconnecting...\n");
            break;
        }

        // Get server's message
        printf("You: ");
        fgets((char *)buffer, BUFFER_SIZE, stdin);
        buffer[strcspn((char *)buffer, "\n")] = '\0';  // Remove newline

        // Encrypt the message
        int encrypted_out_len = RSA_public_encrypt(strlen((char *)buffer) + 1, buffer, encrypted, client_public_key, RSA_PKCS1_OAEP_PADDING);
        if (encrypted_out_len == -1) {
            fprintf(stderr, "Encryption error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        // Send encrypted message
        send(client_socket, encrypted, encrypted_out_len, 0);

        // Check for "disconnect" message
        if (strcmp((char *)buffer, "disconnect") == 0) {
            printf("Disconnecting...\n");
            break;
        }
    }

    close(client_socket);
    close(server_fd);
    RSA_free(private_key);
    RSA_free(client_public_key);

    return 0;
}
