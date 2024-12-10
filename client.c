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
    int sock = 0;
    struct sockaddr_in serv_addr;

    unsigned char buffer[BUFFER_SIZE] = {0};
    unsigned char encrypted[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];

    // Load client's private key
    FILE *private_key_file = fopen("client_private.pem", "rb");
    if (!private_key_file) {
        perror("Unable to open private key file");
        return -1;
    }
    RSA *private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);

    // Load server's public key
    FILE *public_key_file = fopen("public.pem", "rb");
    if (!public_key_file) {
        perror("Unable to open server's public key file");
        return -1;
    }
    RSA *server_public_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);

    if (!private_key || !server_public_key) {
        fprintf(stderr, "Error loading keys\n");
        return -1;
    }

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Connect to server
    if (inet_pton(AF_INET, "192.168.119.128", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    printf("Connected to server.\n");

    // Communication loop
    while (1) {
        // Get client's message
        printf("You: ");
        fgets((char *)buffer, BUFFER_SIZE, stdin);
        buffer[strcspn((char *)buffer, "\n")] = '\0';  // Remove newline

        // Encrypt the message
        int encrypted_out_len = RSA_public_encrypt(strlen((char *)buffer) + 1, buffer, encrypted, server_public_key, RSA_PKCS1_OAEP_PADDING);
        if (encrypted_out_len == -1) {
            fprintf(stderr, "Encryption error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        // Send encrypted message
        send(sock, encrypted, encrypted_out_len, 0);

        // Check for "disconnect" message
        if (strcmp((char *)buffer, "disconnect") == 0) {
            printf("Disconnecting...\n");
            break;
        }

        // Receive encrypted message
        int encrypted_len = recv(sock, encrypted, sizeof(encrypted), 0);
        if (encrypted_len <= 0) {
            printf("Server disconnected.\n");
            break;
        }

        // Decrypt the message
        int decrypted_len = RSA_private_decrypt(encrypted_len, encrypted, decrypted, private_key, RSA_PKCS1_OAEP_PADDING);
        if (decrypted_len == -1) {
            fprintf(stderr, "Decryption error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        printf("Server: %s\n", decrypted);

        // Check for "disconnect" message
        if (strcmp((char *)decrypted, "disconnect") == 0) {
            printf("Disconnecting...\n");
            break;
        }
    }

    close(sock);
    RSA_free(private_key);
    RSA_free(server_public_key);

    return 0;
}