# TCP/IP Encrypted Messaging

## Project Motivation
- I wrote this program for a final assignment in my Introduction to Cybersecurity class at Cal Poly Pomona
- I wanted to apply what we learned about encryption and TCP/IP communication into something tangible
- My goal is to elevate this program into an embedded application allowing people to communicate between different devices and networks

## Generating Server Public and Private Keys
- ### openssl genrsa -out private.pem 2048
- ### openssl rsa -in private.pem -pubout -out public.pem

## Generating Client Public and Private Keys
- ### openssl genrsa -out client_private.pem 2048
- ### openssl rsa -in c;ient_private.pem -pubout -out client_public.pem

## Sharing Server Public Key
- ### scp user@server_ip: /path/to/public.pem /path/to/client/code/directory/

## Sharing Client Public Key
- ### scp client_public.pem user@server_ip: /path/to/server/code/directory/

## Compiling and Running the Server
- ### gcc server.c -o server -lcrypto -lssl
- ### ./server

## Compiling and Running the Client
- ### gcc client.c -o client -lcrypto -lssl
- ### ./client
