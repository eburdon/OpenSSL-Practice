default:  client server 

client: myclient.c 
	gcc -g -Wall -o myclient myclient.c -lcrypto -lssl

server:
	gcc -g -Wall -o server server.c base64.c -lcrypto -lssl
