/*
 * SENG 360	Fall 2014
 * 	Assignment 04
 *
 * 	Erika Burdon
 * 	VOO 723 793
 * 	eburdon@uvic.ca
 * 			
 *
 * My program must open the SSL connection and provide certificate to
 * 	the server.
 * OpenSSL will negotiate key exchange, and do all the encryption. 
 * Protocol:
 * 	B --> A:	personalID
 * 	A --> B:	message
 *
 * I must submit this source code, the received message, and answers
 * 	to Part 6 of the assignment doc. 
 *
 * Compile:  gcc -g -Wall -o myclient myclient.c -lcrypto -lssl
 * Run:	./myclient w.cs.uvic.ca 5555  qZmwCj5Oeh/NB8EdContcrMcvDA	
 * 									*/

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <assert.h>

/* SSL includes */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "base64.h"
#include "common.h"
#include "rc4.h"

/* Command line args; Stored for reference*/
#define PORT            5555
#define SERVERHOST 	w.cs.uvic.ca
#define PID64		qZmwCj5Oeh/NB8EdContcrMcvDA

#define BUF_SIZE	1024


/* All: SSL_FILTYPE_PEM; I must provide my certificate and key! */
const char clientCertFile[] = "/home/eburdon/eburdon/SENG360/Assignments/04/04_assign_files/client.crt";
const char clientKeyFile[] = "/home/eburdon/eburdon/SENG360/Assignments/04/04_assign_files/clientKey.pem";
////
const char serverCertFile[] = "/home/eburdon/eburdon/SENG360/Assignments/04/04_assign_files/server.crt";
const char serverKeyFile[] = "/home/eburdon/eburdon/SENG360/Assignments/04/04_assign_files/serverKey.pem";



/** Initialize the SSL (+ functions)
 * 	borrowed from StackOverflow:
 * 	http://stackoverflow.com/questions/7698488/turn-a-simple-
 * 	  socket-into-an-ssl-socket      */
void init_SSL()
{
   OpenSSL_add_all_algorithms(); /* Load and Register cryptos */
   SSL_load_error_strings();	/* Load all errors messages */

   if ( SSL_library_init() <0 ) {
	fprintf(stderr, "Could not initalize the OpenSSL library!\n");
   }	

   ERR_load_crypto_strings();
}


/* End SSL session */
void shutdown_SSL(SSL *ssl)
{
   SSL_shutdown(ssl);
   SSL_free(ssl);
}


/* Initalize socket address;
 * Shamelessly stolen from Assignment 2's oldClient.c */
void init_sockaddr (struct sockaddr_in *name,
                    const char *hostname, unsigned short int port)
{
  struct hostent *hostinfo;

  bzero(name, sizeof( *name));

  name->sin_family = AF_INET;
  name->sin_port = htons (port);

  hostinfo = gethostbyname (hostname);
  if (hostinfo == NULL) {
    fprintf (stderr, "Unknown host %s.\n", hostname);
    exit (EXIT_FAILURE);
  }
  name->sin_addr = *(struct in_addr *) hostinfo->h_addr;
}


/* Open standard TCP socket
 * Shamelessly stolen from Assignment 2's oldClient.c*/
int open_socket(char *hostname, int port)
{
  /* Client Information */
  int sock;
  struct sockaddr_in servername;

  fprintf(stderr, "Opening connection to [%s][%d]\n", hostname, port);

  /* Create the TCP socket */
  sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    perror ("socket (client)");
    exit (EXIT_FAILURE);
  }

  /* Connect to the server.   */
  init_sockaddr (&servername, hostname, port);
  if (connect (sock,
              (struct sockaddr *) &servername,
               sizeof (servername)) != 0) 
  {
    /* If connection fails, notify user... */
    perror ("connect (client)");
    exit (EXIT_FAILURE);
  }

  fprintf(stderr, "Connected to socket descriptor %d\n",sock);
  return sock;
}


/* Set context certificate and private key files; Confirm they match */
void use_certificates(SSL_CTX *ctx, const char *clcert, const char *clkey)
{
    if(SSL_CTX_use_certificate_file(ctx, clcert, SSL_FILETYPE_PEM)<=0) {
    // if (!(SSL_CTX_use_certificate_chain_file(ctx, clcert))) {
    // NOTE: Both _file & _chain_file work produce correct output!
	fprintf(stderr, "\nuse_certificate error!\n");
    }
    if ((SSL_CTX_use_PrivateKey_file(ctx, clkey, SSL_FILETYPE_PEM))<=0){
	fprintf(stderr, "\nuse_PrivateKey error!\n");
    }

    /* Confirm files match CA */    
    if (!(SSL_CTX_check_private_key(ctx))){
	fprintf(stderr, "Client certificate and (private) key do not match!\n");
	exit(1);
    } else {
	fprintf(stderr, "Client certificate and private key matched to server!\n");
    }
}

/** ------------------ SOLUTION -----------------------*/
int main(int argc, char *argv[])
{
    /* --- General Vars */
    int sock;			// Socket/Connection src
    char buffer[BUF_SIZE+1];	// Send/Receive buffer
    int bytesRead;		// read() buffer length
    
    /* --- Command line/User input vars */
    char *myId;
    char *hostname;
    int port = 0;

    /* --- SSL vars */
    SSL_CTX *ctx;	/* Holds defaults for connections */
    SSL *ssl;	/* One strcut per connections; CORE OBJ */


    /* --- LOAD PROGRAM
     * 	   Assign 04 has the same command line args as Assign 02 */
    if (argc != 4) {
       fprintf(stderr, "%s <hostname> <port> <userid>\n", argv[0]);
       exit(1);
     }
    port = atoi(argv[2]);
    hostname = argv[1];
    myId = argv[3];
   

    /* --- Initialize ssl functions */
    init_SSL();

    /* --- From A02: Make standard TCP socket connection */
    sock = open_socket(hostname, port);

    /* --- Create SSL context */
    if ((ctx = SSL_CTX_new(SSLv3_client_method())) == NULL)
    {
	fprintf(stderr, "Unable to make new SSL context structure\n");
        exit(1);
    }
    fprintf(stdout, "SSL context successfully made\n");

    /* --- Set unique client certificate and key files for connection */
    use_certificates(ctx, clientCertFile, clientKeyFile);

    /* --- Create SSL connection state object (with all prev. info) */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);      /* Attach the socket descriptor */

    
    /* --- FINALLY! Connect performs handshake with server; Comm channel 
     * (socket) must already be set. Returns 1 on success */
    if ( SSL_connect(ssl) != 1 )
    {
  	fprintf(stderr, "Error: Could not build a SSL connection\n");
    } else {
	fprintf(stdout, "Successful SLL connection to server!\n");

	/* B--> A: Send my info to server*/
	SSL_write(ssl, myId, strlen(myId));

	/* Verify server's certificate chain */
	if(!(SSL_CTX_load_verify_locations(ctx, 0, serverCertFile))) {
	    printf("Problem verifying!\n");
	}
	printf("Server certificate verified!\n");

    	/* Get my message from server (A --> B: message */
        bytesRead = SSL_read(ssl, buffer, BUF_SIZE);

        fprintf(stdout, "\nBuffer [%i bytes] dumped below:\n\n", bytesRead);
 	printf("%s\n\n", buffer);
    }

    /* -- Closing routines*/
    shutdown_SSL(ssl);
    close(sock);
    exit(EXIT_SUCCESS);
}

