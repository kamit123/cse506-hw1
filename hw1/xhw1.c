#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>
#include "xcrypt.h"

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

//#define EXTRA_CREDIT

int main(int argc, char *const argv[])
{
	extern char *optarg;
	extern int optind;
	struct xcrypt *xc = NULL;
	int c, err;
	char *password = NULL;
	MD5_CTX context;
	unsigned char digest[16];
	
	#ifdef EXTRA_CREDIT
	char *pattern = "hp:edc:";
	char *help = "./[outputfile] -p password -c cipher_name -[e|d] infile outfile";
	#else
	char *pattern = "hp:ed";
	char *help = "./[outputfile] -p password -[e|d] infile outfile";
	#endif
	
	xc = malloc(sizeof(struct xcrypt));
	if(xc == NULL){
		printf("Error allocating memory to xcrypt\n");
		exit(-1);
	}
	xc->flags = -1;
	xc->cipher = NULL;

	while((c = getopt(argc, argv, pattern)) != -1){
		switch(c){
		case 'h':
			printf("Usage: %s\n ", help);
			err = 0;
			goto out;
		case 'p':
			password = argv[optind-1];
			break;
		case 'e':
			if(xc->flags == -1)
				xc->flags = 1;
			else{
				printf("only one of either -e or -d can be specified.\n");
				err = -1;	
				goto out;
			}
			break;
		case 'd':
			if(xc->flags == -1)
				xc->flags = 0;
			else{   
                                printf("only one of either -e or -d can be specified.\n");
                                err = -1;
				goto out;
                        }
			break;
		#ifdef EXTRA_CREDIT
		case 'c':
			xc->cipher = argv[optind-1];
			break;
		#endif
		case '?':
			printf("Error: Unrecognized options in arguments\n");
			err = -1;
			goto out;
		}
	}

	/* Validates for mandatory parameters */
	if(xc->flags == -1){
                printf("either -e or -d must be specified\n");
                err = -1;
                goto out;
        }

	if(password == NULL){
		printf("-p is a mandatory parameter\n");
		err = -1;
		goto out;
	}
	if(xc->flags == 1 && strlen(password) < 6){
		printf("password length too small!\n");
		err = -1;
		goto out;
	}

	#ifdef EXTRA_CREDIT
		if(xc->cipher == NULL){
			printf("-c argument is mandatory\n");
			err = -1;
			goto out;
		}
	#endif

	/* Making sure infile and outfile arguments are present and
	   assign them to struct xcrypt*/
	if(optind+2 > argc){
		printf("missing arguments\n");
		err = -1;
		goto out;
	}
	xc->infile = argv[optind];
	xc->outfile = argv[optind+1];

	/* 
	   Initialize the keybuf with hash of the user passphrase
	   reference: http://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
	*/
	if(!MD5_Init(&context)){
		printf("Error in MD5_Init (generating hash from password)\n");
		err = -1;
		goto out;
	}
	if(!MD5_Update(&context, password, strlen(password))){
                printf("Error in MD5_Init (generating hash from password)\n");
                err = -1;
		goto out;
        }
	if(!MD5_Final(digest, &context)){
                printf("Error in MD5_Init (generating hash from password)\n");
                err = -1;
		goto out;
        }
	xc -> keybuf = digest;
	xc->keylen = 16;

	err = syscall(__NR_xcrypt, xc);
	if (err == 0)
		printf("syscall returned %d\n", err);
	else
		printf("syscall returned %d (errno=%d)\n", err, errno);
		perror("Result of xcrypt syscall");

out:
	free(xc);
	exit(err);
}
