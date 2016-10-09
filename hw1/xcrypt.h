#ifndef _XCRYPT_H
#define _XCRYPT_H

#define __NR_xcrypt 359

struct xcrypt
{
	char *infile;
	char *outfile;
	char *cipher;
	unsigned char *keybuf;
	int keylen;
	int flags;
};

#endif
