#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <asm/page.h>
#include "xcrypt.h"

//#define EXTRA_CREDIT

asmlinkage extern long (*sysptr)(void *arg);

/* 
   Unlinks a file
   reference: http://lxr.fsl.cs.sunysb.edu/linux/source/fs/wrapfs/inode.c#L231 
*/
int unlink(struct file *victim)
{
	int err;
	struct dentry *dir_dentry = NULL;

 	dir_dentry = dget_parent(victim->f_path.dentry);
	mutex_lock_nested(&dir_dentry->d_inode->i_mutex, I_MUTEX_PARENT);
        if(!&dir_dentry->d_inode->i_mutex){
		printk("could not get lock on victim's parent dir\n");
		err = -ENOLCK;
		goto out;
	} 	

	err = vfs_unlink(dir_dentry->d_inode, victim->f_path.dentry, NULL);
	mutex_unlock(&dir_dentry->d_inode->i_mutex);
        
out:
	dput(dir_dentry);
	return err;
}

/* 
   Rename files
   reference: http://lxr.fsl.cs.sunysb.edu/linux/source/fs/wrapfs/inode.c#L231	
*/
int rename(struct file *old, struct file *new)
{
	int err;
	struct dentry *old_dir_dentry = NULL, *new_dir_dentry = NULL, *trap = NULL;

	old_dir_dentry = dget_parent(old->f_path.dentry);
        new_dir_dentry = dget_parent(new->f_path.dentry);
	
	trap = lock_rename(old_dir_dentry, new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == old->f_path.dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == new->f_path.dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(old_dir_dentry->d_inode, old->f_path.dentry, new_dir_dentry->d_inode, new->f_path.dentry, NULL, 0);
out:
	dput(old_dir_dentry);
	dput(new_dir_dentry);
	unlock_rename(new_dir_dentry, old_dir_dentry);
	return err;
}

/* 
   returns the md5 hash value of the unsigned char* passed to it
   reference: http://stackoverflow.com/questions/17283121/correct-usage-of-crypto-api-in-linux
*/
unsigned char *md5hash(unsigned char *key, int keylen)
{
        struct crypto_hash *tfm = NULL;
        struct scatterlist sg;
        struct hash_desc desc;
        unsigned char *hash = NULL;
        int err;

        tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
        if(IS_ERR(tfm)){
                printk("error in cypto_alloc_hash in md5hash\n");
                err = PTR_ERR(tfm);
                goto out_error;
        }

        desc.tfm = tfm;
        desc.flags = 0;
        sg_init_one(&sg, key, keylen);

        hash = kmalloc(16, GFP_KERNEL);
        if(hash == NULL){
                printk("error while kmalloc for hash in md5hash\n");
                err = -ENOMEM;
                goto out_error;
        }

        err = crypto_hash_init(&desc);
        if(err){
                printk("error in crypto_hash_init in md5hash\n");
                goto out_error;
        }

        err = crypto_hash_update(&desc, &sg, keylen);
        if(err){
                printk("error in crypto_hash_update in md5hash\n");
                goto out_error;
        }

        err = crypto_hash_final(&desc, hash);
        if(err){
                printk("error in crypto_hash_final in md5hash\n");
                goto out_error;
        }

        kfree(tfm);
        return hash;

out_error:
        if(!IS_ERR(tfm))
                kfree(tfm);
        kfree(hash);

        return ERR_PTR(err);
}

/* prepares a 16byte iv from page_num and inode number passed to it */
unsigned char *get_iv(u64 page_num, u64 ino)
{
        unsigned char *iv = NULL;

        iv = kmalloc(16, GFP_KERNEL);
	if(iv == NULL){
		printk("error allocating memory in get_iv\n");
		return ERR_PTR(-ENOMEM);
	}
        memcpy(iv, &page_num, 8);
        memcpy(&iv[8], &ino, 8);

        return iv;
}

/* writes the data to the output file after encrypting/decrypting depending on the flags
   reference:  http://www.chronox.de/crypto-API/ch06s02.html
*/
int write(struct file *inf, struct file *temp_outf, char *cipher, unsigned char *keybuf, int keylen, int flags, char **iv)
{
	struct crypto_blkcipher *blkcipher = NULL;
        struct blkcipher_desc desc;
        struct scatterlist sg;
	int err = 0, size_read, size_written;
	char *buf = NULL;	
	mm_segment_t fs = get_fs();
	#ifdef EXTRA_CREDIT
		char *algname = NULL;
		u64 page_num = 1;
	#endif
	
	#ifdef EXTRA_CREDIT
		/* uses the cipher name passed by user and mode as 'ctr'*/
		algname = kmalloc(strlen(cipher)+6, GFP_KERNEL);
		if(algname == NULL){
			printk("error allocating memory for algname\n");
			err = -ENOMEM;
			goto out;
		}
		memcpy(algname, "ctr(", 4);
		memcpy(&algname[4], cipher, strlen(cipher));
		memcpy(&algname[4+strlen(cipher)], ")", 1);
		memcpy(&algname[4+strlen(cipher)+1], "\0", 1);
		blkcipher = crypto_alloc_blkcipher(algname, 0, 0);
	#else
		blkcipher = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	#endif
	
	if(IS_ERR(blkcipher)){
                printk("error in crypto_alloc_blkcipher\n");
                err = PTR_ERR(blkcipher);

		/* in case the err is -ENOENT, it means the cipher name passed by user is invalid */
		if(err == -ENOENT)
			err = -EINVAL;
		goto out;
        }
        err = crypto_blkcipher_setkey(blkcipher, keybuf, keylen);
        if(err){
                printk("error in crypto_blkcipher_setkey\n");
                goto out;
        }
	desc.tfm = blkcipher;
	desc.flags = 0;

        buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if(buf == NULL){
                        printk("error while kmalloc for buf\n");
                        err = -ENOMEM;
                        goto out;
        }
        sg_init_one(&sg, buf, PAGE_SIZE);

        set_fs(get_ds());
        while((size_read = inf->f_op->read(inf, buf, PAGE_SIZE, &inf->f_pos)) > 0){
		#ifdef EXTRA_CREDIT
			crypto_blkcipher_set_iv(blkcipher, *iv, 16);
		#endif

		if(flags == 1)
                        err = crypto_blkcipher_encrypt(&desc, &sg, &sg, PAGE_SIZE);
		else if(flags == 0)
                        err = crypto_blkcipher_decrypt(&desc, &sg, &sg, PAGE_SIZE);

		if(err){
			err = -EIO;
			goto out;
		}

                size_written = temp_outf->f_op->write(temp_outf, buf, size_read, &temp_outf->f_pos);
                if(size_written == -1){
                        printk("failure to write to temp_outf\n");
                        err = -EIO;
                        goto out;
                }

		#ifdef EXTRA_CREDIT
			page_num++;
			memcpy(*iv, &page_num, 8);
		#endif
        }
        if(size_read == -1){
                printk("failure to read from inf\n");
                err = -EIO;
                goto out;
        }

out:
	set_fs(fs);
	if(blkcipher && !IS_ERR(blkcipher))
                kfree(blkcipher);
	kfree(buf);

	return err;
}

/* This function writes the following to the preamble in case the file is being encryped.
   1) cipher name (#ifdef EXTRA_CREDIT)
   2) hashed value of keybuf (the user passed key)
   3) Initial value of the iv which will be used for encryption (#ifdef EXTRA_CREDIT)

   Incase, the file is being decrypted, it does the following:
   1) reads the cipher name and validates it against the cipher name entered while decrypting
   2) reads the hashed key and validates it against the hashed value of the key passed while decrypting
   3) reads the initial value of the iv used while encrypting and sets it to *iv.

   In short, it proccesses the preamble section of the file.
*/
int process_preamble(struct file *inf, struct file *temp_outf, char *cipher, unsigned char *keybuf, int keylen, int flags, char **iv)
{
	unsigned char *keybuf_hash = NULL;
	int err = 0, size_written = 0, size_read = 0;
	char *pcipher = NULL, *pkey = NULL;
	#ifdef EXTRA_CREDIT
		u64 page_num = 1;
	#endif

	keybuf_hash = md5hash(keybuf, keylen);
        if(IS_ERR(keybuf_hash)){
                printk("error in generating md5hash from keybuf\n");
                err = PTR_ERR(keybuf_hash);
                goto out;
        }

        if(flags == 1){
		#ifdef EXTRA_CREDIT
			/* writing the cipher name */
			size_written = temp_outf->f_op->write(temp_outf, cipher, strlen(cipher)+1, &temp_outf->f_pos);
			if(size_written == -1){
				printk("error writing cipher name to preamble\n");
				err = -EIO;
				goto out;
			}
		#endif

		/* writing the hashed value of the user key */
                size_written = temp_outf->f_op->write(temp_outf, keybuf_hash, 16, &temp_outf->f_pos);
                if(size_written == -1){
                        printk("error writing keybuf_hash to preamble\n");
                        err = -EIO;
                        goto out;
                }

		#ifdef EXTRA_CREDIT
			/* writing the initial iv which will be used for encryption */
			*iv = get_iv(page_num, temp_outf->f_inode->i_ino);
			if(IS_ERR(*iv)){
				err = PTR_ERR(*iv);
				goto out;
			}

			size_written = temp_outf->f_op->write(temp_outf, *iv, 16, &temp_outf->f_pos);
			if(size_written == -1){
				printk("error writing iv to preamble\n");
				err = -EIO;
				goto out;
			}
		#endif
        }
	else if(flags == 0){
		#ifdef EXTRA_CREDIT
			/* reads the cipher name and validates it against the cipher name passed by the user */
			pcipher = kmalloc(strlen(cipher)+1, GFP_KERNEL);
			if(pcipher == NULL){
				printk("error while kmalloc for pcipher\n");
				err = -ENOMEM;
				goto out;
			}
			size_read = inf->f_op->read(inf, pcipher, strlen(cipher)+1, &inf->f_pos);
			if(size_read == -1){
				printk("error reading pcipher from preamble\n");
				err = -EIO;
				goto out;
			}
	
			if(strcmp(cipher, pcipher) != 0){
				printk("different cipher used for encryption\n");
				err = -EINVAL;
				goto out;
			}
		#endif

		/* reads the hashed value of the key used while encrypting and validates it against the hashed value of the user passed key. */
		pkey = kmalloc(16, GFP_KERNEL);
                if(pkey == NULL){
                        printk("error while kmalloc for pkey\n");
                        err = -ENOMEM;
                        goto out;
                }

                size_read = inf->f_op->read(inf, pkey, 16, &inf->f_pos);
                if(size_read == -1){
                        printk("error reading pkey from preamble\n");
                        err = -EIO;
                        goto out;
                }

                if(memcmp(keybuf_hash, pkey, keylen)){
                        printk("key passed for decyption is not the same as used while encryption.\n");
                        err = -EINVAL;
                        goto out;
                }

		#ifdef EXTRA_CREDIT
			/* reads the initial value of iv used while encrypting and sets it to *iv */
			*iv = kmalloc(16, GFP_KERNEL);
			if(*iv == NULL){
				printk("error in allocating memory to iv in write\n");
				err = -ENOMEM;
				goto out;
			}

			size_read = inf->f_op->read(inf, *iv, 16, &inf->f_pos);
			if(size_read == -1){
				printk("error reading iv from temp_outf\n");
				err = -EIO;
				goto out;
			}
		#endif
        }

out:
	if(!IS_ERR(keybuf_hash))
                kfree(keybuf_hash);
	kfree(pcipher);
	kfree(pkey);

	return err;	
}

asmlinkage long xcrypt(void *arg)
{
	struct xcrypt *xc = NULL;
	struct filename *infile = NULL, *outfile = NULL;
	struct file *inf = NULL, *outf = NULL, *temp_outf = NULL;
	struct kstat stat_infile, stat_outfile;
	
	unsigned char *keybuf = NULL;
	char *temp = NULL, *cipher = NULL, *iv = NULL;
	int err = 0, flag_outf_existed = 1;	
	
	xc = kmalloc(sizeof(struct xcrypt), GFP_KERNEL);
	if(xc == NULL){
		printk("error while kmalloc for struct xcrypt\n");
		err = -ENOMEM;
		goto out;
	}
	if(copy_from_user(xc, arg, sizeof(struct xcrypt))){
		printk("error copying struct xcrypt from user\n");
		err = -EINVAL;
		goto out;
	}
	
	/* Validate and open infile */
	infile = getname(xc->infile);
	if(IS_ERR(infile)){
		printk("error in getname infile\n");
		err = PTR_ERR(infile);
		goto out;
	}
	err = vfs_stat(xc->infile, &stat_infile);
        if(err){
                printk("error in vfs_stat for infile\n");
                goto out;
        }
	if(!S_ISREG(stat_infile.mode)){
		printk("infile is not a regular file\n");
		err = -EINVAL;
		goto out;
	}
	inf = filp_open(infile->name, O_RDONLY, 0);
        if(IS_ERR(inf)){
                printk("error opening infile\n");
                err = PTR_ERR(inf);
		goto out;
        }
	
	/* Validate and open outfile */
	outfile = getname(xc->outfile); 
	if(IS_ERR(outfile)){
                printk("error in getname outfile\n");
                err = PTR_ERR(outfile);
                goto out;
        }
	err = vfs_stat(xc->outfile, &stat_outfile);
        if(err == 0)
		flag_outf_existed = 1;
	else if(err == -ENOENT){
                flag_outf_existed = 0;
        }
	else{
                printk("error in vfs_stat outfile\n");
                goto out;
        }
	outf = filp_open(outfile->name, O_WRONLY | O_CREAT, 0);
        if(IS_ERR(outf)){
		printk("error opening outfile\n");
                err = PTR_ERR(outf);
        	goto out;
	}

	/* Check if infile and outfile are not same */
	if(stat_infile.ino == stat_outfile.ino){
         	if(strcmp(inf->f_inode->i_sb->s_type->name, outf->f_inode->i_sb->s_type->name) == 0){
                	printk("infile and outfile points to the same file\n");
                        err = -EINVAL;
                        goto out;
		}
	}

	/* Create outfile.tmp for writing */
	temp = kmalloc(strlen(outfile->name)+5, GFP_KERNEL);
	if(temp == NULL){
		err = -ENOMEM;
		printk("error allocating memory to temp\n");
		goto out;
	}
	memcpy(temp, outfile->name, strlen(outfile->name));
	memcpy(&temp[strlen(outfile->name)], ".tmp\0", 5);
	temp_outf = filp_open(temp, O_WRONLY | O_CREAT, stat_infile.mode);
	if(IS_ERR(temp_outf)){
		printk("error opening temp outfile\n");
                err = PTR_ERR(temp_outf);
		goto out;
        }

	/*Validate keybuf and copy it from user*/
	if(xc->keylen == 0){
		printk("hash key length is 0, error.\n");
		err = -EINVAL;
		goto out;
	}
	keybuf = kmalloc(xc->keylen, GFP_KERNEL);
	if(keybuf == NULL){
		printk("error while kmalloc for keybuf\n");
		err = -ENOMEM;
		goto out;
	}
	if(copy_from_user(keybuf, xc->keybuf, xc->keylen)){
		printk("error while copying keybuf from user\n");
		err = -EINVAL;
		goto out;
	}

	/*Validate flags value*/
	if(xc->flags !=0 && xc->flags != 1){
		printk("only flags value of 0 or 1 is supported\n");
		err = -EINVAL;
		goto out;
	}

	#ifdef EXTRA_CREDIT
		/* Validate xcipher and copy from user*/
		if(strlen_user(xc->cipher) == 0){
			printk("cipher name length is 0, error.\n");
			err = -EINVAL;
			goto out;
		}
		cipher = kmalloc(strlen_user(xc->cipher), GFP_KERNEL);
		if(cipher == NULL){
			printk("error while kmalloc for cipher\n");
			err = -ENOMEM;
			goto out;
		}
		if(copy_from_user(cipher, xc->cipher, strlen_user(xc->cipher))){
			printk("error while copying cipher from user\n");
			err = -EINVAL;
			goto out;
		}
	#endif
	
	if((err = process_preamble(inf, temp_outf, cipher, keybuf, xc->keylen, xc->flags, &iv)))
	goto out;	
	
	if((err = write(inf, temp_outf, cipher, keybuf, xc->keylen, xc->flags, &iv)))
		goto out;
	
	/* Closing temp_outf because after renaming I will loose access to it and won't be able to close it.*/
	filp_close(temp_outf, NULL);
	err = rename(temp_outf, outf);
	if(err)
		printk("error renaming temp_outf to outf\n");
out:
	kfree(xc);
	if(infile && !IS_ERR(infile))
		putname(infile);
	if(inf && !IS_ERR(inf))
		filp_close(inf, NULL);
	
	if(outfile && !IS_ERR(outfile))
		putname(outfile);
	if(outf && !IS_ERR(outf))
		filp_close(outf, NULL);
	
	kfree(temp);
	/*Close temp_outf here only if err occurred else it has already been closed above*/
	if(err && temp_outf && !IS_ERR(temp_outf))
		filp_close(temp_outf, NULL);
	
	kfree(keybuf);
	#ifdef EXTRA_CREDIT
		kfree(cipher);
		if(iv && !IS_ERR(iv))
			kfree(iv);
	#endif	
	
	/*Unlink temp_outf and outf seperately here only in case of error, else they have been dealt with above.*/
	if(err && temp_outf && !IS_ERR(temp_outf))
		unlink(temp_outf);
	if(err && !flag_outf_existed)
		unlink(outf);

	return err;
}

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
