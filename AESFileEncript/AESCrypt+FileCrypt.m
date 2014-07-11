//
//  AESCrypt.m
//  DemoForPdfToText
//
//  Created by DarkLinden on 12/6/11.
//  Copyright (c) 2011 darklinden. All rights reserved.
//

#import "AESCrypt+FileCrypt.h"
#import "aes.h"
#import "evp.h"
#import "sha.h"
#import "rand.h"
#import "err.h"

#import <assert.h>
#import <stdio.h> 

#define _LARGE_FILES

@implementation AESCrypt (FileCrypt)

+ (BOOL)AESEncrypyFile:(NSString*)src toFile:(NSString*)des withKey:(NSString*)strkey
{
    //salt
    unsigned char iv[16] = {1};
    AES_KEY key;
    int ret;
    
    int len;
    
    unsigned char buffer_in[256] = {0x0};
    unsigned char buffer_out[257] = {0x0};
    
    FILE *file_src = fopen([src UTF8String], "r");
	FILE *file_des = fopen([des UTF8String], "wb");
    
    if(!file_src)
    {
        return NO;  
    }
    
    if(!file_des)
    {
        return NO;  
    }
    
    ret = AES_set_encrypt_key((const unsigned char *)[strkey UTF8String], 128, &key);   
    if (ret < 0) 
    {
//        printf("L%d: AES_set_encrypt_key error!\n", __LINE__);    
        return NO;  
    }
    
    memset(iv, 0x0, 16); 
    
    while( (len = (int)fread(buffer_in, sizeof(unsigned char), 256, file_src)) == 256)
    {
        AES_cbc_encrypt(buffer_in, buffer_out, len, &key, iv, AES_ENCRYPT);
        len = (int)fwrite(buffer_out, sizeof(unsigned char), len, file_des);
        if(len < 0)
        {
            return NO;
        }
    }
    
    if(len)
    {
        AES_cbc_encrypt(buffer_in, buffer_out, len, &key, iv, AES_ENCRYPT);
        ret = len;
        len = (len & 0xFFFFFFF0) + ((len & 0x0F) ? 16 : 0);
        *(buffer_out + len) = (len - ret);
        len = (int)fwrite(buffer_out, sizeof(unsigned char), len + 1, file_des);
        if(len < 0)
        {
            return NO;
        }
    }
    
    //appen file key check
    unsigned char fappen_in[16] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0};
    unsigned char fappen_out[32] = {0x0};
    unsigned char fappen_iv[16] = {0x0};
    memset(fappen_out, 0x0, 32);
    memset(fappen_iv, 0x0, 16);
    
    AES_cbc_encrypt(fappen_in, fappen_out, 16, &key, fappen_iv, AES_ENCRYPT);
    
    len = (int)fwrite(fappen_out, sizeof(unsigned char), 32, file_des);
    if(len < 0)
    {
        return NO;
    }
//    for(int i = 0; i < 32; ++i) printf("%02x ", fappen_out[i]);
        
    fclose(file_src);
    fclose(file_des);
    return YES;
}

+ (BOOL)AESDecrypyFile:(NSString*)src toFile:(NSString*)des withKey:(NSString*)strkey
{
    //salt
    unsigned char iv[16] = {1};
    AES_KEY key;
    int ret;
    int len;
    
    unsigned char buffer_in[256] = {0x0};
    unsigned char buffer_out[257] = {0x0};
    
    FILE *file_src = fopen([src UTF8String], "r");
	FILE *file_des = fopen([des UTF8String], "wb");
    
    if(!file_src)
    {
        return NO;  
    }
    
    if(!file_des)
    {
        return NO;  
    }
    
    ret = AES_set_decrypt_key((const unsigned char *)[strkey UTF8String], 128, &key);
    if (ret < 0 ) 
    {   
        return NO;
    }
    
    memset(iv, 0x0, 16);
    len = (int)fread(buffer_in, sizeof(unsigned char), 256, file_src);
    while( len == 256)
    {
        unsigned char buffer_in_tmp[256] = {0x0};
        memcpy(buffer_in_tmp, buffer_in, 256);
        
        ret = (int)fread(buffer_in, sizeof(unsigned char), 256, file_src);
        
//        printf("buffer_in \n");
//        for(int i = 0; i < ret; ++i) printf("%02x ", buffer_in[i]);
//        printf("buffer_in_tmp \n");
//        for(int i = 0; i < len; ++i) printf("%02x ", buffer_in_tmp[i]);
        
        if(ret < 32)
        {
            len = len + ret - 32;
            len -= (unsigned char) (buffer_in_tmp[len - 1]);
            len -= 1;
            
            AES_cbc_encrypt(buffer_in_tmp, buffer_out, len, &key, iv, AES_DECRYPT);
            
//            for(int i = 0; i < len; ++i) printf("%02x ", buffer_out[i]);
        }
        else if(ret == 32)
        {
            AES_cbc_encrypt(buffer_in_tmp, buffer_out, len - 2, &key, iv, AES_DECRYPT);
        }
        else if(ret == 33)
        {            
            AES_cbc_encrypt(buffer_in_tmp, buffer_out, len, &key, iv, AES_DECRYPT);
            
//            for(int i = 0; i < len; ++i) printf("%02x ", buffer_out[i]);
            
            len -= (unsigned char) (buffer_in[0]);
        }
        else {
            AES_cbc_encrypt(buffer_in_tmp, buffer_out, len, &key, iv, AES_DECRYPT);
        }
        
        len = (int)fwrite(buffer_out, sizeof(unsigned char), len, file_des);
        if(len < 0)
        {
            return NO;
        }
        len = ret;    
    }
    
    if(len > 33)
    {
        AES_cbc_encrypt(buffer_in, buffer_out, len - 32, &key, iv, AES_DECRYPT);
        len -= (unsigned char)(buffer_in[len - 33]);
        len -= 33;
        len = (int)fwrite(buffer_out, sizeof(unsigned char), len, file_des);
        if(len < 0)
        {
            return NO;
        }
    }
    
    fclose(file_src);
    fclose(file_des);
    return YES;
}

+ (BOOL)AESKey:(NSString*)strKey matchFile:(NSString*)filePath
{
    int ret;
    int len;
    AES_KEY key;
    FILE *file_src;
    BOOL retValue = NO;
    unsigned char buffer_in[32] = {0x0};
    unsigned char buffer_out[33] = {0x0};
    unsigned char iv[16] = {1};
    
    memset(buffer_in, 0x0, 32);
    memset(buffer_out, 0x0, 33);
    memset(iv, 0x0, 16);
    
    file_src = fopen([filePath UTF8String], "r");
    fseeko(file_src, -32, SEEK_END);
    
    ret = (int)fread(buffer_in, sizeof(unsigned char), 32, file_src);
    if (ret < 0) return NO;
    len = ret;
    
//    for(int i = 0; i < ret; ++i) printf("%02x ", buffer_in[i]);
    
    ret = AES_set_decrypt_key((const unsigned char *)[strKey UTF8String], 128, &key);
    if (ret < 0 ) return NO;
    AES_cbc_encrypt(buffer_in, buffer_out, 32, &key, iv, AES_DECRYPT);
    
//    for(int i = 0; i < 32; ++i) printf("%02x ", buffer_out[i]);
    
    if (buffer_out[0] == 0x1
        && buffer_out[1] == 0x2
        && buffer_out[2] == 0x3
        && buffer_out[3] == 0x4
        && buffer_out[4] == 0x5
        && buffer_out[5] == 0x6
        && buffer_out[6] == 0x7
        && buffer_out[7] == 0x8
        && buffer_out[8] == 0x7
        && buffer_out[9] == 0x6
        && buffer_out[10] == 0x5
        && buffer_out[11] == 0x4
        && buffer_out[12] == 0x3
        && buffer_out[13] == 0x2
        && buffer_out[14] == 0x1
        && buffer_out[15] == 0x0) {
        retValue = YES;
    }
    
    fclose(file_src);
    return retValue;
}

/*
 #define BIG_TEST_SIZE 1024
 char rkey[AES_BLOCK_SIZE+1];
 AES_KEY key;
 char plaintext[BIG_TEST_SIZE];
 char ciphertext[BIG_TEST_SIZE];
 char checktext[BIG_TEST_SIZE];
 char iv[AES_BLOCK_SIZE*4];
 char saved_iv[AES_BLOCK_SIZE*4];
 
 RAND_pseudo_bytes((unsigned char*)rkey, sizeof rkey);
 strcpy(iv,"0123456789012345");
 
 
 memcpy(saved_iv, 0x0, sizeof saved_iv);
 
 strcpy((char*)plaintext,"string to make the random number generator think it has entropy1111111111");
 
 // Straight encrypt
 
 AES_set_encrypt_key((unsigned char*)rkey, 8*AES_BLOCK_SIZE, &key);
 hexdump(stdout, "plaintext", (unsigned char*)plaintext, strlen(plaintext));
 
 AES_cbc_encrypt((unsigned char*)plaintext, (unsigned char*)ciphertext, strlen(plaintext), &key, (unsigned char*)iv,AES_ENCRYPT);
 hexdump(stdout, "ciphertext", (unsigned char*)ciphertext, strlen(plaintext));
 
 // Straight decrypt
 
 AES_set_decrypt_key((unsigned char*)rkey, 8*AES_BLOCK_SIZE, &key);
 memcpy(saved_iv, 0x0, sizeof saved_iv);
 AES_cbc_encrypt((unsigned char*)ciphertext, (unsigned char*)checktext, strlen(plaintext), &key, (unsigned char*)iv,AES_DECRYPT);
 hexdump(stdout, "checktext", (unsigned char*)checktext, strlen(plaintext));
 */

@end
