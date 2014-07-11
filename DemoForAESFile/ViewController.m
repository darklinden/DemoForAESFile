//
//  ViewController.m
//  DemoForAESFile
//
//  Created by darklinden on 5/16/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "ViewController.h"
#import "AESCrypt+FileCrypt.h"

#define PATH_DOC [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) objectAtIndex:0]

@implementation ViewController

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return YES;
}

static void hexdump(FILE *f,const char *title,const unsigned char *s,int l)
{
    int n=0;
    
    fprintf(f,"%s",title);
    for( ; n < l ; ++n)
    {
        if((n%16) == 0)
            fprintf(f,"\n%04x",n);
        fprintf(f," %02x",s[n]);
    }
    fprintf(f,"\n");
}

- (IBAction)pBtn_encryptClick:(id)sender
{
    NSString *src = [PATH_DOC stringByAppendingPathComponent:@"src.dmg"];
    NSString *des = [PATH_DOC stringByAppendingPathComponent:@"des.dmg"];
    
    [AESCrypt AESEncrypyFile:src toFile:des withKey:@"qazwsX1"];
}

- (IBAction)pBtn_decryptClick:(id)sender
{
    NSString *des = [PATH_DOC stringByAppendingPathComponent:@"des.dmg"];
    NSString *tmp = [PATH_DOC stringByAppendingPathComponent:@"tmp.dmg"];
    
    [AESCrypt AESDecrypyFile:des toFile:tmp withKey:@"qazwsX1"];
}

- (IBAction)pBtn_checkClick:(id)sender
{
    NSString *des = [PATH_DOC stringByAppendingPathComponent:@"des.dmg"];
    
    if ([AESCrypt AESKey:@"qazwsX1" matchFile:des]) {
        NSLog(@"password is OK");
    }
    else {
        NSLog(@"password is wrong!");
    }
}

@end
