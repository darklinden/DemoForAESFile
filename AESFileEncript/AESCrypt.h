//
//  AESCrypt.h
//  DemoForPdfToText
//
//  Created by DarkLinden on 12/6/11.
//  Copyright (c) 2011 darklinden. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AESCrypt : NSObject
+ (BOOL)AESEncrypyFile:(NSString*)src toFile:(NSString*)des withKey:(NSString*)strkey;
+ (BOOL)AESDecrypyFile:(NSString*)src toFile:(NSString*)des withKey:(NSString*)strkey;
+ (BOOL)AESKey:(NSString*)strKey matchFile:(NSString*)filePath;
@end

