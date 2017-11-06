//
//  Cipher.h
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@interface Cipher : NSObject {
    NSString* cipherKey;
}

@property (retain) NSString* cipherKey;

- (NSData *) encryptWithData:(NSData *) plainText withKey:(NSString *)key;
- (NSString *) encryptWithString:(NSString *) plainText withKey:(NSString *)key;
- (NSData *) decryptWithData:(NSData *) cipherText withKey:(NSString *)key;
- (NSString *) decryptWithString:(NSString *) cipherText withKey:(NSString *)key;
- (NSData *) transform:(CCOperation) encryptOrDecrypt data:(NSData *) inputData;
+ (NSData *) md5:(NSString *) stringToHash;

@end
