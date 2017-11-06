//
//  Cipher.m
//

#import "Cipher.h"

@implementation Cipher
@synthesize cipherKey;

- (NSData *) encryptWithData:(NSData *) plainText withKey:(NSString *)key {
    [self setCipherKey:key];
    return [self transform:kCCEncrypt data:plainText];
}

- (NSString *) encryptWithString:(NSString *) plainText withKey:(NSString *)key {
    return [[self encryptWithData:[plainText dataUsingEncoding:NSUTF8StringEncoding ] withKey:key]base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSData *) decryptWithData:(NSData *) cipherText withKey:(NSString *)key {
    [self setCipherKey:key];
    return [self transform:kCCDecrypt data:cipherText];
}

- (NSString *) decryptWithString:(NSString *) cipherText withKey:(NSString *)key{
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:cipherText options:0];
    return [[NSString alloc] initWithData:[self decryptWithData:decodedData withKey:key] encoding:NSUTF8StringEncoding];
}

- (NSData *) transform:(CCOperation) encryptOrDecrypt data:(NSData *) inputData {
    // kCCKeySizeAES128 = 16 bytes
    // CC_MD5_DIGEST_LENGTH = 16 bytes
    NSData* secretKey = [Cipher md5:cipherKey];
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = kCCSuccess;
    uint8_t iv[kCCBlockSizeAES128];
    memset((void *) iv, 0x0, (size_t) sizeof(iv));
    status = CCCryptorCreate(encryptOrDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                             [secretKey bytes], kCCKeySizeAES128, iv, &cryptor);
    if (status != kCCSuccess) {
        return nil;
    }
    size_t bufsize = CCCryptorGetOutputLength(cryptor, (size_t)[inputData length], true);
    void * buf = malloc(bufsize * sizeof(uint8_t));
    memset(buf, 0x0, bufsize);
    size_t bufused = 0;
    size_t bytesTotal = 0;
    status = CCCryptorUpdate(cryptor, [inputData bytes], (size_t)[inputData length],
                             buf, bufsize, &bufused);
    if (status != kCCSuccess) {
        free(buf);
        CCCryptorRelease(cryptor);
        return nil;
    }
    bytesTotal += bufused;
    status = CCCryptorFinal(cryptor, buf + bufused, bufsize - bufused, &bufused);
    if (status != kCCSuccess) {
        free(buf);
        CCCryptorRelease(cryptor);
        return nil;
    }
    bytesTotal += bufused;
    CCCryptorRelease(cryptor);
    return [NSData dataWithBytesNoCopy:buf length:bytesTotal];
}

+ (NSData *) md5:(NSString *) stringToHash {
    const char *src = [stringToHash UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(src, strlen(src), result);
    return [NSData dataWithBytes:result length:CC_MD5_DIGEST_LENGTH];
}

@end

