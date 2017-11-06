#import <Foundation/Foundation.h>
#import "NSData+CommonCrypto.h"
#import "Cipher.h"

int main (int argc, const char * argv[])
{

    //WITH NSData
    NSString *firstString = @"https://www.apple.com/";
    NSString *password = @"eighteen.letters.";
    Cipher *ci = [[Cipher alloc]init];
    NSData *encryptedFirstStringData = [ci encryptWithData:[ firstString dataUsingEncoding:NSUTF8StringEncoding ] withKey:password];
    NSString *encryptedString = [encryptedFirstStringData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSLog(@"encryptWithData %@",encryptedString);


    NSString *secondEncryptedString = @"jH3ul1GY20lFvA/EFtsrB177IaWcuyQ457cfUA24Brk=";
    NSData *base64DecodedData = [[NSData alloc] initWithBase64EncodedString:secondEncryptedString options:0];
    NSData *decryptedData = [ci decryptWithData:base64DecodedData  withKey:password];
    NSString* decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    NSLog(@"decryptWithData %@",decryptedString);

    //WITH NSString
    NSLog(@"encryptWithString %@",[ci encryptWithString:firstString withKey:password]);
    NSLog(@"decryptWithString %@",[ci decryptWithString:secondEncryptedString withKey:password]);

    return 0;
}
