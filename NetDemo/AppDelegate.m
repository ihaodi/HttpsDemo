//
//  AppDelegate.m
//  NetDemo
//
//  Created by 好迪 on 16/3/3.
//  Copyright © 2016年 好迪. All rights reserved.
//

#import "AppDelegate.h"
#import <AFNetworking/AFNetworking.h>
#import "AFgzipRequestSerializer/AFgzipRequestSerializer.h"
#import <MKNetworkKit/MKNetworkKit.h>
#define _AFNETWORKING_ALLOW_INVALID_SSL_CERTIFICATES_ 1

@interface AppDelegate ()<NSURLSessionDelegate>
@property (nonatomic, strong)NSURLConnection *connection;
@property (nonatomic, strong)NSArray *trustedCertificates;

@property (nonatomic, strong)AFHTTPSessionManager *manager;

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    
    //系统原生
//    [self test3];
    
//    [NSURLRequest allowsAnyHTTPSCertificateForHost:@"ddddd"];
    
    //afnetwork 3.0
    [self testConnect1];
    
    //mknetwork
//    [self testMK];
    
    return YES;
}

- (void)test3{
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
    
    NSURL *url = [NSURL URLWithString:@"https://sevnew.welian.com"];
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
    [request setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    [request setHTTPShouldHandleCookies:NO];
    [request setTimeoutInterval:30];
    [request setHTTPMethod:@"GET"];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSString *message = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSLog(@"%@", message);
    }];
    
    [task resume];
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    NSString *method = challenge.protectionSpace.authenticationMethod;
    NSLog(@"%@", method);
    
    if([method isEqualToString:NSURLAuthenticationMethodServerTrust]){
        
        NSString *host = challenge.protectionSpace.host;
        NSLog(@"%@", host);
        
        NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        return;
    }
    
    NSString *thePath = [[NSBundle mainBundle] pathForResource:@"client" ofType:@"p12"];
    NSData *PKCS12Data = [[NSData alloc] initWithContentsOfFile:thePath];
    CFDataRef inPKCS12Data = (CFDataRef)CFBridgingRetain(PKCS12Data);
    SecIdentityRef identity;
    
    // 读取p12证书中的内容
    OSStatus result = [self extractP12Data:inPKCS12Data toIdentity:&identity];
    if(result != errSecSuccess){
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }
    
    SecCertificateRef certificate = NULL;
    SecIdentityCopyCertificate (identity, &certificate);
    
    const void *certs[] = {certificate};
    CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
    
    NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identity certificates:(NSArray*)CFBridgingRelease(certArray) persistence:NSURLCredentialPersistencePermanent];
    
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
}

-(OSStatus) extractP12Data:(CFDataRef)inP12Data toIdentity:(SecIdentityRef*)identity {
    
    OSStatus securityError = errSecSuccess;
    
    CFStringRef password = CFSTR("welian");
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12Data, options, &items);
    
    if (securityError == 0) {
        CFDictionaryRef ident = CFArrayGetValueAtIndex(items,0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityError;
}

//+ (BOOL)extractIdentity:(SecIdentityRef *)outIdentity
//               andTrust:(SecTrustRef*)outTrust
//         fromPKCS12Data:(NSData *)inPKCS12Data {
//    OSStatus securityError = errSecSuccess;
//    
//    // 证书密钥
//    NSDictionary *optionsDictionary = @{@"welian": (__bridge id)kSecImportExportPassphrase};
//    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
//    securityError = SecPKCS12Import((__bridge CFDataRef)inPKCS12Data,
//                                    (__bridge CFDictionaryRef)optionsDictionary,
//                                    &items);
//    
//    if (securityError == 0) {
//        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex (items, 0);
//        const void *tempIdentity = NULL;
//        tempIdentity = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemIdentity);
//        *outIdentity = (SecIdentityRef)tempIdentity;
//        const void *tempTrust = NULL;
//        tempTrust = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemTrust);
//        *outTrust = (SecTrustRef)tempTrust;
//    } else {
//        NSLog(@"Failed with error code %d",(int)securityError);
//        return NO;
//    }
//    return YES;
//}


- (void)testConnect1{
//    SecIdentityRef identity = NULL;
//    SecTrustRef trust = NULL;
//    NSString *p12 = [[NSBundle mainBundle] pathForResource:@"client" ofType:@"p12"];
//    NSData *PKCS12Data = [NSData dataWithContentsOfFile:p12];
//    
//    [self extractIdentity:&identity andTrust:&trust fromPKCS12Data:PKCS12Data];
    
//    [self extractP12Data:inPKCS12Data toIdentity:&identity];
    
    NSString *certFilePath = [[NSBundle mainBundle] pathForResource:@"server" ofType:@"der"];
    NSData *certData = [NSData dataWithContentsOfFile:certFilePath];
    NSSet *certSet = [NSSet setWithObject:certData];
    AFSecurityPolicy *policy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate withPinnedCertificates:certSet];
    policy.allowInvalidCertificates = YES;
    policy.validatesDomainName = NO;
    
    
    _manager = [AFHTTPSessionManager manager];
    _manager.securityPolicy = policy;
    _manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    _manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    _manager.responseSerializer.acceptableContentTypes =  [NSSet setWithObjects:@"application/json", @"text/json", @"text/javascript",@"text/plain", nil];
//    [manager.securityPolicy setAllowInvalidCertificates:YES];
    //关闭缓存避免干扰测试r
    _manager.requestSerializer.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    [_manager setSessionDidBecomeInvalidBlock:^(NSURLSession * _Nonnull session, NSError * _Nonnull error) {
        DLog(@"setSessionDidBecomeInvalidBlock");
    }];

    
    __weak typeof(self)weakSelf = self;
    
    
    [_manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession*session, NSURLAuthenticationChallenge *challenge, NSURLCredential *__autoreleasing*_credential) {
        NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
        __autoreleasing NSURLCredential *credential =nil;
        if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
            if([weakSelf.manager.securityPolicy evaluateServerTrust:challenge.protectionSpace.serverTrust forDomain:challenge.protectionSpace.host]) {
                credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
                if(credential) {
                    disposition =NSURLSessionAuthChallengeUseCredential;
                } else {
                    disposition =NSURLSessionAuthChallengePerformDefaultHandling;
                }
            } else {
                disposition = NSURLSessionAuthChallengeCancelAuthenticationChallenge;
            }
        } else {
            // client authentication
            SecIdentityRef identity = NULL;
            SecTrustRef trust = NULL;
            NSString *p12 = [[NSBundle mainBundle] pathForResource:@"client"ofType:@"p12"];
            NSFileManager *fileManager =[NSFileManager defaultManager];
            
            if(![fileManager fileExistsAtPath:p12])
            {
                NSLog(@"client.p12:not exist");
            }
            else
            {
                NSData *PKCS12Data = [NSData dataWithContentsOfFile:p12];
                
                if ([[weakSelf class]extractIdentity:&identity andTrust:&trust fromPKCS12Data:PKCS12Data])
                {
                    SecCertificateRef certificate = NULL;
                    SecIdentityCopyCertificate(identity, &certificate);
                    const void*certs[] = {certificate};
                    CFArrayRef certArray =CFArrayCreate(kCFAllocatorDefault, certs,1,NULL);
                    credential =[NSURLCredential credentialWithIdentity:identity certificates:(__bridge  NSArray*)certArray persistence:NSURLCredentialPersistencePermanent];
                    disposition =NSURLSessionAuthChallengeUseCredential;
                }
            }
        }
        *_credential = credential;
        return disposition;
    }];
    
    [_manager POST:@"https://sevnew.welian.com" parameters:nil progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        NSString *message = [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
        NSLog(@"%@",message);
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        NSLog(@"%@",error);
    }];
}

+ (BOOL)extractIdentity:(SecIdentityRef*)outIdentity andTrust:(SecTrustRef *)outTrust fromPKCS12Data:(NSData *)inPKCS12Data {
    OSStatus securityError = errSecSuccess;
    //client certificate password
    NSDictionary*optionsDictionary = [NSDictionary dictionaryWithObject:@"你的密码"
                                                                forKey:(__bridge id)kSecImportExportPassphrase];
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import((__bridge CFDataRef)inPKCS12Data,(__bridge CFDictionaryRef)optionsDictionary,&items);
    
    if(securityError == 0) {
        CFDictionaryRef myIdentityAndTrust =CFArrayGetValueAtIndex(items,0);
        const void*tempIdentity =NULL;
        tempIdentity= CFDictionaryGetValue (myIdentityAndTrust,kSecImportItemIdentity);
        *outIdentity = (SecIdentityRef)tempIdentity;
        const void*tempTrust =NULL;
        tempTrust = CFDictionaryGetValue(myIdentityAndTrust,kSecImportItemTrust);
        *outTrust = (SecTrustRef)tempTrust;
    } else {
        NSLog(@"Failedwith error code %d",(int)securityError);
        return NO;
    }
    return YES;
}



- (void)testConnect{
    
    //先导入证书
    NSString *cerPath                = [[NSBundle mainBundle] pathForResource:@"welianca" ofType:@"cer"];
    NSData *certData                 = [NSData dataWithContentsOfFile:cerPath];
    
    SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
    
   
    self.trustedCertificates = @[CFBridgingRelease(certificate)];
    
    NSURL * httpsURL = [NSURL URLWithString:@"https://sevnew.welian.com"];
    self.connection = [NSURLConnection connectionWithRequest:[NSURLRequest requestWithURL:httpsURL] delegate:self];
    [self.connection start];
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    return [protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        //if ([trustedHosts containsObject:challenge.protectionSpace.host])
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]
             forAuthenticationChallenge:challenge];
    
    [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
}

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    //1)获取trust object
    SecTrustRef trust = challenge.protectionSpace.serverTrust;
    SecTrustResultType result;
    
    //注意：这里将之前导入的证书设置成下面验证的Trust Object的anchor certificate
    SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)self.trustedCertificates);
    
    //2)SecTrustEvaluate会查找前面SecTrustSetAnchorCertificates设置的证书或者系统默认提供的证书，对trust进行验证
    OSStatus status = SecTrustEvaluate(trust, &result);
    if (status == errSecSuccess &&
        (result == kSecTrustResultProceed ||
         result == kSecTrustResultUnspecified)) {
            
            NSLog(@"验证 chengg ong ");

            //3)验证成功，生成NSURLCredential凭证cred，告知challenge的sender使用这个凭证来继续连接
            NSURLCredential *cred = [NSURLCredential credentialForTrust:trust];
            [challenge.sender useCredential:cred forAuthenticationChallenge:challenge];
            
        } else {
            NSLog(@"验证 fal");
            //5)验证失败，取消这次验证流程
            [challenge.sender cancelAuthenticationChallenge:challenge];
            
        }
}



- (void)testMK{
    SecIdentityRef identity = NULL;
    SecTrustRef trust = NULL;
    NSString *p12 = [[NSBundle mainBundle] pathForResource:@"clien-cer" ofType:@"der"];
    NSData *PKCS12Data = [NSData dataWithContentsOfFile:p12];
    
    [[self class] extractIdentity:&identity andTrust:&trust fromPKCS12Data:PKCS12Data];
    
    NSString *url = @"https://sevnew.welian.com";
   
    
    MKNetworkEngine *engine = [[MKNetworkEngine alloc] initWithHostName:@"121.40.225.104"];
    MKNetworkOperation *op = [engine operationWithPath:nil params:nil httpMethod:@"GET" ssl:YES];
//    op.postDataEncoding = MKNKPostDataEncodingTypeJSON; // 传JOSN
    
    // 这个是app bundle 路径下的自签证书
    op.clientCertificate = [[[NSBundle mainBundle] resourcePath]
                            stringByAppendingPathComponent:@"client.p12"];
    // 这个是自签证书的密码
    op.clientCertificatePassword = @"welian";
    
    // 由于自签名的证书是需要忽略的，所以这里需要设置为YES，表示允许
    op.shouldContinueWithInvalidCertificate = YES;
    [op addCompletionHandler:^(MKNetworkOperation *completedOperation) {
        NSLog(@"%@", completedOperation.responseString);
    } errorHandler:^(MKNetworkOperation *completedOperation, NSError *error) {
        NSLog(@"%@", [error description]);
    }];
    
    [engine enqueueOperation:op];
}

//- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
//    return [protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust];
//}
//
//- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
//    [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
//    
//    [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
//}


- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
