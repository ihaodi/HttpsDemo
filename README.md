# AFNetworking 3.0与服务端 自签名证书 https双向认证

iOS网络安全现在越来越重要，一个抓包工具（charles等）随随便便就能抓到你所请求的数据，这些数据如果是明码的后果很严重，不是指明文，可以通过这些数据来判定服务端部署的数据接口，更能够嗅探到服务端的漏洞。

所以最近因公司业务及数据安全上的需要准备使用https方式进行数据请求。而且苹果现在默认是https方式请求。
## Apple CSR CER P12 mobileprovition 到底是什么
* CSR（Certificate Signing Request）钥匙串文件 为生成证书做基础，要生成CER证书必须要有CSR私钥，此私钥包含了用户自己的一些信息。这个文件是保存在我们的mac的(keychain)里面的, 此文件包含了(公钥和私钥)
* CER 包含了开发者信息和公钥
* P12 它不仅包含CER的信息，还有私钥信息，即： P12备份文件 = CER文件  + 私钥；所以有了这个p12就再也不用担心证书丢失了
* mobileprovition 包含了上述所有内容 Certificate && App ID && Device, 这个Provisioning Profile文件会在打包时嵌入到.ipa的包里。本人理解的是 可以真机调试的凭证。

## https原理
HTTPS（全称：Hyper Text Transfer Protocol over Secure Socket Layer），是以安全为目标的HTTP通道，简单讲是HTTP的安全版。即HTTP下加入SSL层，HTTPS的安全基础是SSL，因此加密的详细内容就需要SSL。 它是一个URI scheme（抽象标识符体系），句法类同http:体系。用于安全的HTTP数据传输。https:URL表明它使用了HTTP，但HTTPS存在不同于HTTP的默认端口及一个加密/身份验证层（在HTTP与TCP之间）。这个系统的最初研发由网景公司(Netscape)进行，并内置于其浏览器Netscape Navigator中，提供了身份验证与加密通讯方法。（摘自百度百科）

PKI（公钥基础设施）技术是HTTPS的基础，PKI与非对称密钥加密技术密切相关，包括消息摘要、数字签名和加密服务，而数字证书以及证书机构（CA – Certificate Authority）是PKI中的重要概念。

看看这篇[文章](http://www.jianshu.com/p/2927ca2b3719)

双向认证原理图:

![图片](../images/httpsyuanlitu.png)


##需要准备的自签名证书
1.服务器私钥 2.由CA签发的含有服务器公钥的数字证书 3.CA的数字证书。在双向认证的实践中，通常服务器可以自己作为证书机构，并且由服务器CA签发服务器证书和客户端证书。


1.客户端私钥 2. 由CA签发的含有客户端公钥的数字证书。为了避免中间人攻击，客户端还需要内置服务器证书，用来验证所连接的服务器是否是指定的服务器。

* 服务端 .cer  
* 客户端 .p12  

## 使用AFNetworking 3.0
```
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
    //关闭缓存避免干扰测试r
    _manager.requestSerializer.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    [_manager setSessionDidBecomeInvalidBlock:^(NSURLSession * _Nonnull session, NSError * _Nonnull error) {
        DLog(@"setSessionDidBecomeInvalidBlock");
    }];
```
    //客服端请求验证 重写 setSessionDidReceiveAuthenticationChallengeBlock 方法
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
```
+(BOOL)extractIdentity:(SecIdentityRef*)outIdentity andTrust:(SecTrustRef *)outTrust fromPKCS12Data:(NSData *)inPKCS12Data {
    OSStatus securityError = errSecSuccess;
    //client certificate password
    NSDictionary*optionsDictionary = [NSDictionary dictionaryWithObject:@"你的p12密码"
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
```
完毕

* 使用MKNetworkKit 与 使用苹果官方原生 代码片段 详见Demo

## Demo
<https://github.com/cuiwe000/HttpsDemo.git>
## 参考文档
* <http://m.ithao123.cn/content-10472230.html>
* [苹果官方说明](https://developer.apple.com/library/mac/documentation/Security/Conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html)
