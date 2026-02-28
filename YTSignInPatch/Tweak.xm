// YTSignInPatch - Fix Google sign-in on sideloaded YouTube with YTLite b3
// Strips device/version identifiers from OAuth URL that Google uses to block sideloaded apps
// Based on: https://gist.github.com/AhmedBafkir/0c16b806b3fb233995aa01b93da44f93
// Keychain fix: https://gist.github.com/BandarHL/492d50de46875f9ac7a056aad084ac10

#import <Foundation/Foundation.h>

// === Sign-In Fix: Strip identifying params from SSO URL ===
%hook SSORPCService
+ (id)URLFromURL:(id)arg1 withAdditionalFragmentParameters:(NSDictionary *)arg2 {
    NSURL *orig = %orig;
    NSURLComponents *urlComponents = [[NSURLComponents alloc] initWithURL:orig resolvingAgainstBaseURL:NO];
    NSMutableArray *newQueryItems = [urlComponents.queryItems mutableCopy];
    for (NSURLQueryItem *queryItem in urlComponents.queryItems) {
        if ([queryItem.name isEqualToString:@"system_version"]
            || [queryItem.name isEqualToString:@"app_version"]
            || [queryItem.name isEqualToString:@"kdlc"]
            || [queryItem.name isEqualToString:@"kss"]
            || [queryItem.name isEqualToString:@"lib_ver"]
            || [queryItem.name isEqualToString:@"device_model"]) {
            [newQueryItems removeObject:queryItem];
        }
    }
    urlComponents.queryItems = [newQueryItems copy];
    return urlComponents.URL;
}
%end

// === Keychain Fix: Allow sideloaded app to access keychain ===
%hook SSOKeychainCore
+ (NSString *)accessGroup {
    return nil;
}
+ (NSString *)sharedAccessGroup {
    return nil;
}
%end

%hook SSOKeychainHelper
+ (NSString *)accessGroup {
    return nil;
}
+ (NSString *)sharedAccessGroup {
    return nil;
}
%end
