// ios-sdk/Sources/KTImGuiOverlay/include/KTImGuiOverlay.h
#import <Foundation/Foundation.h>
#if __has_include(<UIKit/UIKit.h>)
#import <UIKit/UIKit.h>
#endif

NS_ASSUME_NONNULL_BEGIN

/// Pure Objective-C interface for the standalone ImGui + Metal KT AOV overlay.
__attribute__((visibility("default")))
@interface KTImGuiOverlay : NSObject

#if __has_include(<UIKit/UIKit.h>)
+ (void)showInWindow:(UIWindow *)hostWindow
           serverURL:(NSString *)serverURL
          licenseKey:(NSString *)licenseKey
            deviceID:(NSString *)deviceID
           expiresAt:(double)expiresAt
           getKeyURL:(nullable NSString *)getKeyURL;
#endif

+ (void)hide;
+ (BOOL)isVisible;

@end

NS_ASSUME_NONNULL_END
