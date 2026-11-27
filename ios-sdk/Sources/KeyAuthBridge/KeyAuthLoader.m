// ios-sdk/Sources/KeyAuthBridge/KeyAuthLoader.m
#import "KeyAuthBridge.h"
#import <objc/message.h>
#if __has_include(<UIKit/UIKit.h>)
#import <UIKit/UIKit.h>
#endif

static void KTTriggerInstallHook(void) {
    Class gateClass = NSClassFromString(@"KeyAuthGate");
    SEL installSel = NSSelectorFromString(@"installHook");
    if (gateClass && [gateClass respondsToSelector:installSel]) {
        ((void (*)(id, SEL))objc_msgSend)(gateClass, installSel);
    }
}

@implementation KeyAuthLoader

+ (void)load {
    KTTriggerInstallHook();
#if __has_include(<UIKit/UIKit.h>)
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(__unused NSNotification *note) {
                    KTTriggerInstallHook();
                }];
#endif
}

@end
