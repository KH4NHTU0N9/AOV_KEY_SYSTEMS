// ios-sdk/Sources/KeyAuthBridge/KeyAuthLoader.m
#import "KeyAuthBridge.h"
#import <objc/message.h>

@implementation KeyAuthLoader

+ (void)load {
    Class gateClass = NSClassFromString(@"KeyAuthGate");
    SEL installSel = NSSelectorFromString(@"installHook");
    if (gateClass && [gateClass respondsToSelector:installSel]) {
        ((void (*)(id, SEL))objc_msgSend)(gateClass, installSel);
    }
}

@end
