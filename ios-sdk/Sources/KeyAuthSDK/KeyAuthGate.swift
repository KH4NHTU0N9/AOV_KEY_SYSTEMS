// ios-sdk/Sources/KeyAuthSDK/KeyAuthGate.swift
import Foundation
import ObjectiveC
#if canImport(UIKit)
import UIKit
#endif

/// Runtime gate that intercepts MenuLoad.checkAndExecutePaidBlock and enforces KeyAuthSDK verification.
@objc(KeyAuthGate)
public final class KeyAuthGate: NSObject {
    private static var hookInstalled = false

    @objc public static func installHook() {
        #if canImport(UIKit)
        guard !hookInstalled else { return }

        if attemptSwizzle() {
            hookInstalled = true
            return
        }

        // Retry on main queue in case MenuLoad registers slightly after dyld image init
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            if !hookInstalled, attemptSwizzle() {
                hookInstalled = true
            }
        }
        #endif
    }

    #if canImport(UIKit)
    private static func attemptSwizzle() -> Bool {
        guard let menuClass: AnyClass = objc_getClass("MenuLoad") as? AnyClass else {
            return false
        }
        let targetSel = NSSelectorFromString("checkAndExecutePaidBlock")
        guard let method = class_getInstanceMethod(menuClass, targetSel) else {
            return false
        }

        let block: @convention(block) (AnyObject) -> Void = { menuLoadInstance in
            DispatchQueue.main.async {
                presentAuthAndUnlock(menuLoadInstance: menuLoadInstance)
            }
        }
        method_setImplementation(method, imp_implementationWithBlock(block))
        return true
    }

    private static func presentAuthAndUnlock(menuLoadInstance: AnyObject) {
        let bundle = Bundle(for: KeyAuthGate.self)
        let info = bundle.infoDictionary ?? [:]

        guard let serverStr = info["KeyAuthServerURL"] as? String,
              let serverURL = URL(string: serverStr),
              let pubKey = info["KeyAuthPublicKey"] as? String,
              !pubKey.isEmpty else {
            NSLog("[KeyAuthGate] Missing KeyAuthServerURL or KeyAuthPublicKey in Info.plist")
            return
        }

        let title = (info["KeyAuthTitle"] as? String) ?? "KT AOV"
        let subtitle = (info["KeyAuthSubtitle"] as? String) ?? "Enter your activation key"

        guard let window = findKeyWindow() else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                presentAuthAndUnlock(menuLoadInstance: menuLoadInstance)
            }
            return
        }

        let client = LicenseClient(baseURL: serverURL, publicKeyBase64: pubKey)
        client.bootstrap(in: window, title: title, subtitle: subtitle) { _ in
            let initSel = NSSelectorFromString("initTapGes")
            if let obj = menuLoadInstance as? NSObject, obj.responds(to: initSel) {
                _ = obj.perform(initSel)
            }
        }
    }

    private static func findKeyWindow() -> UIWindow? {
        if #available(iOS 15.0, *) {
            for scene in UIApplication.shared.connectedScenes {
                if let winScene = scene as? UIWindowScene {
                    if let key = winScene.windows.first(where: { $0.isKeyWindow }) ?? winScene.windows.first {
                        return key
                    }
                }
            }
        }
        return UIApplication.shared.windows.first(where: { $0.isKeyWindow }) ?? UIApplication.shared.windows.first
    }
    #endif
}
