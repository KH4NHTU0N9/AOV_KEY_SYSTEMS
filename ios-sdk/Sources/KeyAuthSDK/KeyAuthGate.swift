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
    private static var watchdogTimer: Timer?
    private static weak var authorizedMenuLoad: NSObject?
    private static var activeClient: LicenseClient?

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

        guard let window = findKeyWindow(), window.rootViewController != nil else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                presentAuthAndUnlock(menuLoadInstance: menuLoadInstance)
            }
            return
        }

        let client = LicenseClient(baseURL: serverURL, publicKeyBase64: pubKey)
        activeClient = client
        client.bootstrap(in: window, title: title, subtitle: subtitle) { _ in
            activeClient = nil
            if let obj = menuLoadInstance as? NSObject {
                authorizedMenuLoad = obj
                attachMenu(menuLoadObj: obj)
                startOverlayWatchdog()
            }
        }
    }

    private static func attachMenu(menuLoadObj: NSObject) {
        let initSel = NSSelectorFromString("initTapGes")
        if menuLoadObj.responds(to: initSel) {
            _ = menuLoadObj.perform(initSel)
        }
    }

    /// Re-attaches TDMenuController whenever logout/login swaps rootViewController or UIWindow.
    private static func startOverlayWatchdog() {
        guard watchdogTimer == nil else { return }
        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            guard let menuLoadObj = authorizedMenuLoad,
                  let activeWindow = findKeyWindow(),
                  let activeRoot = activeWindow.rootViewController else {
                return
            }

            if let tdClass: AnyClass = objc_getClass("TDMenuController") as? AnyClass {
                let sharedSel = NSSelectorFromString("shared")
                if let sharedObj = (tdClass as AnyObject).perform(sharedSel)?.takeUnretainedValue(),
                   let menuVC = sharedObj as? UIViewController {
                    let loadedView = menuVC.viewIfLoaded
                    let wrongParent = (menuVC.parent !== activeRoot)
                    let wrongWindow = (loadedView?.window !== activeWindow)
                    let detached = (loadedView?.superview == nil)

                    if wrongParent || wrongWindow || detached {
                        attachMenu(menuLoadObj: menuLoadObj)
                    }

                    if let view = menuVC.viewIfLoaded,
                       let superview = view.superview,
                       activeRoot.presentedViewController == nil,
                       superview.subviews.last !== view {
                        superview.bringSubviewToFront(view)
                    }

                    // Ensure floating bubble never gets stuck invisible while panel is closed
                    if menuVC.responds(to: NSSelectorFromString("panel")),
                       menuVC.responds(to: NSSelectorFromString("bubble")),
                       let panel = menuVC.value(forKey: "panel") as? UIView,
                       let bubble = menuVC.value(forKey: "bubble") as? UIView,
                       panel.isHidden,
                       (bubble.isHidden || bubble.alpha < 0.1) {
                        bubble.isHidden = false
                        bubble.alpha = 1.0
                    }
                    return
                }
            }

            attachMenu(menuLoadObj: menuLoadObj)
        }
    }

    private static func pickNormalWindow(from windows: [UIWindow]) -> UIWindow? {
        let candidates = windows.filter { !$0.isHidden && $0.rootViewController != nil && $0.windowLevel == .normal }
        return candidates.first(where: { $0.isKeyWindow }) ?? candidates.first
    }

    private static func findKeyWindow() -> UIWindow? {
        if #available(iOS 15.0, *) {
            for scene in UIApplication.shared.connectedScenes {
                if let winScene = scene as? UIWindowScene,
                   let match = pickNormalWindow(from: winScene.windows) {
                    return match
                }
            }
        }
        return pickNormalWindow(from: UIApplication.shared.windows)
    }
    #endif
}
