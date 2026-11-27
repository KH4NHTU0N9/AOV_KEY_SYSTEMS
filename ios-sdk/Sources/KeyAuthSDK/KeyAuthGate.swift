// ios-sdk/Sources/KeyAuthSDK/KeyAuthGate.swift
import Foundation
import ObjectiveC
#if canImport(UIKit)
import UIKit
#endif

/// Runtime gate supporting both legacy MenuLoad swizzling and standalone KTImGuiOverlay boot.
@objc(KeyAuthGate)
public final class KeyAuthGate: NSObject {
    private static var hookInstalled = false
    private static var authStarted = false
    private static var isAuthorized = false
    private static var watchdogTimer: Timer?
    private static var lastReverifyAt: TimeInterval = 0
    private static weak var authorizedMenuLoad: NSObject?
    private static var activeClient: LicenseClient?
    private static var activePayload: LicensePayload?
    #if canImport(UIKit)
    private static var overlayBridgeHandler: ((UIWindow, LicensePayload, URL, String, String?) -> Void)?

    public static func registerOverlayPresenter(
        _ handler: @escaping (UIWindow, LicensePayload, URL, String, String?) -> Void
    ) {
        overlayBridgeHandler = handler
    }
    #endif

    @objc public static func installHook() {
        #if canImport(UIKit)
        guard !hookInstalled else { return }

        if attemptSwizzle() {
            hookInstalled = true
            return
        }

        // Wait until UIApplication finishes launching for standalone non-AWSCognito IPAs
        NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { _ in
            if !hookInstalled, attemptSwizzle() {
                hookInstalled = true
                return
            }
            if !hookInstalled && !authStarted {
                startStandaloneAuth()
            }
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            if !hookInstalled, attemptSwizzle() {
                hookInstalled = true
                return
            }
            if !hookInstalled && !authStarted {
                startStandaloneAuth()
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

    private static func startStandaloneAuth() {
        hookInstalled = true
        presentAuthAndUnlock(menuLoadInstance: nil)
    }

    private static func presentAuthAndUnlock(menuLoadInstance: AnyObject?) {
        guard !authStarted || menuLoadInstance != nil else { return }
        authStarted = true

        let bundle = Bundle(for: KeyAuthGate.self)
        let info = bundle.infoDictionary ?? [:]

        guard let serverStr = info["KeyAuthServerURL"] as? String,
              let serverURL = URL(string: serverStr),
              let pubKey = info["KeyAuthPublicKey"] as? String,
              !pubKey.isEmpty else {
            NSLog("[KeyAuthGate] Missing KeyAuthServerURL or KeyAuthPublicKey in Info.plist")
            authStarted = false
            return
        }

        let title = (info["KeyAuthTitle"] as? String) ?? "KT AOV"
        let subtitle = (info["KeyAuthSubtitle"] as? String) ?? "Enter your activation key"
        let getKeyRaw = info["KeyAuthGetKeyURL"] as? String

        guard let window = findKeyWindow(), window.rootViewController != nil else {
            authStarted = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                presentAuthAndUnlock(menuLoadInstance: menuLoadInstance)
            }
            return
        }

        let client = LicenseClient(baseURL: serverURL, publicKeyBase64: pubKey)
        activeClient = client
        client.bootstrap(
            in: window,
            title: title,
            subtitle: subtitle,
            getKeyURLRaw: getKeyRaw
        ) { payload in
            isAuthorized = true
            activePayload = payload
            lastReverifyAt = Date().timeIntervalSince1970
            if let obj = menuLoadInstance as? NSObject {
                authorizedMenuLoad = obj
                attachMenu(menuLoadObj: obj)
            } else {
                presentStandaloneOverlay(in: window, payload: payload, serverURL: serverURL, pubKey: pubKey, getKeyRaw: getKeyRaw)
            }
            startOverlayWatchdog(serverURL: serverURL, pubKey: pubKey, getKeyRaw: getKeyRaw)
        }
    }

    private static func presentStandaloneOverlay(
        in window: UIWindow,
        payload: LicensePayload,
        serverURL: URL,
        pubKey: String,
        getKeyRaw: String?
    ) {
        if let handler = overlayBridgeHandler {
            handler(window, payload, serverURL, pubKey, getKeyRaw)
            return
        }
        if let overlayCls: AnyClass = NSClassFromString("KTImGuiOverlay") {
            let showSel = NSSelectorFromString("showInWindow:serverURL:licenseKey:deviceID:expiresAt:getKeyURL:")
            if (overlayCls as AnyObject).responds(to: showSel) {
                typealias Fn = @convention(c) (AnyObject, Selector, UIWindow, NSString, NSString, NSString, Double, NSString?) -> Void
                let imp = class_getMethodImplementation(object_getClass(overlayCls), showSel)
                if let imp {
                    let fn = unsafeBitCast(imp, to: Fn.self)
                    let resolvedURL = LicenseClient.normalizeGetKeyURL(getKeyRaw, deviceID: payload.device_id)?.absoluteString as NSString?
                    fn(overlayCls as AnyObject, showSel, window, serverURL.absoluteString as NSString, payload.key as NSString, payload.device_id as NSString, payload.expires_at, resolvedURL)
                }
            }
        }
    }

    private static func hideStandaloneOverlay() {
        if let overlayCls: AnyClass = NSClassFromString("KTImGuiOverlay") {
            let hideSel = NSSelectorFromString("hide")
            if (overlayCls as AnyObject).responds(to: hideSel) {
                _ = (overlayCls as AnyObject).perform(hideSel)
            }
        }
    }

    private static func attachMenu(menuLoadObj: NSObject) {
        let initSel = NSSelectorFromString("initTapGes")
        if menuLoadObj.responds(to: initSel) {
            _ = menuLoadObj.perform(initSel)
        }
    }

    /// Re-attaches overlay across logout/login and enforces server/expiry re-checks.
    private static func startOverlayWatchdog(serverURL: URL, pubKey: String, getKeyRaw: String?) {
        guard watchdogTimer == nil else { return }
        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            guard isAuthorized, let payload = activePayload else { return }
            let now = Date().timeIntervalSince1970
            if now >= payload.expires_at || (now - lastReverifyAt) >= 45.0 {
                lastReverifyAt = now
                activeClient?.verify(key: payload.key, deviceID: payload.device_id) { res in
                    switch res {
                    case .success(let refreshed):
                        activePayload = refreshed
                    case .failure(let err):
                        if case .networkError = err {
                            // Keep alive briefly on transient offline drops unless expired
                            if now >= payload.expires_at {
                                revokeAndPrompt(serverURL: serverURL, pubKey: pubKey, getKeyRaw: getKeyRaw)
                            }
                        } else {
                            revokeAndPrompt(serverURL: serverURL, pubKey: pubKey, getKeyRaw: getKeyRaw)
                        }
                    }
                }
            }

            guard let activeWindow = findKeyWindow(),
                  let activeRoot = activeWindow.rootViewController else {
                return
            }

            if let menuLoadObj = authorizedMenuLoad {
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
            } else {
                // Re-attach standalone KTImGuiOverlay only if hidden/detached
                if let overlayCls: AnyClass = NSClassFromString("KTImGuiOverlay") {
                    let visSel = NSSelectorFromString("isVisible")
                    var visible = false
                    if (overlayCls as AnyObject).responds(to: visSel),
                       let imp = class_getMethodImplementation(object_getClass(overlayCls), visSel) {
                        typealias BoolFn = @convention(c) (AnyObject, Selector) -> Bool
                        let fn = unsafeBitCast(imp, to: BoolFn.self)
                        visible = fn(overlayCls as AnyObject, visSel)
                    }
                    if !visible {
                        presentStandaloneOverlay(in: activeWindow, payload: payload, serverURL: serverURL, pubKey: pubKey, getKeyRaw: getKeyRaw)
                    }
                }
            }
        }
    }

    private static func revokeAndPrompt(serverURL: URL, pubKey: String, getKeyRaw: String?) {
        isAuthorized = false
        authStarted = false
        activePayload = nil
        watchdogTimer?.invalidate()
        watchdogTimer = nil
        hideStandaloneOverlay()
        presentAuthAndUnlock(menuLoadInstance: authorizedMenuLoad)
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
