// ios-sdk/Sources/KeyAuthSDK/KeychainStore.swift
import Foundation
import Security
#if canImport(UIKit)
import UIKit
#endif

/// Persistent iOS/macOS Keychain storage (with UserDefaults fallback if Keychain entitlements are unavailable).
public enum KeychainStore {
    public static let defaultService = "com.ktaov.keyauth"
    private static let deviceAccount = "device_udid"
    private static let keyAccount = "license_key"

    private static func fallbackKey(service: String, account: String) -> String {
        "\(service).\(account)"
    }

    @discardableResult
    public static func save(_ value: String, account: String, service: String = defaultService) -> Bool {
        let data = Data(value.utf8)
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(baseQuery as CFDictionary)

        var newItem = baseQuery
        newItem[kSecValueData as String] = data
        newItem[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(newItem as CFDictionary, nil)

        // Mirror to UserDefaults so sideloaded builds / macOS without Keychain entitlements still persist state
        UserDefaults.standard.set(value, forKey: fallbackKey(service: service, account: account))
        return status == errSecSuccess
    }

    public static func load(account: String, service: String = defaultService) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data,
           let string = String(data: data, encoding: .utf8),
           !string.isEmpty {
            return string
        }
        if let fallback = UserDefaults.standard.string(forKey: fallbackKey(service: service, account: account)),
           !fallback.isEmpty {
            return fallback
        }
        return nil
    }

    public static func delete(account: String, service: String = defaultService) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
        UserDefaults.standard.removeObject(forKey: fallbackKey(service: service, account: account))
    }

    /// Returns a persistent device ID that survives app reinstalls via Keychain.
    public static func getOrCreateDeviceID(service: String = defaultService) -> String {
        if let cached = load(account: deviceAccount, service: service), !cached.isEmpty {
            return cached
        }
        #if canImport(UIKit)
        let generated = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
        #else
        let generated = UUID().uuidString
        #endif
        save(generated, account: deviceAccount, service: service)
        return generated
    }

    public static func savedLicenseKey(service: String = defaultService) -> String? {
        load(account: keyAccount, service: service)
    }

    public static func saveLicenseKey(_ key: String, service: String = defaultService) {
        save(key, account: keyAccount, service: service)
    }

    public static func clearLicenseKey(service: String = defaultService) {
        delete(account: keyAccount, service: service)
    }
}
