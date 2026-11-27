// ios-sdk/Sources/KeyAuthSDK/LicenseClient.swift
import CryptoKit
import Foundation
#if canImport(UIKit)
import UIKit
#endif

public struct LicensePayload: Codable, Equatable {
    public let status: String
    public let key: String
    public let device_id: String
    public let expires_at: TimeInterval
    public let issued_at: TimeInterval
    public let nonce: String
}

private struct VerifyAPIResponse: Decodable {
    let status: String?
    let payload_raw: String?
    let signature: String?
    let error: String?
    let detail: String?
}

public enum LicenseError: Error, LocalizedError, Equatable {
    case invalidConfiguration
    case networkError(String)
    case serverRejected(String)
    case invalidSignature
    case keyMismatch
    case nonceMismatch
    case deviceMismatch
    case expired

    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "Invalid server URL or Ed25519 public key."
        case .networkError(let msg): return "Network error: \(msg)"
        case .serverRejected(let msg): return msg
        case .invalidSignature: return "Response signature verification failed."
        case .keyMismatch: return "License key in signed payload does not match."
        case .nonceMismatch: return "Security challenge (nonce) mismatch."
        case .deviceMismatch: return "License is bound to another device."
        case .expired: return "License key has expired."
        }
    }
}

/// Client for verifying license keys against the KeyAuth backend with Ed25519 signature checks.
public final class LicenseClient {
    public let baseURL: URL
    public let publicKeyBase64: String
    private let serviceName: String
    private let session: URLSession

    public init(
        baseURL: URL,
        publicKeyBase64: String,
        serviceName: String = "com.ktaov.keyauth",
        session: URLSession = .shared
    ) {
        self.baseURL = baseURL
        self.publicKeyBase64 = publicKeyBase64
        self.serviceName = serviceName
        self.session = session
    }

    /// Normalizes a configured Get-Key portal URL and appends `?code=<deviceID>`.
    public static func normalizeGetKeyURL(_ raw: String?, deviceID: String) -> URL? {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              var comps = URLComponents(string: trimmed),
              let scheme = comps.scheme?.lowercased(),
              (scheme == "http" || scheme == "https"),
              let host = comps.host, !host.isEmpty else {
            return nil
        }
        var path = comps.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if path.isEmpty || path == "get-key" {
            comps.path = "/get-key/"
        } else {
            path += path.hasSuffix("/get-key") ? "/" : "/get-key/"
            comps.path = "/" + path
        }
        var items = comps.queryItems ?? []
        items.removeAll { $0.name == "code" }
        items.append(URLQueryItem(name: "code", value: deviceID))
        comps.queryItems = items
        return comps.url
    }

    /// Validates an Ed25519-signed response offline against the pinned public key.
    public func validateSignedResponse(
        payloadRaw: String,
        signatureBase64: String,
        expectedNonce: String,
        expectedDeviceID: String,
        expectedKey: String? = nil,
        now: TimeInterval = Date().timeIntervalSince1970
    ) -> Result<LicensePayload, LicenseError> {
        guard let pubKeyData = Data(base64Encoded: publicKeyBase64),
              let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubKeyData),
              let sigData = Data(base64Encoded: signatureBase64) else {
            return .failure(.invalidConfiguration)
        }

        let payloadData = Data(payloadRaw.utf8)
        guard pubKey.isValidSignature(sigData, for: payloadData),
              let decoded = try? JSONDecoder().decode(LicensePayload.self, from: payloadData) else {
            return .failure(.invalidSignature)
        }

        guard decoded.status == "ok" else {
            return .failure(.serverRejected("License rejected"))
        }
        if let expectedKey, decoded.key != expectedKey {
            return .failure(.keyMismatch)
        }
        guard decoded.issued_at <= now + 300 else {
            return .failure(.invalidSignature)
        }
        guard decoded.nonce == expectedNonce else {
            return .failure(.nonceMismatch)
        }
        guard decoded.device_id == expectedDeviceID else {
            return .failure(.deviceMismatch)
        }
        guard decoded.expires_at > now else {
            return .failure(.expired)
        }

        return .success(decoded)
    }

    /// Sends a verification request to `/api/v1/verify` and verifies the returned Ed25519 signature.
    public func verify(
        key: String,
        deviceID: String? = nil,
        appVersion: String = "1.0.0",
        completion: @escaping (Result<LicensePayload, LicenseError>) -> Void
    ) {
        let trimmedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedKey.isEmpty else {
            completion(.failure(.serverRejected("Please enter a license key.")))
            return
        }

        let resolvedDevice = deviceID ?? KeychainStore.getOrCreateDeviceID(service: serviceName)
        let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "")

        let endpoint = baseURL.appendingPathComponent("api/v1/verify")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 15

        let body: [String: String] = [
            "key": trimmedKey,
            "device_id": resolvedDevice,
            "nonce": nonce,
            "app_version": appVersion
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        session.dataTask(with: request) { data, response, err in
            if let err {
                DispatchQueue.main.async { completion(.failure(.networkError(err.localizedDescription))) }
                return
            }
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
            if statusCode >= 500 {
                DispatchQueue.main.async { completion(.failure(.networkError("Server error (HTTP \(statusCode))"))) }
                return
            }
            guard let data else {
                DispatchQueue.main.async { completion(.failure(.networkError("Empty server response"))) }
                return
            }
            if statusCode == 422 {
                DispatchQueue.main.async { completion(.failure(.serverRejected("Invalid key format or device ID."))) }
                return
            }
            guard let apiResp = try? JSONDecoder().decode(VerifyAPIResponse.self, from: data) else {
                DispatchQueue.main.async { completion(.failure(.networkError("Malformed server response (HTTP \(statusCode))"))) }
                return
            }
            guard apiResp.status == "ok",
                  let payloadRaw = apiResp.payload_raw,
                  let signature = apiResp.signature else {
                let msg = apiResp.error ?? apiResp.detail ?? "Invalid license key"
                DispatchQueue.main.async { completion(.failure(.serverRejected(msg))) }
                return
            }

            let validation = self.validateSignedResponse(
                payloadRaw: payloadRaw,
                signatureBase64: signature,
                expectedNonce: nonce,
                expectedDeviceID: resolvedDevice,
                expectedKey: trimmedKey
            )
            if case .success = validation {
                KeychainStore.saveLicenseKey(trimmedKey, service: self.serviceName)
            }
            DispatchQueue.main.async { completion(validation) }
        }.resume()
    }

    #if canImport(UIKit)
    /// Checks saved Keychain key on launch and presents KeyPromptViewController if missing or invalid.
    public func bootstrap(
        in window: UIWindow,
        title: String = "KT AOV License",
        subtitle: String = "Enter your activation key to continue",
        getKeyURLRaw: String? = nil,
        onAuthorized: @escaping (LicensePayload) -> Void
    ) {
        let devID = KeychainStore.getOrCreateDeviceID(service: serviceName)
        let resolvedGetKeyURL = Self.normalizeGetKeyURL(getKeyURLRaw, deviceID: devID)
        if let saved = KeychainStore.savedLicenseKey(service: serviceName) {
            verify(key: saved, deviceID: devID) { [weak window] result in
                guard let window else { return }
                switch result {
                case .success(let payload):
                    onAuthorized(payload)
                case .failure(let error):
                    if case .networkError = error {
                        // Keep saved key on transient network error so user can retry without retyping
                    } else {
                        KeychainStore.clearLicenseKey(service: self.serviceName)
                    }
                    self.presentPrompt(
                        in: window,
                        title: title,
                        subtitle: subtitle,
                        getKeyURL: resolvedGetKeyURL,
                        prefillKey: saved,
                        initialError: error.localizedDescription,
                        onAuthorized: onAuthorized
                    )
                }
            }
        } else {
            presentPrompt(
                in: window,
                title: title,
                subtitle: subtitle,
                getKeyURL: resolvedGetKeyURL,
                prefillKey: nil,
                initialError: nil,
                onAuthorized: onAuthorized
            )
        }
    }

    private func presentPrompt(
        in window: UIWindow,
        title: String,
        subtitle: String,
        getKeyURL: URL?,
        prefillKey: String?,
        initialError: String?,
        onAuthorized: @escaping (LicensePayload) -> Void
    ) {
        DispatchQueue.main.async { [weak window] in
            guard let window else { return }
            guard var topVC = window.rootViewController else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    self.presentPrompt(
                        in: window,
                        title: title,
                        subtitle: subtitle,
                        getKeyURL: getKeyURL,
                        prefillKey: prefillKey,
                        initialError: initialError,
                        onAuthorized: onAuthorized
                    )
                }
                return
            }
            while let presented = topVC.presentedViewController {
                topVC = presented
            }
            let prompt = KeyPromptViewController(
                client: self,
                titleText: title,
                subtitleText: subtitle,
                getKeyURL: getKeyURL,
                prefillKey: prefillKey,
                initialError: initialError,
                onAuthorized: onAuthorized
            )
            prompt.modalPresentationStyle = .overFullScreen
            prompt.modalTransitionStyle = .crossDissolve
            topVC.present(prompt, animated: true)
        }
    }
    #endif
}
