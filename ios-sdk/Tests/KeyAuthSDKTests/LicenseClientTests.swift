// ios-sdk/Tests/KeyAuthSDKTests/LicenseClientTests.swift
import CryptoKit
import Foundation
import XCTest
@testable import KeyAuthSDK

final class LicenseClientTests: XCTestCase {
    private func sign(payload: [String: Any], with privKey: Curve25519.Signing.PrivateKey) throws -> (String, String) {
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let raw = String(decoding: data, as: UTF8.self)
        let sig = try privKey.signature(for: data)
        return (raw, sig.base64EncodedString())
    }

    func testValidSignedPayloadPasses() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let pubB64 = priv.publicKey.rawRepresentation.base64EncodedString()
        let client = LicenseClient(baseURL: URL(string: "https://example.com")!, publicKeyBase64: pubB64)

        let now: TimeInterval = 1_700_000_000
        let payload: [String: Any] = [
            "status": "ok",
            "key": "KTAOV-ABCD-1234-EFGH",
            "device_id": "DEV-001",
            "expires_at": now + 3600,
            "issued_at": now,
            "nonce": "nonce-123"
        ]
        let (raw, sig) = try sign(payload: payload, with: priv)
        let result = client.validateSignedResponse(
            payloadRaw: raw,
            signatureBase64: sig,
            expectedNonce: "nonce-123",
            expectedDeviceID: "DEV-001",
            now: now
        )
        guard case .success(let decoded) = result else {
            return XCTFail("Expected valid verification, got \(result)")
        }
        XCTAssertEqual(decoded.key, "KTAOV-ABCD-1234-EFGH")
    }

    func testTamperedSignatureFails() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let other = Curve25519.Signing.PrivateKey()
        let client = LicenseClient(
            baseURL: URL(string: "https://example.com")!,
            publicKeyBase64: other.publicKey.rawRepresentation.base64EncodedString()
        )
        let now: TimeInterval = 1_700_000_000
        let (raw, sig) = try sign(payload: [
            "status": "ok",
            "key": "KTAOV-1111",
            "device_id": "DEV-001",
            "expires_at": now + 3600,
            "issued_at": now,
            "nonce": "n1"
        ], with: priv)

        let result = client.validateSignedResponse(payloadRaw: raw, signatureBase64: sig, expectedNonce: "n1", expectedDeviceID: "DEV-001", now: now)
        XCTAssertEqual(result, .failure(.invalidSignature))
    }

    func testDeviceMismatchNonceAndExpiryFail() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let client = LicenseClient(
            baseURL: URL(string: "https://example.com")!,
            publicKeyBase64: priv.publicKey.rawRepresentation.base64EncodedString()
        )
        let now: TimeInterval = 1_700_000_000
        let (raw, sig) = try sign(payload: [
            "status": "ok",
            "key": "KTAOV-1111",
            "device_id": "DEV-001",
            "expires_at": now + 100,
            "issued_at": now,
            "nonce": "n1"
        ], with: priv)

        XCTAssertEqual(
            client.validateSignedResponse(payloadRaw: raw, signatureBase64: sig, expectedNonce: "wrong", expectedDeviceID: "DEV-001", now: now),
            .failure(.nonceMismatch)
        )
        XCTAssertEqual(
            client.validateSignedResponse(payloadRaw: raw, signatureBase64: sig, expectedNonce: "n1", expectedDeviceID: "DEV-999", now: now),
            .failure(.deviceMismatch)
        )
        XCTAssertEqual(
            client.validateSignedResponse(payloadRaw: raw, signatureBase64: sig, expectedNonce: "n1", expectedDeviceID: "DEV-001", now: now + 500),
            .failure(.expired)
        )
        XCTAssertEqual(
            client.validateSignedResponse(payloadRaw: raw, signatureBase64: sig, expectedNonce: "n1", expectedDeviceID: "DEV-001", expectedKey: "OTHER-KEY", now: now),
            .failure(.keyMismatch)
        )
    }

    func testNormalizeGetKeyURL() {
        let u1 = LicenseClient.normalizeGetKeyURL("https://key.ktaov.vn/", deviceID: "DEV-123")
        XCTAssertEqual(u1?.absoluteString, "https://key.ktaov.vn/get-key/?code=DEV-123")

        let u2 = LicenseClient.normalizeGetKeyURL("https://key.ktaov.vn/get-key", deviceID: "DEV-123")
        XCTAssertEqual(u2?.absoluteString, "https://key.ktaov.vn/get-key/?code=DEV-123")

        XCTAssertNil(LicenseClient.normalizeGetKeyURL("javascript:alert(1)", deviceID: "DEV-123"))
        XCTAssertNil(LicenseClient.normalizeGetKeyURL("", deviceID: "DEV-123"))
    }
}
