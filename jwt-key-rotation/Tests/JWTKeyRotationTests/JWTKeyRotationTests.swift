import JWTKeyRotation
import JWTKit
import Testing

#if !canImport(Darwin)
    import FoundationEssentials
#else
    import Foundation
#endif

@Suite("Key Rotation Manager Tests")
struct KeyRotationManagerTests {
    @Test("Rotation flow")
    func rotationFlow() async throws {
        let manager = await KeyRotationManager(
            initialKey: ES256PrivateKey(),
            keyId: "old"
        )

        let oldPayload = TestPayload(
            sub: SubjectClaim(value: "old-user"),
            name: "Test",
            admin: false,
            exp: ExpirationClaim(value: Date().addingTimeInterval(3600))
        )

        let oldToken = try await manager.signToken(oldPayload)

        // Rotate to new key
        await manager.rotateKey(
            newKey: ES256PrivateKey(),
            newKeyId: "new"
        )

        let newPayload = TestPayload(
            sub: SubjectClaim(value: "new-user"),
            name: "Test",
            admin: false,
            exp: ExpirationClaim(value: Date().addingTimeInterval(3600))
        )

        let newToken = try await manager.signToken(newPayload)

        // Verify both work during grace period
        _ = try await manager.verifyToken(oldToken, as: TestPayload.self)
        _ = try await manager.verifyToken(newToken, as: TestPayload.self)

        // Remove old keys (grace period over)
        await manager.removeOldKeys()

        // New token still works
        let verifiedNew = try await manager.verifyToken(newToken, as: TestPayload.self)
        #expect(verifiedNew.sub.value == "new-user")

        // Old token should fail
        await #expect(throws: JWTError.noKeyProvided) {
            _ = try await manager.verifyToken(oldToken, as: TestPayload.self)
        }
    }

    @Test("Multiple rotations")
    func multipleRotations() async throws {
        // First key
        let manager = await KeyRotationManager(
            initialKey: ES256PrivateKey(),
            keyId: "v1"
        )

        let payload1 = TestPayload(
            sub: SubjectClaim(value: "user-v1"),
            name: "Test",
            admin: false,
            exp: ExpirationClaim(value: Date().addingTimeInterval(3600))
        )

        let token1 = try await manager.signToken(payload1)

        // Rotate to v2
        await manager.rotateKey(
            newKey: ES256PrivateKey(),
            newKeyId: "v2"
        )

        let payload2 = TestPayload(
            sub: SubjectClaim(value: "user-v2"),
            name: "Test",
            admin: false,
            exp: ExpirationClaim(value: Date().addingTimeInterval(3600))
        )

        let token2 = try await manager.signToken(payload2)

        // Rotate to v3
        await manager.rotateKey(
            newKey: ES256PrivateKey(),
            newKeyId: "v3"
        )

        let payload3 = TestPayload(
            sub: SubjectClaim(value: "user-v3"),
            name: "Test",
            admin: false,
            exp: ExpirationClaim(value: Date().addingTimeInterval(3600))
        )

        let token3 = try await manager.signToken(payload3)

        // All three tokens should verify
        let verified1 = try await manager.verifyToken(token1, as: TestPayload.self)
        let verified2 = try await manager.verifyToken(token2, as: TestPayload.self)
        let verified3 = try await manager.verifyToken(token3, as: TestPayload.self)

        #expect(verified1.sub.value == "user-v1")
        #expect(verified2.sub.value == "user-v2")
        #expect(verified3.sub.value == "user-v3")

        await manager.removeOldKeys()

        // Only v3 should work now
        let verified3Again = try await manager.verifyToken(token3, as: TestPayload.self)
        #expect(verified3Again.sub.value == "user-v3")

        // v1 and v2 should fail
        await #expect(throws: JWTError.noKeyProvided) {
            _ = try await manager.verifyToken(token1, as: TestPayload.self)
        }
        await #expect(throws: JWTError.noKeyProvided) {
            _ = try await manager.verifyToken(token2, as: TestPayload.self)
        }
    }
}

struct TestPayload: JWTPayload, Equatable {
    var sub: SubjectClaim
    var name: String
    var admin: Bool
    var exp: ExpirationClaim

    func verify(using _: some JWTAlgorithm) throws {
        try exp.verifyNotExpired()
    }
}
