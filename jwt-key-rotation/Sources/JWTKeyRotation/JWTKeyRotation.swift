import JWTKit

/// Example implementation of a simple key rotation manager.
/// This demonstrates how to build rotation logic on top of JWTKeyCollection primitives.
public actor KeyRotationManager {
    private var keyCollection: JWTKeyCollection
    private var currentKeyId: JWKIdentifier
    private var previousKeyIds: Set<JWKIdentifier>

    /// Initialize the manager with the first key
    public init(initialKey: some ECDSAKey, keyId: JWKIdentifier) async {
        keyCollection = .init()
        currentKeyId = keyId
        previousKeyIds = []

        await keyCollection.add(ecdsa: initialKey, kid: keyId)
    }

    /// Rotate to a new key while keeping the previous key active
    /// This starts the grace period where both keys can verify tokens
    public func rotateKey(
        newKey: ECDSA.PrivateKey<some ECDSACurveType>, newKeyId: JWKIdentifier
    ) async {
        previousKeyIds.insert(currentKeyId)
        currentKeyId = newKeyId

        await keyCollection.add(ecdsa: newKey, kid: newKeyId)
    }

    /// Remove old keys after the grace period has ended
    /// Call this after all tokens signed with old keys have expired
    public func removeOldKeys() async {
        await self.keyCollection.removeAll(except: [currentKeyId])
    }

    /// Sign a new token with the current key
    public func signToken(_ payload: some JWTPayload) async throws -> String {
        try await keyCollection.sign(payload, kid: currentKeyId)
    }

    /// Verify any token (will work with current or previous keys during grace period)
    public func verifyToken<Payload: JWTPayload>(
        _ token: String, as: Payload.Type
    ) async throws -> Payload {
        try await keyCollection.verify(token, as: Payload.self)
    }
}
