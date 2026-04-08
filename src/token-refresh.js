const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

/**
 * Handles token refresh with rotation to prevent token reuse.
 * Each refresh generates a new refresh token and invalidates the old one.
 */
class TokenRefreshRotation {
  constructor(config = {}) {
    this.secret = config.secret || process.env.JWT_SECRET;
    this.refreshSecret = config.refreshSecret || process.env.JWT_REFRESH_SECRET;
    this.accessTokenExpiry = config.accessTokenExpiry || '15m';
    this.refreshTokenExpiry = config.refreshTokenExpiry || '7d';
    this.tokenStore = config.tokenStore || new Map();
  }

  /**
   * Generate a new access/refresh token pair.
   * @param {object} payload - User payload to encode.
   * @returns {{ accessToken: string, refreshToken: string, tokenId: string }}
   */
  generateTokenPair(payload) {
    const tokenId = uuidv4();

    const accessToken = jwt.sign(
      { ...payload, tokenId },
      this.secret,
      { expiresIn: this.accessTokenExpiry }
    );

    const refreshToken = jwt.sign(
      { userId: payload.userId, tokenId },
      this.refreshSecret,
      { expiresIn: this.refreshTokenExpiry }
    );

    // Store the refresh token ID with metadata
    this.tokenStore.set(tokenId, {
      userId: payload.userId,
      createdAt: Date.now(),
      consumed: false,
    });

    return { accessToken, refreshToken, tokenId };
  }

  /**
   * Rotate a refresh token: validate the old one and issue a new pair.
   * @param {string} oldRefreshToken - The refresh token to rotate.
   * @returns {{ accessToken: string, refreshToken: string, tokenId: string }}
   */
  rotateRefreshToken(oldRefreshToken) {
    try {
      const decoded = jwt.verify(oldRefreshToken, this.refreshSecret);
      const stored = this.tokenStore.get(decoded.tokenId);

      if (!stored) {
        throw new Error('TOKEN_NOT_FOUND');
      }

      if (stored.consumed) {
        // Token reuse detected — invalidate all tokens for this user
        this._invalidateAllUserTokens(stored.userId);
        throw new Error('TOKEN_REUSE_DETECTED');
      }

      // Mark the old token as consumed
      stored.consumed = true;

      // Generate a new token pair
      return this.generateTokenPair({ userId: stored.userId });
    } catch (err) {
      if (err.name === 'JsonWebTokenError') {
        throw new Error('INVALID_REFRESH_TOKEN');
      }
      throw err;
    }
  }

  /**
   * Invalidate all refresh tokens for a given user (compromise response).
   * @param {string} userId
   */
  _invalidateAllUserTokens(userId) {
    for (const [tokenId, meta] of this.tokenStore.entries()) {
      if (meta.userId === userId) {
        meta.consumed = true;
      }
    }
  }

  /**
   * Revoke a specific refresh token by its ID.
   * @param {string} tokenId
   */
  revokeToken(tokenId) {
    const stored = this.tokenStore.get(tokenId);
    if (stored) {
      stored.consumed = true;
    }
  }

  /**
   * Clean up expired tokens from the store.
   * @param {number} maxAgeMs - Max age in milliseconds.
   */
  cleanupExpiredTokens(maxAgeMs = 7 * 24 * 60 * 60 * 1000) {
    const now = Date.now();
    for (const [tokenId, meta] of this.tokenStore.entries()) {
      if (now - meta.createdAt > maxAgeMs) {
        this.tokenStore.delete(tokenId);
      }
    }
  }
}

module.exports = TokenRefreshRotation;
