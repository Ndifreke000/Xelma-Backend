import crypto from 'crypto';

const CHALLENGE_EXPIRY_MINUTES = 5; // Challenges expire after 5 minutes

/**
 * Generate a cryptographically secure random challenge string
 * Following SEP-style challenge pattern
 * @returns Random challenge string
 */
export function generateChallenge(): string {
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(32).toString('hex');

  // Create a challenge in the format: "xelma_auth_[timestamp]_[random]"
  return `xelma_auth_${timestamp}_${randomBytes}`;
}

/**
 * Calculate expiration date for a challenge
 * @returns Date object representing challenge expiration
 */
export function getChallengeExpiry(): Date {
  const expiry = new Date();
  expiry.setMinutes(expiry.getMinutes() + CHALLENGE_EXPIRY_MINUTES);
  return expiry;
}

/**
 * Check if a challenge has expired
 * @param expiresAt Expiration date of the challenge
 * @returns True if expired, false otherwise
 */
export function isChallengeExpired(expiresAt: Date): boolean {
  return new Date() > expiresAt;
}

/**
 * Get the challenge expiry duration in seconds
 * @returns Challenge expiry duration in seconds
 */
export function getChallengeExpirySeconds(): number {
  return CHALLENGE_EXPIRY_MINUTES * 60;
}
