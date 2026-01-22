import { Router, Request, Response } from 'express';
import { prisma } from '../lib/prisma';
import { generateChallenge, getChallengeExpiry, isChallengeExpired } from '../utils/challenge.util';
import { generateToken } from '../utils/jwt.util';
import { verifySignature, isValidStellarAddress } from '../services/stellar.service';
import {
  ChallengeRequestBody,
  ChallengeResponse,
  ConnectRequestBody,
  ConnectResponse,
} from '../types/auth.types';
import { challengeRateLimiter, connectRateLimiter } from '../middleware/rateLimiter.middleware';

const router = Router();

/**
 * POST /api/auth/challenge
 * Step 1: Request a challenge for wallet authentication
 *
 * Security Features:
 * - Rate limited: 10 requests per 15 minutes per IP
 * - Generates cryptographically secure random challenge
 * - Challenge expires after 5 minutes
 * - Validates wallet address format
 */
router.post('/challenge', challengeRateLimiter, async (req: Request, res: Response) => {
  try {
    const { walletAddress }: ChallengeRequestBody = req.body;

    // Validate required fields
    if (!walletAddress) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'walletAddress is required',
      });
    }

    // Validate Stellar address format
    if (!isValidStellarAddress(walletAddress)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Invalid Stellar wallet address format',
      });
    }

    // Clean up expired challenges for this wallet (housekeeping)
    await prisma.authChallenge.deleteMany({
      where: {
        walletAddress,
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    // Generate new challenge
    const challenge = generateChallenge();
    const expiresAt = getChallengeExpiry();

    // Store challenge in database
    await prisma.authChallenge.create({
      data: {
        challenge,
        walletAddress,
        expiresAt,
        isUsed: false,
      },
    });

    const response: ChallengeResponse = {
      challenge,
      expiresAt: expiresAt.toISOString(),
    };

    return res.status(200).json(response);
  } catch (error) {
    console.error('Error generating challenge:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to generate authentication challenge',
    });
  }
});

/**
 * POST /api/auth/connect
 * Step 2: Verify signature and authenticate wallet
 *
 * Security Features:
 * - Rate limited: 5 requests per 15 minutes per IP
 * - Verifies Stellar signature using Ed25519
 * - Implements replay protection (one-time use challenges)
 * - Validates challenge expiration
 * - Creates/updates user record
 * - Returns signed JWT with expiry
 */
router.post('/connect', connectRateLimiter, async (req: Request, res: Response) => {
  try {
    const { walletAddress, challenge, signature }: ConnectRequestBody = req.body;

    // Validate required fields
    if (!walletAddress || !challenge || !signature) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'walletAddress, challenge, and signature are required',
      });
    }

    // Validate Stellar address format
    if (!isValidStellarAddress(walletAddress)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Invalid Stellar wallet address format',
      });
    }

    // Find the challenge in database
    const authChallenge = await prisma.authChallenge.findUnique({
      where: {
        challenge,
      },
    });

    // Validate challenge exists
    if (!authChallenge) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: 'Invalid or expired challenge',
      });
    }

    // Validate challenge belongs to this wallet
    if (authChallenge.walletAddress !== walletAddress) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: 'Challenge does not match wallet address',
      });
    }

    // Check if challenge has expired
    if (isChallengeExpired(authChallenge.expiresAt)) {
      // Delete expired challenge
      await prisma.authChallenge.delete({
        where: { id: authChallenge.id },
      });

      return res.status(401).json({
        error: 'Authentication Error',
        message: 'Challenge has expired. Please request a new one.',
      });
    }

    // Replay protection: Check if challenge has been used
    if (authChallenge.isUsed) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: 'Challenge has already been used',
      });
    }

    // Verify the signature using Stellar SDK
    const isValidSignature = await verifySignature(walletAddress, challenge, signature);

    if (!isValidSignature) {
      return res.status(401).json({
        error: 'Authentication Error',
        message: 'Invalid signature',
      });
    }

    // Mark challenge as used (replay protection)
    await prisma.authChallenge.update({
      where: { id: authChallenge.id },
      data: {
        isUsed: true,
        usedAt: new Date(),
      },
    });

    // Create or update user record
    let user = await prisma.user.findUnique({
      where: { walletAddress },
    });

    const now = new Date();

    if (!user) {
      // Create new user
      user = await prisma.user.create({
        data: {
          walletAddress,
          publicKey: walletAddress,
          lastLoginAt: now,
        },
      });
    } else {
      // Update existing user's last login
      user = await prisma.user.update({
        where: { walletAddress },
        data: {
          lastLoginAt: now,
        },
      });
    }

    // Link challenge to user
    await prisma.authChallenge.update({
      where: { id: authChallenge.id },
      data: {
        userId: user.id,
      },
    });

    // Generate JWT token
    const token = generateToken(user.id, user.walletAddress);

    // Clean up old used challenges for this user (housekeeping)
    await prisma.authChallenge.deleteMany({
      where: {
        walletAddress,
        isUsed: true,
        usedAt: {
          lt: new Date(Date.now() - 24 * 60 * 60 * 1000), // Older than 24 hours
        },
      },
    });

    const response: ConnectResponse = {
      token,
      user: {
        id: user.id,
        walletAddress: user.walletAddress,
        createdAt: user.createdAt.toISOString(),
        lastLoginAt: user.lastLoginAt?.toISOString() || now.toISOString(),
      },
    };

    return res.status(200).json(response);
  } catch (error) {
    console.error('Error authenticating wallet:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to authenticate wallet',
    });
  }
});

export default router;
