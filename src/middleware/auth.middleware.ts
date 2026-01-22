import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt.util';
import { JwtPayload } from '../types/auth.types';

// Extend Express Request type to include user
export interface AuthRequest extends Request {
  user?: JwtPayload;
}

/**
 * Authentication middleware to protect routes
 * Verifies JWT token from Authorization header
 *
 * Usage:
 * router.get('/protected', authenticateToken, (req: AuthRequest, res) => {
 *   const user = req.user; // Access authenticated user info
 * });
 */
export function authenticateToken(req: AuthRequest, res: Response, next: NextFunction): void {
  try {
    // Get token from Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.substring(7)
      : null;

    if (!token) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Access token is required',
      });
      return;
    }

    // Verify token
    const decoded = verifyToken(token);

    if (!decoded) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid or expired token',
      });
      return;
    }

    // Attach user info to request
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error in authentication middleware:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Authentication failed',
    });
  }
}

/**
 * Optional authentication middleware
 * Attaches user info if valid token is provided, but doesn't block the request
 *
 * Usage:
 * router.get('/optional-auth', optionalAuthentication, (req: AuthRequest, res) => {
 *   if (req.user) {
 *     // User is authenticated
 *   } else {
 *     // User is not authenticated (but that's okay)
 *   }
 * });
 */
export function optionalAuthentication(req: AuthRequest, res: Response, next: NextFunction): void {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.substring(7)
      : null;

    if (token) {
      const decoded = verifyToken(token);
      if (decoded) {
        req.user = decoded;
      }
    }

    next();
  } catch (error) {
    // Don't block the request on error, just continue without user info
    next();
  }
}
