import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { prisma } from '../lib/prisma';
import request from 'supertest';
import { createApp } from '../index';
import { generateToken } from '../utils/jwt.util';
import { Express } from 'express';

describe('Predictions Routes - Auth Identity Binding (Issue #64)', () => {
  let app: Express;
  let userA: any;
  let userB: any;
  let userAToken: string;
  let userBToken: string;
  let testRound: any;

  beforeAll(async () => {
    app = createApp();

    userA = await prisma.user.create({
      data: {
        walletAddress: 'GUSER_A_PRED_TEST_AAAAAAAAAAAAAAAA',
        virtualBalance: 1000,
      },
    });

    userB = await prisma.user.create({
      data: {
        walletAddress: 'GUSER_B_PRED_TEST_BBBBBBBBBBBBBBBB',
        virtualBalance: 500,
      },
    });

    userAToken = generateToken(userA.id, userA.walletAddress);
    userBToken = generateToken(userB.id, userB.walletAddress);
  });

  beforeEach(async () => {
    // Create a fresh round for each test
    testRound = await prisma.round.create({
      data: {
        mode: 'UP_DOWN',
        status: 'ACTIVE',
        startPrice: 0.1234,
        startTime: new Date(),
        endTime: new Date(Date.now() + 300000), // 5 minutes
        poolUp: 0,
        poolDown: 0,
      },
    });
  });

  afterAll(async () => {
    await prisma.prediction.deleteMany({});
    await prisma.round.deleteMany({});
    await prisma.user.deleteMany({
      where: { id: { in: [userA.id, userB.id] } },
    });
    await prisma.$disconnect();
  });

  describe('POST /api/predictions/submit - user identity enforcement', () => {
    it('should use authenticated user ID (not body userId)', async () => {
      const res = await request(app)
        .post('/api/predictions/submit')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          roundId: testRound.id,
          amount: 100,
          side: 'UP',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.prediction).toBeDefined();

      // Verify the prediction was created for userA (from token, not body)
      const prediction = await prisma.prediction.findUnique({
        where: { id: res.body.prediction.id },
      });

      expect(prediction).not.toBeNull();
      expect(prediction!.userId).toBe(userA.id);

      // Verify userA's balance was deducted
      const updatedUserA = await prisma.user.findUnique({
        where: { id: userA.id },
      });
      expect(updatedUserA!.virtualBalance).toBe(900); // 1000 - 100
    });

    it('should ignore userId in request body if provided', async () => {
      // Even if the client tries to pass userB's ID, it should be ignored
      const res = await request(app)
        .post('/api/predictions/submit')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          roundId: testRound.id,
          userId: userB.id, // Attempting to impersonate userB
          amount: 50,
          side: 'DOWN',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Verify the prediction was created for userA (from token), NOT userB
      const prediction = await prisma.prediction.findUnique({
        where: { id: res.body.prediction.id },
      });

      expect(prediction).not.toBeNull();
      expect(prediction!.userId).toBe(userA.id); // Should be userA
      expect(prediction!.userId).not.toBe(userB.id); // Should NOT be userB

      // Verify userA's balance was deducted, not userB's
      const updatedUserA = await prisma.user.findUnique({
        where: { id: userA.id },
      });
      const updatedUserB = await prisma.user.findUnique({
        where: { id: userB.id },
      });

      expect(updatedUserA!.virtualBalance).toBe(850); // 900 - 50 (from previous test)
      expect(updatedUserB!.virtualBalance).toBe(500); // Unchanged
    });

    it('should prevent user from making predictions on behalf of others', async () => {
      // UserA tries to submit prediction as userB
      const res = await request(app)
        .post('/api/predictions/submit')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          roundId: testRound.id,
          userId: userB.id, // Malicious attempt
          amount: 200,
          side: 'UP',
        });

      expect(res.status).toBe(200); // Request succeeds, but uses userA's identity

      // Verify userB was NOT affected
      const userBPredictions = await prisma.prediction.findMany({
        where: { userId: userB.id },
      });
      expect(userBPredictions.length).toBe(0); // No predictions for userB

      // Verify userA made the prediction
      const userAPredictions = await prisma.prediction.findMany({
        where: { userId: userA.id },
      });
      expect(userAPredictions.length).toBeGreaterThan(0);
    });
  });

  describe('POST /api/predictions/submit - validation', () => {
    it('should reject missing roundId', async () => {
      const res = await request(app)
        .post('/api/predictions/submit')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          amount: 100,
          side: 'UP',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Round ID is required');
    });

    it('should reject missing amount', async () => {
      const res = await request(app)
        .post('/api/predictions/submit')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          roundId: testRound.id,
          side: 'UP',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid amount');
    });

    it('should reject invalid amount (negative)', async () => {
      const res = await request(app)
        .post('/api/predictions/submit')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          roundId: testRound.id,
          amount: -50,
          side: 'UP',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid amount');
    });

    it('should reject amount=0', async () => {
      const res = await request(app)
        .post('/api/predictions/submit')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          roundId: testRound.id,
          amount: 0,
          side: 'UP',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid amount');
    });

    it('should require authentication', async () => {
      const res = await request(app)
        .post('/api/predictions/submit')
        .send({
          roundId: testRound.id,
          amount: 100,
          side: 'UP',
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
    });
  });
});
