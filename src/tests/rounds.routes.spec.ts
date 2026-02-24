import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { prisma } from '../lib/prisma';
import request from 'supertest';
import { createApp } from '../index';
import { generateToken } from '../utils/jwt.util';
import { Express } from 'express';

describe('Rounds Routes - Mode Validation (Issue #63)', () => {
  let app: Express;
  let adminUser: any;
  let adminToken: string;

  beforeAll(async () => {
    app = createApp();

    adminUser = await prisma.user.create({
      data: {
        walletAddress: 'GADMIN_MODE_TEST_AAAAAAAAAAAAAAAAA',
        role: 'ADMIN',
        virtualBalance: 1000,
      },
    });

    adminToken = generateToken(adminUser.id, adminUser.walletAddress);
  });

  afterAll(async () => {
    await prisma.round.deleteMany({});
    await prisma.user.deleteMany({ where: { id: adminUser.id } });
    await prisma.$disconnect();
  });

  describe('POST /api/rounds/start - mode validation', () => {
    it('should accept mode=0 (UP_DOWN) without falsy rejection', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          mode: 0,
          startPrice: 0.1234,
          duration: 300,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.round).toBeDefined();
      expect(res.body.round.mode).toBe('UP_DOWN');

      // Cleanup
      await prisma.round.delete({ where: { id: res.body.round.id } });
    });

    it('should accept mode=1 (LEGENDS)', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          mode: 1,
          startPrice: 0.1234,
          duration: 300,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.round).toBeDefined();
      expect(res.body.round.mode).toBe('LEGENDS');

      // Cleanup
      await prisma.round.delete({ where: { id: res.body.round.id } });
    });

    it('should reject mode=-1 as invalid', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          mode: -1,
          startPrice: 0.1234,
          duration: 300,
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid mode');
    });

    it('should reject mode=2 as out of range', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          mode: 2,
          startPrice: 0.1234,
          duration: 300,
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid mode');
    });

    it('should reject mode as string', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          mode: 'UP_DOWN',
          startPrice: 0.1234,
          duration: 300,
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid mode');
    });

    it('should reject missing mode (undefined)', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          startPrice: 0.1234,
          duration: 300,
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid mode');
    });

    it('should reject mode=null', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          mode: null,
          startPrice: 0.1234,
          duration: 300,
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid mode');
    });
  });

  describe('POST /api/rounds/start - startPrice and duration validation', () => {
    it('should reject startPrice=0 (edge case for falsy check)', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          mode: 0,
          startPrice: 0,
          duration: 300,
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid start price');
    });

    it('should reject duration=0 (edge case for falsy check)', async () => {
      const res = await request(app)
        .post('/api/rounds/start')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          mode: 0,
          startPrice: 0.1234,
          duration: 0,
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid duration');
    });
  });
});
