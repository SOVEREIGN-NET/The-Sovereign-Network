import { describe, it, expect } from 'vitest';
import {
  SdkError,
  IdentityError,
  WalletError,
  DomainError,
  DeploymentError,
  NetworkError,
  ValidationError,
} from '../../src/error.js';

describe('Error Types', () => {
  describe('SdkError', () => {
    it('creates error with type and context', () => {
      const error = new SdkError('Identity', { key: 'value' }, 'Something went wrong');
      expect(error.type).toBe('Identity');
      expect(error.context).toEqual({ key: 'value' });
      expect(error.message).toBe('Something went wrong');
      expect(error instanceof Error).toBe(true);
    });

    it('carries multiple context fields', () => {
      const error = new SdkError('Network', {
        endpoint: 'quic://node.zhtp:5555',
        timeout: 5000,
        retries: 3,
      }, 'Connection failed');
      expect(error.context.endpoint).toBe('quic://node.zhtp:5555');
      expect(error.context.timeout).toBe(5000);
      expect(error.context.retries).toBe(3);
    });

    it('has proper Error stack trace', () => {
      const error = new SdkError('Domain', {}, 'Test error');
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('SdkError');
    });
  });

  describe('IdentityError', () => {
    it('creates identity-specific error', () => {
      const error = new IdentityError('Failed to load identity', { keystorePath: '/home/user/.zhtp' });
      expect(error.type).toBe('Identity');
      expect(error.context.keystorePath).toBe('/home/user/.zhtp');
    });

    it('preserves message and context', () => {
      const error = new IdentityError('DID mismatch', { expected: 'did:zhtp:abc', got: 'did:zhtp:def' });
      expect(error.message).toBe('DID mismatch');
      expect(error.context.expected).toBe('did:zhtp:abc');
      expect(error.context.got).toBe('did:zhtp:def');
    });
  });

  describe('WalletError', () => {
    it('creates wallet-specific error', () => {
      const error = new WalletError('Insufficient balance', {
        required: 1000n,
        available: 500n,
      });
      expect(error.type).toBe('Wallet');
      expect(error.context.required).toBe(1000n);
      expect(error.context.available).toBe(500n);
    });
  });

  describe('DomainError', () => {
    it('creates domain-specific error', () => {
      const error = new DomainError('Domain already registered', {
        domain: 'test.zhtp',
        owner: 'z123...',
      });
      expect(error.type).toBe('Domain');
      expect(error.context.domain).toBe('test.zhtp');
    });
  });

  describe('DeploymentError', () => {
    it('creates deployment-specific error', () => {
      const error = new DeploymentError('Deployment failed', {
        domain: 'app.zhtp',
        step: 'upload',
      });
      expect(error.type).toBe('Deployment');
      expect(error.context.domain).toBe('app.zhtp');
      expect(error.context.step).toBe('upload');
    });
  });

  describe('NetworkError', () => {
    it('creates network-specific error', () => {
      const error = new NetworkError('QUIC connection timeout', {
        host: 'node.zhtp',
        port: 5555,
        timeout: 5000,
      });
      expect(error.type).toBe('Network');
      expect(error.context.host).toBe('node.zhtp');
      expect(error.context.timeout).toBe(5000);
    });
  });

  describe('ValidationError', () => {
    it('creates validation error with accumulated issues', () => {
      const issues = [
        { field: 'domain', message: 'must start with alphanumeric' },
        { field: 'fee', message: 'must be positive' },
      ];
      const error = new ValidationError('Validation failed', issues, {
        domainValue: '-invalid',
        feeValue: -100,
      });
      expect(error.type).toBe('Validation');
      expect(error.errors).toEqual(issues);
      expect(error.errors.length).toBe(2);
    });

    it('carries validation issues and context together', () => {
      const issues = [{ field: 'address', message: 'Invalid format' }];
      const error = new ValidationError('Address validation failed', issues, {
        input: 'bad-address',
        allowedFormats: ['z...'],
      });
      expect(error.errors[0].field).toBe('address');
      expect(error.context.input).toBe('bad-address');
    });

    it('handles empty validation issues', () => {
      const error = new ValidationError('No issues', [], { reason: 'test' });
      expect(error.errors).toEqual([]);
    });
  });

  describe('Error inheritance', () => {
    it('all error types are instances of Error', () => {
      const errors = [
        new IdentityError('test', {}),
        new WalletError('test', {}),
        new DomainError('test', {}),
        new DeploymentError('test', {}),
        new NetworkError('test', {}),
        new ValidationError('test', [], {}),
      ];

      errors.forEach(error => {
        expect(error instanceof Error).toBe(true);
        expect(error.type).toBeDefined();
      });
    });

    it('ValidationError has errors property', () => {
      const error = new ValidationError('test', [], {});
      expect(error.errors).toBeDefined();
      expect(Array.isArray(error.errors)).toBe(true);
    });
  });
});
