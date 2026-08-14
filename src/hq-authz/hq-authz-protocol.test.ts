import { describe, expect, it } from 'vitest';

import {
  buildHqAuthzBody,
  signHqAuthzRequest,
  splitPermission,
} from './hq-authz-protocol';

describe('splitPermission', () => {
  it('uses explicit action', () => {
    expect(splitPermission('contracts', 'write')).toEqual({
      feature: 'contracts',
      action: 'write',
    });
  });

  it('splits feature/action on slash', () => {
    expect(splitPermission('contracts/write')).toEqual({
      feature: 'contracts',
      action: 'write',
    });
  });

  it('defaults action to read', () => {
    expect(splitPermission('contracts')).toEqual({
      feature: 'contracts',
      action: 'read',
    });
  });
});

describe('buildHqAuthzBody', () => {
  it('produces canonical body with resolved permission', () => {
    const body = buildHqAuthzBody({
      clerkUserId: 'user_123',
      email: null,
      productSlug: 'soundlaunch',
      feature: 'contracts',
      action: 'write',
    });
    expect(body).toBe(
      JSON.stringify({
        clerkUserId: 'user_123',
        email: null,
        productSlug: 'soundlaunch',
        feature: 'contracts',
        action: 'write',
      }),
    );
  });
});

describe('signHqAuthzRequest', () => {
  it('builds the exact canonical string and HMAC-SHA256 (known vector)', () => {
    const method = 'POST';
    const path = '/internal/authz/check';
    const timestamp = '1700000000';
    const nonce = 'test-nonce-1234';
    const body = JSON.stringify({
      clerkUserId: 'user_123',
      email: null,
      productSlug: 'soundlaunch',
      feature: 'contracts',
      action: 'write',
    });
    const clientSecret = 'test-secret';

    const signature = signHqAuthzRequest({
      method,
      path,
      timestamp,
      nonce,
      body,
      clientSecret,
    });

    // Known vector, computed independently:
    //   bodyHash  = sha256(body)
    //   canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`
    expect(signature).toBe(
      'acd1f0db397f23b7bac7d783fdd411f902b57cc7f87a40e3433b5fb08921bc5f',
    );
  });

  it('is order-sensitive: different nonce -> different signature', () => {
    const common = {
      method: 'POST',
      path: '/internal/authz/check',
      timestamp: '1700000000',
      body: '{"a":1}',
      clientSecret: 'test-secret',
    };
    const a = signHqAuthzRequest({ ...common, nonce: 'n1' });
    const b = signHqAuthzRequest({ ...common, nonce: 'n2' });
    expect(a).not.toBe(b);
  });
});
