import { afterEach, describe, expect, it } from 'vitest';

import { getHqClientSecret } from './hq-authz-client';

const ENV_KEYS = ['HQ_CLIENT_SECRET', 'HQ_CLIENT_SECRETS'] as const;

afterEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
});

describe('getHqClientSecret', () => {
  it('returns the single HQ_CLIENT_SECRET when set', () => {
    process.env.HQ_CLIENT_SECRET = 'single-secret';
    expect(getHqClientSecret('any-id')).toBe('single-secret');
  });

  it('resolves the secret for a clientId from HQ_CLIENT_SECRETS lines', () => {
    process.env.HQ_CLIENT_SECRETS = 'hq-primary:secret-one\nother:secret-two';
    expect(getHqClientSecret('hq-primary')).toBe('secret-one');
    expect(getHqClientSecret('other')).toBe('secret-two');
  });

  it('preserves colons inside the secret value', () => {
    process.env.HQ_CLIENT_SECRETS = 'hq-primary:sec:ret:with:colons';
    expect(getHqClientSecret('hq-primary')).toBe('sec:ret:with:colons');
  });

  it('returns undefined for an unknown clientId', () => {
    process.env.HQ_CLIENT_SECRETS = 'hq-primary:secret-one';
    expect(getHqClientSecret('missing')).toBeUndefined();
  });

  it('handles CRLF line endings', () => {
    process.env.HQ_CLIENT_SECRETS = 'hq-primary:secret-one\r\nother:secret-two\r\n';
    expect(getHqClientSecret('other')).toBe('secret-two');
  });
});
