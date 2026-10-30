import assert from 'node:assert/strict';
import test from 'node:test';
import { generateTotp, normalizeTotpSecret } from './totp.js';

// RFC 6238 SHA-1 test vectors converted from eight digits to UGOS's six digits.
const vectors = [
  [59_000, '94287082'],
  [1_111_111_109_000, '07081804'],
  [1_111_111_111_000, '14050471'],
  [1_234_567_890_000, '89005924'],
  [2_000_000_000_000, '69279037'],
  [20_000_000_000_000, '65353130'],
];

test('generates RFC-compatible six-digit TOTP codes', async () => {
  for (const [timestamp, expected] of vectors) {
    assert.equal(await generateTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', timestamp), expected.slice(-6));
  }
});

test('accepts spaced Base32 secrets and otpauth URIs', () => {
  assert.equal(normalizeTotpSecret(' jbsw y3dp ehpk 3pxp ==== '), 'JBSWY3DPEHPK3PXP');
  assert.equal(normalizeTotpSecret('otpauth://totp/NAS:admin?secret=JBSWY3DPEHPK3PXP&issuer=UGOS'), 'JBSWY3DPEHPK3PXP');
});

test('rejects invalid TOTP configuration', async () => {
  for (const value of ['123456', 'not-base32!', 'otpauth://hotp/NAS?secret=JBSWY3DPEHPK3PXP']) {
    assert.equal(normalizeTotpSecret(value), null);
  }
  assert.equal(normalizeTotpSecret(''), '');
  assert.equal(normalizeTotpSecret(undefined), '');
});
