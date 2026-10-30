import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import jsQR from 'jsqr';
import QRCode from 'qrcode';

test('serves the same jsQR decoder used to recognize TOTP QR codes', async () => {
  const data = await QRCode.toBuffer('otpauth://totp/UGOS:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=UGOS', { type: 'png', width: 320, margin: 2 });
  const png = await import('pngjs').then(({ PNG }) => PNG.sync.read(Buffer.from(data)));
  const result = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  assert.ok(result);
  const uri = new URL(result.data);
  assert.equal(uri.protocol, 'otpauth:');
  assert.equal(uri.hostname, 'totp');
  assert.equal(uri.searchParams.get('secret'), 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');
});

test('Worker route serves the decoder without third-party dependencies', async () => {
  const source = await readFile(new URL('./worker.js', import.meta.url), 'utf8');
  assert.match(source, /self\.jsQR=\$\{jsQR\.toString\(\)\}/);
  assert.match(source, /getImageData\(0, 0, bitmap\.width, bitmap\.height\)/);
});
