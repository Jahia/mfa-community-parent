/**
 * Pure-JS TOTP (RFC 6238) generator for tests.
 *
 * Mirrors org.jahia.modules.upa.mfa.totp.TotpService:
 *   - HMAC-SHA1
 *   - 30-second time step
 *   - 6-digit codes
 *   - dynamic truncation (RFC 4226)
 *
 * Uses Node's `crypto` module via Cypress's Node-context. This file is loaded by
 * specs; calls to its functions are made synchronously inside `.then(...)` so the
 * code can be passed straight to a GraphQL mutation.
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const crypto = require('crypto');

const TIME_STEP_SECONDS = 30;
const DIGITS = 6;

/** RFC 4648 Base32 alphabet (no padding). */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decode an RFC 4648 Base32 string (padding tolerated, whitespace stripped).
 */
export function base32Decode(s: string): Buffer {
    const cleaned = s.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
    const bytes: number[] = [];
    let buffer = 0;
    let bitsLeft = 0;
    for (const ch of cleaned) {
        const idx = BASE32_ALPHABET.indexOf(ch);
        if (idx === -1) {
            throw new Error(`Invalid Base32 character: '${ch}'`);
        }
        buffer = (buffer << 5) | idx;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            bitsLeft -= 8;
            bytes.push((buffer >> bitsLeft) & 0xff);
        }
    }
    return Buffer.from(bytes);
}

/**
 * Compute the TOTP code for the given Base32 secret at `nowSeconds` (default: real now).
 */
export function totpCode(secretBase32: string, nowSeconds: number = Math.floor(Date.now() / 1000)): string {
    const secret = base32Decode(secretBase32);
    const counter = Math.floor(nowSeconds / TIME_STEP_SECONDS);
    return hotpCode(secret, counter);
}

/**
 * Pack a TOTP counter (a number well below 2^53) into 8 big-endian bytes,
 * without using BigInt or Buffer.writeBigUInt64BE — those aren't available in
 * the polyfilled `buffer` package that Cypress's webpack ships to the browser.
 */
function counterToBytes(counter: number): Uint8Array {
    const out = new Uint8Array(8);
    const high = Math.floor(counter / 0x100000000);
    // upper 32 bits
    out[0] = (high >>> 24) & 0xff;
    out[1] = (high >>> 16) & 0xff;
    out[2] = (high >>> 8) & 0xff;
    out[3] = high & 0xff;
    // lower 32 bits
    out[4] = (counter >>> 24) & 0xff;
    out[5] = (counter >>> 16) & 0xff;
    out[6] = (counter >>> 8) & 0xff;
    out[7] = counter & 0xff;
    return out;
}

/**
 * Compute the HOTP code for the given secret and counter (RFC 4226 dynamic truncation).
 */
export function hotpCode(secret: Buffer, counter: number): string {
    const counterBytes = counterToBytes(counter);
    const hash: Buffer = crypto.createHmac('sha1', secret).update(counterBytes).digest();
    const offset = hash[hash.length - 1] & 0x0f;
    const binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);
    const code = (binary % 1_000_000).toString().padStart(DIGITS, '0');
    return code;
}

/**
 * Compute a TOTP code for the NEXT 30-second window (used to test replay rejection
 * and to obtain a different code from the previous one without sleeping).
 */
export function nextWindowCode(secretBase32: string): string {
    const future = Math.floor(Date.now() / 1000) + TIME_STEP_SECONDS;
    return totpCode(secretBase32, future);
}
