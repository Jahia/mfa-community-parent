/**
 * Pure-JS TOTP (RFC 6238) generator for tests.
 *
 * Mirrors org.jahia.modules.upa.mfa.totp.TotpService:
 *   - HMAC-SHA1
 *   - 30-second time step
 *   - 6-digit codes
 *   - dynamic truncation (RFC 4226)
 *
 * Self-contained: HMAC-SHA1 is implemented below on Uint8Array, with no Node `crypto`
 * or `Buffer`. Specs run in the browser, and since Cypress 15 the default spec bundler
 * no longer polyfills Node core modules, so `require('crypto')` there yields an empty
 * module. Web Crypto would work but is asynchronous; these functions stay synchronous
 * so specs can call them inside `.then(...)` and pass the code straight to a mutation.
 */

const TIME_STEP_SECONDS = 30;
const DIGITS = 6;

/** RFC 4648 Base32 alphabet (no padding). */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decode an RFC 4648 Base32 string (padding tolerated, whitespace stripped).
 */
export function base32Decode(s: string): Uint8Array {
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
    return Uint8Array.from(bytes);
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
 * without BigInt or Buffer.writeBigUInt64BE, neither of which the browser bundle can rely on.
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

const SHA1_BLOCK_BYTES = 64;

/** SHA-1 (FIPS 180-4) of `message`. Test-only: SHA-1 is what RFC 6238 TOTP uses here. */
function sha1(message: Uint8Array): Uint8Array {
    const bitLength = message.length * 8;
    const paddedLength = Math.ceil((message.length + 9) / SHA1_BLOCK_BYTES) * SHA1_BLOCK_BYTES;
    const padded = new Uint8Array(paddedLength);
    padded.set(message);
    padded[message.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000));
    view.setUint32(paddedLength - 4, bitLength >>> 0);

    let h0 = 0x67452301;
    let h1 = 0xefcdab89;
    let h2 = 0x98badcfe;
    let h3 = 0x10325476;
    let h4 = 0xc3d2e1f0;
    const w = new Uint32Array(80);
    for (let block = 0; block < paddedLength; block += SHA1_BLOCK_BYTES) {
        for (let i = 0; i < 16; i++) {
            w[i] = view.getUint32(block + i * 4);
        }
        for (let i = 16; i < 80; i++) {
            const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (x << 1) | (x >>> 31);
        }
        let a = h0;
        let b = h1;
        let c = h2;
        let d = h3;
        let e = h4;
        for (let i = 0; i < 80; i++) {
            let f: number;
            let k: number;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }
            const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) >>> 0;
            e = d;
            d = c;
            c = (b << 30) | (b >>> 2);
            b = a;
            a = temp;
        }
        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }
    const digest = new Uint8Array(20);
    const out = new DataView(digest.buffer);
    [h0, h1, h2, h3, h4].forEach((h, i) => out.setUint32(i * 4, h));
    return digest;
}

/** HMAC-SHA1 (RFC 2104). */
function hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
    const blockKey = new Uint8Array(SHA1_BLOCK_BYTES);
    blockKey.set(key.length > SHA1_BLOCK_BYTES ? sha1(key) : key);
    const inner = new Uint8Array(SHA1_BLOCK_BYTES + message.length);
    const outer = new Uint8Array(SHA1_BLOCK_BYTES + 20);
    for (let i = 0; i < SHA1_BLOCK_BYTES; i++) {
        inner[i] = blockKey[i] ^ 0x36;
        outer[i] = blockKey[i] ^ 0x5c;
    }
    inner.set(message, SHA1_BLOCK_BYTES);
    outer.set(sha1(inner), SHA1_BLOCK_BYTES);
    return sha1(outer);
}

/**
 * Compute the HOTP code for the given secret and counter (RFC 4226 dynamic truncation).
 */
export function hotpCode(secret: Uint8Array, counter: number): string {
    const hash = hmacSha1(secret, counterToBytes(counter));
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
