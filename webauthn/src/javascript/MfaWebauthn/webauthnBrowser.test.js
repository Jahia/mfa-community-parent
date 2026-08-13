import {describe, it, expect} from 'vitest';
import {b64uToBuf, bufToB64u} from './webauthnBrowser';

// The yubico server speaks base64url (no padding, "-"/"_" instead of "+"/"/") for credential ids
// and challenges. A padding-remainder bug here would silently corrupt every credential id and
// challenge sent to/from the authenticator, so every possible 4-char-group padding remainder
// (0,1,2,3 extra bytes beyond a multiple of 3) is exercised via buffer lengths 0..4.
describe('bufToB64u / b64uToBuf round trip', () => {
    for (let len = 0; len <= 4; len++) {
        it(`round-trips a buffer of length ${len} through bufToB64u -> b64uToBuf`, () => {
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = ((i * 53) + 7) % 256;
            }

            const encoded = bufToB64u(bytes.buffer);
            const decoded = new Uint8Array(b64uToBuf(encoded));

            expect(Array.from(decoded)).toEqual(Array.from(bytes));
        });
    }

    it('produces a URL-safe string: no "+", "/" or "=" padding characters', () => {
        // Chosen so the standard (non-url-safe) base64 alphabet would emit both "+" (sextet 62)
        // and "/" (sextet 63): 0xFB=11111011, 0xFF=11111111, 0xBF=10111111 -> sextets 62,63,62,63.
        const bytes = new Uint8Array([0xFB, 0xFF, 0xBF]);

        const encoded = bufToB64u(bytes.buffer);

        expect(encoded).not.toMatch(/[+/=]/);
        expect(encoded).toMatch(/[-_]/);
    });

    it('decodes the "-"/"_" url-safe substitutions back to the original bytes', () => {
        const bytes = new Uint8Array([0xFB, 0xFF, 0xBF]);
        const encoded = bufToB64u(bytes.buffer);

        expect(Array.from(new Uint8Array(b64uToBuf(encoded)))).toEqual([0xFB, 0xFF, 0xBF]);
    });
});
