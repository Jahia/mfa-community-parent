import { afterEach, describe, expect, it, vi } from "vitest";
import totpStatus from "./totpStatus";
import disableTotp from "./disableTotp";
import regenerateBackupCodes from "./regenerateBackupCodes";
import webauthnStatus from "./webauthnStatus";
import renameWebauthnCredential from "./renameWebauthnCredential";
import deleteWebauthnCredential from "./deleteWebauthnCredential";

const API = "/modules/graphql";

/** Stub global.fetch to return one JSON payload (a GraphQL response envelope). */
function mockGraphql(payload: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve({ json: () => Promise.resolve(payload) } as Response)),
  );
}

/** A top-level GraphQL error envelope (e.g. a server DataFetchingException). */
const errorEnvelope = { errors: [{ message: "factor.totp.invalid_code" }], data: null };

describe("self-service MFA settings services", () => {
  afterEach(() => vi.unstubAllGlobals());

  describe("totpStatus", () => {
    it("parses an enrolled status", async () => {
      mockGraphql({ data: { mfaTotp: { status: { enrolled: true, hasBackupCodes: true, remainingBackupCodes: 7 } } } });
      const res = await totpStatus(API);
      expect(res).toEqual({ success: true, enrolled: true, hasBackupCodes: true, remainingBackupCodes: 7 });
    });

    it("surfaces a top-level error", async () => {
      mockGraphql(errorEnvelope);
      const res = await totpStatus(API);
      expect(res.success).toBe(false);
    });

    it("returns a network error when fetch rejects", async () => {
      vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("offline"))));
      const res = await totpStatus(API);
      expect(res).toMatchObject({ success: false, error: { code: "network_error" } });
    });
  });

  describe("disableTotp", () => {
    it("succeeds when the mutation returns a session", async () => {
      mockGraphql({ data: { upa: { mfaFactors: { totp: { disable: { session: { initiated: false } } } } } } });
      expect((await disableTotp(API, "123456")).success).toBe(true);
    });

    it("fails on an invalid-code top-level error", async () => {
      mockGraphql(errorEnvelope);
      expect((await disableTotp(API, "000000")).success).toBe(false);
    });
  });

  describe("regenerateBackupCodes", () => {
    it("returns the fresh codes", async () => {
      mockGraphql({ data: { upa: { mfaFactors: { totp: { regenerateBackupCodes: { backupCodes: ["AAAA", "BBBB"] } } } } } });
      const res = await regenerateBackupCodes(API, "123456");
      expect(res).toEqual({ success: true, backupCodes: ["AAAA", "BBBB"] });
    });
  });

  describe("webauthnStatus", () => {
    it("parses supported + credentials", async () => {
      mockGraphql({
        data: {
          mfaWebauthn: {
            supported: true,
            status: { registered: true, credentials: [{ credentialId: "c1", nickname: "Key", signCount: 1, createdAt: null, lastUsedAt: null, transports: [], aaguid: null }] },
          },
        },
      });
      const res = await webauthnStatus(API);
      expect(res).toMatchObject({ success: true, supported: true, registered: true });
      if (res.success) {
        expect(res.credentials).toHaveLength(1);
      }
    });

    it("reports unavailable (soft-wire) when the mfaWebauthn type is absent from the schema", async () => {
      // Bundle not installed → Jahia returns a ValidationError-classified top-level error (data:null).
      // (Real shape verified against a webauthn-absent Jahia node.)
      mockGraphql({
        errors: [
          {
            message: "Validation error (FieldUndefined@[mfaWebauthn]) : Field 'mfaWebauthn' in type 'Query' is undefined",
            extensions: { classification: "ValidationError" },
          },
        ],
        data: null,
      });
      const res = await webauthnStatus(API);
      expect(res).toEqual({ success: false, unavailable: true });
    });

    it("surfaces a runtime error (not unavailable) when the error is not a ValidationError", async () => {
      // Execution error (data present/null, no ValidationError classification) → normal error path,
      // so a genuine backend failure still shows an error rather than silently hiding the section.
      mockGraphql(errorEnvelope);
      const res = await webauthnStatus(API);
      expect(res.success).toBe(false);
      expect(res).not.toHaveProperty("unavailable");
    });
  });

  describe("rename / delete credential", () => {
    it("rename succeeds on boolean true", async () => {
      mockGraphql({ data: { upa: { mfaFactors: { webauthn: { renameCredential: true } } } } });
      expect((await renameWebauthnCredential(API, "c1", "Laptop")).success).toBe(true);
    });

    it("delete fails when the mutation does not return true", async () => {
      mockGraphql({ data: { upa: { mfaFactors: { webauthn: { deleteCredential: false } } } } });
      expect((await deleteWebauthnCredential(API, "c1")).success).toBe(false);
    });
  });
});
