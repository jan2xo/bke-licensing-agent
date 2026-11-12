import "dotenv/config";
import { afterAll, describe, expect, it } from "vitest";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@/platform/persistence/generated/prisma/client";
import {
  stageStartupMachineKeyInTransaction,
  activateStartupMachineKeyInTransaction,
  revokeStartupMachineKeyInTransaction,
} from "@/apps/web/agent-sessions/startup-machine-trust-admin";
import { prepareAndSignStandaloneStartupPolicyInTransaction } from
  "@/apps/web/agent-sessions/standalone-startup-policy-issuance";

// This file is copied into the EXACT DS checkout by the Agent-only CI job.
// It has no customer/admin route, network listener or production connection.
const eligible = (() => {
  if (process.env.GITHUB_ACTIONS !== "true" ||
      process.env.NODE_ENV !== "test" ||
      process.env.BKE_CROSS_REPO_STARTUP_SQL_PROOF !== "1") return false;
  try {
    const url = new URL(process.env.DATABASE_URL ?? "");
    return ["localhost", "127.0.0.1"].includes(url.hostname) &&
      url.port === "5432" && url.pathname === "/bke_test" &&
      Boolean(process.env.BKE_CROSS_REPO_STARTUP_INPUT) &&
      Boolean(process.env.BKE_CROSS_REPO_STARTUP_OUTPUT);
  } catch { return false; }
})();

type BridgeInput = Readonly<{
  schema: string; candidate: string; proof: string; fingerprint: string;
}>;
const fixture = eligible
  ? JSON.parse(readFileSync(process.env.BKE_CROSS_REPO_STARTUP_INPUT!, "utf8")) as BridgeInput
  : null;
const candidate = fixture ? JSON.parse(fixture.candidate) as {
  kid: string; device_id: string; public_key_pem: string;
} : null;
const attestation = fixture ? JSON.parse(fixture.proof) as {
  kid: string; payload: string; signature: string;
} : null;
const payload = attestation ? JSON.parse(attestation.payload) as {
  product_id: string; version: string; attestation_id: string;
  image_path: string; image_sha256: string; allowed_user_sid: string;
} : null;
const db = eligible ? new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL! }),
}) : null;
const stageAdminId = "ci-startup-stage-" + randomUUID();
const reviewAdminId = "ci-startup-review-" + randomUUID();
const issuer = generateKeyPairSync("ed25519");
const issuerKid = "ci-startup-policy-" + randomUUID();
const issuerPublic = issuer.publicKey.export({ format: "pem", type: "spki" }).toString();
const issuerKeyset = JSON.stringify({
  [issuerKid]: issuer.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
});
let productDatabaseId = "";
let installed = false;

describe.runIf(eligible)("actual .NET Agent → disposable DS SQL → .NET Agent", { concurrent: false }, () => {
  afterAll(async () => {
    if (!db) return;
    // Fully local disposable runner; never delete anything without exact fixture IDs.
    await db.$executeRaw`
      DELETE FROM "AgentStartupAttestationReceipt"
       WHERE "signerKid" = ${candidate!.kid}
    `.catch(() => undefined);
    await db.auditLog.deleteMany({
      where: { targetId: { in: [candidate!.kid, payload!.attestation_id] } },
    }).catch(() => undefined);
    if (productDatabaseId)
      await db.product.delete({ where: { id: productDatabaseId } }).catch(() => undefined);
    await db.$executeRaw`
      DELETE FROM "AgentStartupAttestationSigningKey" WHERE "kid" = ${candidate!.kid}
    `.catch(() => undefined);
    await db.$executeRaw`
      DELETE FROM "AccountProductLeaseSigningKey" WHERE "kid" = ${issuerKid}
    `.catch(() => undefined);
    await db.user.deleteMany({
      where: { id: { in: [stageAdminId, reviewAdminId] } },
    }).catch(() => undefined);
    await db.$disconnect();
  });

  it("requires two independent SQL ADMINs and actual .NET protected-key proof", async () => {
    expect(fixture?.schema).toBe("bke.agent-ds-agent-startup-handshake-fixture.v1");
    expect(fixture?.candidate).not.toContain("PRIVATE KEY");
    expect(fixture?.proof).not.toContain("PRIVATE KEY");
    expect(attestation?.kid).toBe(candidate?.kid);
    expect(payload?.image_path).toMatch(/^C:\\\\Program Files\\\\BKE Digital Solutions\\\\Render Dock\\\\RENDER DOCK\.exe$/);
    const der = Buffer.from(candidate!.public_key_pem.replace(
      /-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, ""), "base64");
    expect(createHash("sha256").update(der).digest("hex")).toBe(fixture!.fingerprint);

    await db!.user.createMany({ data: [
      { id: stageAdminId, email: "start-" + randomUUID() + "@bke.test",
        role: "ADMIN", lifecycleState: "ACTIVE" },
      { id: reviewAdminId, email: "review-" + randomUUID() + "@bke.test",
        role: "ADMIN", lifecycleState: "ACTIVE" },
    ] });
    const staged = await db!.$transaction(tx =>
      stageStartupMachineKeyInTransaction(tx, {
        candidate: fixture!.candidate,
        reviewedFingerprintSha256: fixture!.fingerprint,
      }, stageAdminId), { isolationLevel: "Serializable" });
    expect(staged.status).toBe("STAGED");
    await expect(db!.$transaction(tx =>
      activateStartupMachineKeyInTransaction(tx, {
        kid: candidate!.kid, confirmedFingerprintSha256: fixture!.fingerprint,
        freshSignedInstallProof: fixture!.proof,
      }, stageAdminId), { isolationLevel: "Serializable" }))
      .rejects.toThrow("MACHINE_KEY_INDEPENDENT_ADMIN_REQUIRED");

    const activated = await db!.$transaction(tx =>
      activateStartupMachineKeyInTransaction(tx, {
        kid: candidate!.kid, confirmedFingerprintSha256: fixture!.fingerprint,
        freshSignedInstallProof: fixture!.proof,
      }, reviewAdminId), { isolationLevel: "Serializable" });
    expect(activated.status).toBe("ACTIVE");
    const rows = await db!.$queryRaw<Array<{ status: string; stagedBy: string;
      activatedBy: string; activationProofSha256: string }>>`
      SELECT "status", "stagedBy", "activatedBy", "activationProofSha256"
        FROM "AgentStartupAttestationSigningKey" WHERE "kid" = ${candidate!.kid}
    `;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.stagedBy).toBe(stageAdminId);
    expect(rows[0]!.activatedBy).toBe(reviewAdminId);
    expect(rows[0]!.activationProofSha256).toBe(
      createHash("sha256").update(fixture!.proof).digest("hex"));
    installed = true;
  });

  it("issues a true SQL-owned LICENSE_KEY policy, burns the Agent nonce and exports only public proof", async () => {
    expect(installed).toBe(true);
    await db!.$executeRaw`
      INSERT INTO "AccountProductLeaseSigningKey"
        ("kid","publicKeyPem","privateKeyReference","status","activatedAt")
      VALUES (${issuerKid}, ${issuerPublic}, ${"keyset:" + issuerKid}, 'ACTIVE', now())
    `;
    const product = await db!.product.create({ data: {
      slug: "ci-agent-startup-" + randomUUID().slice(0, 8),
      productId: payload!.product_id,
      name: "Disposable signed startup",
      summary: "Private exact-byte cross-repository certification",
      description: "No customer product, publication or deployment",
      type: "SOFTWARE", active: false,
      launcherExecutionType: "STANDALONE", licenseType: "Commercial",
    } });
    productDatabaseId = product.id;
    await db!.$executeRaw`
      UPDATE "ProductActivationPolicy" SET "activationMode" = 'LICENSE_KEY'
       WHERE "productId" = ${product.id}
    `;
    await db!.product.update({ where: { id: product.id },
      data: { active: true, publishedAt: new Date() } });
    await db!.productVersion.create({ data: {
      productId: product.id, version: payload!.version,
      operatingSystem: "windows", architecture: "x64",
      lifecycle: "STABLE", active: true, publishedAt: new Date(),
    } });
    const result = await db!.$transaction(tx =>
      prepareAndSignStandaloneStartupPolicyInTransaction(tx, {
        signedAgentInstallAttestation: fixture!.proof,
        keyset: issuerKeyset,
      }), { isolationLevel: "Serializable", timeout: 10_000 });
    expect(result.mode).toBe("LICENSE_KEY");
    expect(result.productId).toBe(payload!.product_id);
    const outer = JSON.parse(result.envelope);
    const signed = JSON.parse(outer.payload);
    expect(signed.image_sha256).toBe(payload!.image_sha256);
    expect(signed.allowed_user_sid).toBe(payload!.allowed_user_sid);
    expect(signed.activation_mode).toBe("LICENSE_KEY");
    await expect(db!.$transaction(tx =>
      prepareAndSignStandaloneStartupPolicyInTransaction(tx, {
        signedAgentInstallAttestation: fixture!.proof,
        keyset: issuerKeyset,
      }), { isolationLevel: "Serializable" }))
      .rejects.toThrow("STARTUP_POLICY_ATTESTATION_REPLAY");
    const receipts = await db!.$queryRaw<Array<{ count: bigint }>>`
      SELECT COUNT(*)::bigint AS count FROM "AgentStartupAttestationReceipt"
       WHERE "attestationId" = ${payload!.attestation_id}::uuid
    `;
    expect(receipts[0]?.count).toBe(1n);
    const audit = await db!.auditLog.findFirst({ where: {
      action: "AGENT_STANDALONE_STARTUP_POLICY_ISSUED",
      targetId: payload!.attestation_id,
    } });
    expect(audit).not.toBeNull();
    expect(JSON.stringify(audit)).not.toContain("PRIVATE KEY");
    writeFileSync(process.env.BKE_CROSS_REPO_STARTUP_OUTPUT!,
      JSON.stringify({
        schema: "bke.ds-agent-startup-handshake-result.v1",
        envelope: result.envelope, kid: issuerKid, public_key_pem: issuerPublic,
      }), { encoding: "utf8", flag: "wx", mode: 0o600 });
  });

  it("terminal machine-key revocation blocks another DS authorization attempt", async () => {
    await db!.$transaction(tx => revokeStartupMachineKeyInTransaction(
      tx, candidate!.kid, reviewAdminId,
      "Ephemeral cross-repo certification completed"));
    const rows = await db!.$queryRaw<Array<{ status: string }>>`
      SELECT "status" FROM "AgentStartupAttestationSigningKey" WHERE "kid" = ${candidate!.kid}
    `;
    expect(rows[0]?.status).toBe("REVOKED");
    await expect(db!.$transaction(tx =>
      prepareAndSignStandaloneStartupPolicyInTransaction(tx, {
        signedAgentInstallAttestation: fixture!.proof,
        keyset: issuerKeyset,
      }), { isolationLevel: "Serializable" }))
      .rejects.toThrow("STARTUP_ATTESTATION_UNTRUSTED_AGENT");
  });
});
