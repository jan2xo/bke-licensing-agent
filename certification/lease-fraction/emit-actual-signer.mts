// L1 TS producer: invoke the REAL @bke/licensing issuer at a pinned Git SHA.
// Every key here is a deterministic public TEST seed. No production services.
import { createPrivateKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [vectorPath, providerPath, outputPath] = process.argv.slice(2);
if (!vectorPath || !providerPath || !outputPath) {
  throw new Error("Usage: emit-actual-signer <vectors.json> <provider.ts> <producer.json>");
}

const fixture = JSON.parse(readFileSync(vectorPath, "utf8"));
if (fixture.schema !== "bke.lease-vectors.v1" ||
    fixture.libraryContract !== "bke.product-lease.v1") {
  throw new Error("Unexpected lease-vector contract");
}

const { issueAccountProductLeaseJws } =
  await import(pathToFileURL(providerPath).href);
if (typeof issueAccountProductLeaseJws !== "function") {
  throw new Error("Real TypeScript signing export is missing");
}

// Canonical public synthetic Ed25519 seed: 32 bytes of 0x42.
const pem = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, 0x42),
  ]),
  format: "der",
  type: "pkcs8",
}).export({ format: "pem", type: "pkcs8" }).toString();

const valid = fixture.vectors.find((v: {name: string}) => v.name === "valid");
if (!valid?.jws) throw new Error("Canonical signed valid vector missing");
const decodedClaims = JSON.parse(
  Buffer.from(valid.jws.split(".")[1], "base64url").toString("utf8"),
);
const signer = { kid: fixture.activeKid, privateKeyPem: pem };
const regenerated = issueAccountProductLeaseJws(decodedClaims, signer);
if (regenerated !== valid.jws) {
  throw new Error("Production TypeScript signer disagrees with pinned vector bytes");
}
const useJws = issueAccountProductLeaseJws({
  ...decodedClaims,
  leaseId: "vector-lease-use-001",
  allowedActions: ["USE"],
}, signer);

writeFileSync(outputPath, JSON.stringify({
  schema: "bke.lease-fraction-producer.v1",
  validJws: regenerated,
  useJws,
}, null, 2) + "\n", { mode: 0o600 });
console.log("Real TypeScript issuer emitted byte-identical OPEN and independent USE leases.");
