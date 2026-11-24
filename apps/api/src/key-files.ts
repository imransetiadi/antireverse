// The secret files that lie beside the data directory, like the directory's lock. `startApi` creates each on the
// first start; a backup of the data directory is only whole with them (slice 18h).

/** The file name of the signing key. It lies beside the data directory, like the directory's lock. */
export const SIGNING_KEY_FILE = "signing-key.json";
/** The file name of the attestation key set: beside the data directory too, a separate file and key purpose. */
export const ATTESTATION_KEY_FILE = "attestation-keys.json";
/** The file name of the audit key (slice 18a): beside the others, a separate file and key purpose. */
export const AUDIT_KEY_FILE = "audit-key.json";
/** The file name of the secret that keys the per-address count of confirmation mails (slice 06b), beside the others. */
export const ADDRESS_KEY_FILE = "mail-hash-key.json";
/** The file name of the month salts of the Guard device references (slice 17a, review M3), beside the others. */
export const USAGE_SALTS_FILE = "usage-salts.json";

/** Every file `startApi` keeps beside the data directory. A file added there must be added here, or a backup loses it. */
export const KEY_FILES: readonly string[] = [
  SIGNING_KEY_FILE,
  ATTESTATION_KEY_FILE,
  AUDIT_KEY_FILE,
  ADDRESS_KEY_FILE,
  USAGE_SALTS_FILE,
];
