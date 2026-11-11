import { randomFillSync } from "node:crypto";

const HEX: string[] = [];
for (let i = 0; i < 256; i++) HEX.push((i + 0x100).toString(16).slice(1));

// One randomFillSync call costs about the same for 16 bytes as for 4,096: draw random bytes from a pool.
const POOL_SIZE = 4096;
const BYTES_PER_ID = 10;
const pool = new Uint8Array(POOL_SIZE);
let poolPos = POOL_SIZE;
let lastMs = 0;
let seq = 0; // 12-bit counter in rand_a: strict order within one millisecond
const bytes = new Uint8Array(16);

/**
 * A UUID version 7 (RFC 9562) for the given time in milliseconds.
 * Monotonic per process: a time earlier than the previous one is clamped forward, so identifiers never go backwards.
 */
export function uuidv7(nowMs: number): string {
  if (poolPos + BYTES_PER_ID > POOL_SIZE) {
    randomFillSync(pool);
    poolPos = 0;
  }
  let ms = Math.floor(nowMs);
  if (!(ms > lastMs)) {
    // the same millisecond, a clock that went backwards, or not a number at all
    ms = lastMs;
    seq = (seq + 1) & 0xfff;
    if (seq === 0) ms = lastMs + 1; // counter overflow: borrow the next millisecond
  } else {
    seq = (((pool[poolPos] as number) << 8) | (pool[poolPos + 1] as number)) & 0x7ff;
  }
  lastMs = ms;
  // Division, not shifts: bit operators truncate to 32 bits.
  bytes[0] = Math.floor(ms / 0x10000000000) & 0xff;
  bytes[1] = Math.floor(ms / 0x100000000) & 0xff;
  bytes[2] = Math.floor(ms / 0x1000000) & 0xff;
  bytes[3] = Math.floor(ms / 0x10000) & 0xff;
  bytes[4] = Math.floor(ms / 0x100) & 0xff;
  bytes[5] = ms & 0xff;
  bytes[6] = 0x70 | (seq >>> 8); // version 7
  bytes[7] = seq & 0xff;
  bytes[8] = ((pool[poolPos + 2] as number) & 0x3f) | 0x80; // variant 10xx
  for (let i = 9; i < 16; i++) bytes[i] = pool[poolPos + i - 6] as number;
  poolPos += BYTES_PER_ID;
  let id = "";
  for (let i = 0; i < 16; i++) {
    id += HEX[bytes[i] as number];
    if (i === 3 || i === 5 || i === 7 || i === 9) id += "-";
  }
  return id;
}
