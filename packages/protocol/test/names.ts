// Shared by the tests of App and alert channel names (slice 06b): one rule for both.

/** The one rule of App and alert channel names (slice 06b): refused inside a name. */
export const UNSAFE_NAMES = [
  "shop\r\nBcc: x@y.z",
  "shop\u0000web",
  "shop\u0007web",
  "shop\tweb",
  "shop\u007fweb",
  "shop\u0085web",
  "shop\u009fweb",
  "shop\u2028web",
  "shop\u2029web",
  "shop\u202aweb",
  "shop\u202eweb",
  "shop\u2066web",
  "shop\u2069web",
  "shop\u200bweb",
  "shop\ufeffweb",
  "shop\ud800web",
  "shop\udc00web",
];
/** Allowed: scripts, emoji with joiners, ZWNJ, and the LRM/RLM marks right-to-left text needs. */
export const SAFE_NAMES = [
  "Storefront",
  "Café Shop",
  "日本のショップ",
  "Shop 😀",
  "Team 👩\u200d💻",
  "می\u200cخواهم",
  "shop \u200eEU\u200f",
  "shop-web (EU)",
];
