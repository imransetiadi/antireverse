// The address as the daily confirmation-mail caps count it (review F1): one inbox, one count. A `+tag` is dropped for
// every domain (most providers deliver `name+tag@` to `name@`), and for Gmail, which ignores dots in the local part and
// treats googlemail.com as gmail.com, the dots go too. Only for counting: mail still goes to the address as given.

const GMAIL_DOMAINS = new Set(["gmail.com", "googlemail.com"]);

/** The address the caps count: `+tag` dropped; for Gmail also the dots, and googlemail.com read as gmail.com. */
export function capAddress(address: string): string {
  const at = address.lastIndexOf("@");
  let local = address.slice(0, at);
  let domain = address.slice(at + 1);
  const plus = local.indexOf("+");
  if (plus > 0) local = local.slice(0, plus);
  if (GMAIL_DOMAINS.has(domain)) {
    domain = "gmail.com";
    local = local.replaceAll(".", "") || local;
  }
  return `${local}@${domain}`;
}
