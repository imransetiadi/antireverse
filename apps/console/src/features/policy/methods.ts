// The methods the add-Rule form offers, in the order it shows them. The contract allows any HTTP method
// on a Rule; the Console offers the five that carry almost all API traffic. No method chosen means all.
export const RULE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type RuleMethod = (typeof RULE_METHODS)[number];
