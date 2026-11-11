import { toProblemErrors } from "@antireverse/protocol";
import { zValidator } from "@hono/zod-validator";
import type { ZodType } from "zod";
import { problem } from "./problem.ts";

/** Validates the JSON body against `schema`; a body that does not fit is a 400 problem naming each path. */
export function validateJson<S extends ZodType>(schema: S) {
  return zValidator("json", schema, (result, c) => {
    if (!result.success) return problem(c, "validation", toProblemErrors(result.error));
  });
}

/** Validates the query string against `schema`; a value that does not fit is a 400 problem naming each path. */
export function validateQuery<S extends ZodType>(schema: S) {
  return zValidator("query", schema, (result, c) => {
    if (!result.success) return problem(c, "validation", toProblemErrors(result.error));
  });
}
