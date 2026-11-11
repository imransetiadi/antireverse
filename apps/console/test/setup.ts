// Vitest globals are off, so Testing Library neither registers its cleanup nor sets the act flag itself.
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => cleanup());
