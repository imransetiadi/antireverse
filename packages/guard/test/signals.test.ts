import { describe, expect, it } from "vitest";
import { createGuard, type GuardNavigator } from "../src/index.js";
import { APP_ID, cleanNavigator, ENDPOINT, UA } from "./helpers.ts";

const signalsOf = (navigator: GuardNavigator | null) =>
  createGuard({ appId: APP_ID, endpoint: ENDPOINT, navigator }).signals();

describe("Signals v1", () => {
  it("a clean desktop Chrome shows none", () => {
    expect(signalsOf(cleanNavigator())).toEqual([]);
  });

  describe("automation.webdriver", () => {
    it("is on when navigator.webdriver is true", () => {
      expect(signalsOf(cleanNavigator({ webdriver: true }))).toEqual(["automation.webdriver"]);
    });
    it.each([false, undefined])("is off when navigator.webdriver is %s", (webdriver) => {
      const navigator = cleanNavigator();
      if (webdriver === undefined) delete navigator.webdriver;
      else navigator.webdriver = webdriver;
      expect(signalsOf(navigator)).toEqual([]);
    });
    it("is off for a truthy value that is not true", () => {
      expect(signalsOf(cleanNavigator({ webdriver: "true" as unknown as boolean }))).toEqual([]);
    });
  });

  describe("automation.headless", () => {
    it("is on for a HeadlessChrome user agent", () => {
      const navigator = cleanNavigator({
        userAgent: UA.headlessLinux,
        platform: "Linux x86_64",
        userAgentData: { platform: "Linux" },
      });
      expect(signalsOf(navigator)).toEqual(["automation.headless"]);
    });
    it.each([
      ["missing", undefined],
      ["empty", { length: 0 }],
    ])("is on when plugins are %s and the UA claims desktop Chrome", (_name, plugins) => {
      const navigator = cleanNavigator();
      if (plugins === undefined) delete navigator.plugins;
      else navigator.plugins = plugins;
      expect(signalsOf(navigator)).toEqual(["automation.headless"]);
    });
    it("is off when plugins are absent on mobile Chrome", () => {
      const navigator = {
        userAgent: UA.chromeAndroid,
        platform: "Linux armv8l",
        plugins: { length: 0 },
        userAgentData: { platform: "Android" },
      };
      expect(signalsOf(navigator)).toEqual([]);
    });
    it("is off when plugins are absent on a browser that is not Chrome", () => {
      expect(signalsOf({ userAgent: UA.firefoxLinux, platform: "Linux x86_64", plugins: { length: 0 } })).toEqual([]);
    });
  });

  describe("env.inconsistent", () => {
    it("is on when the UA says Windows and navigator.platform says Mac", () => {
      expect(signalsOf(cleanNavigator({ platform: "MacIntel", userAgentData: null }))).toEqual(["env.inconsistent"]);
    });
    it("is on when the UA says Mac and userAgentData says Windows", () => {
      const navigator = cleanNavigator({ userAgent: UA.chromeMac, platform: "MacIntel" });
      expect(signalsOf(navigator)).toEqual(["env.inconsistent"]);
    });
    it("is on when the UA says Windows and navigator.platform says Linux", () => {
      expect(signalsOf(cleanNavigator({ platform: "Linux x86_64", userAgentData: null }))).toEqual([
        "env.inconsistent",
      ]);
    });
    it.each([
      ["Mac", UA.chromeMac, "MacIntel", "macOS"],
      ["Android with a Linux platform", UA.chromeAndroid, "Linux armv8l", "Android"],
      ["iPhone", UA.safariIphone, "iPhone", undefined],
      ["Linux", UA.firefoxLinux, "Linux x86_64", undefined],
      ["Windows with Win64", UA.chromeWindows, "Win64", "Windows"],
    ])("is off for a consistent %s", (_name, userAgent, platform, uaPlatform) => {
      const navigator: GuardNavigator = { userAgent, platform, plugins: { length: 5 } };
      if (uaPlatform) navigator.userAgentData = { platform: uaPlatform };
      expect(signalsOf(navigator)).toEqual([]);
    });
    it("is off when the platform is unknown or empty", () => {
      expect(signalsOf(cleanNavigator({ platform: "", userAgentData: { platform: "" } }))).toEqual([]);
      expect(signalsOf(cleanNavigator({ platform: "PlayStation 5", userAgentData: null }))).toEqual([]);
    });
  });

  it("lists several signals in the canonical order", () => {
    const navigator = cleanNavigator({ webdriver: true, userAgent: UA.headlessLinux, userAgentData: null });
    expect(signalsOf(navigator)).toEqual(["automation.webdriver", "automation.headless", "env.inconsistent"]);
  });

  it("returns a fresh array each time", () => {
    const guard = createGuard({ appId: APP_ID, endpoint: ENDPOINT, navigator: cleanNavigator({ webdriver: true }) });
    const first = guard.signals();
    first.push("automation.headless");
    expect(guard.signals()).toEqual(["automation.webdriver"]);
  });

  it("is empty without a navigator", () => {
    expect(signalsOf(null)).toEqual([]);
  });
});
