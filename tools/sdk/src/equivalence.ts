// The second run of the equivalence check (slice 23, D-143). Some product tests have a wall-clock budget and can
// fail when the machine is busy. A test file with any result that is not "passed" is run once more, alone, in the
// same mode (source or compiled output), and that result counts. Nothing is dropped: after the second run every
// test must still have passed in both modes and the two modes must agree test by test, so a test that fails for a
// reason, or differs for a reason, fails the check as before.

export interface RunReport {
  numTotalTests: number;
  numPassedTests: number;
  numFailedTests: number;
  numPendingTests: number;
  numTodoTests: number;
  testResults: Array<{ name: string; status: string; assertionResults: Array<{ fullName: string; status: string }> }>;
}

/** The files (as the report names them) with a test that did not pass, or that failed as a whole. Sorted. */
export function notPassedFiles(report: RunReport): string[] {
  return report.testResults
    .filter((file) => file.status !== "passed" || file.assertionResults.some((a) => a.status !== "passed"))
    .map((file) => file.name)
    .sort();
}

/**
 * The first run with the results of `files` taken from the second run. A file is replaced only when the second run
 * reports it with every test the first run had: a second run cannot make a test disappear or bring in another file.
 */
export function mergeRerun(first: RunReport, second: RunReport, files: readonly string[]): RunReport {
  const testResults = first.testResults.map((file) => {
    if (!files.includes(file.name)) return file;
    const again = second.testResults.find((candidate) => candidate.name === file.name);
    if (again === undefined) return file;
    const names = new Set(again.assertionResults.map((a) => a.fullName));
    if (again.assertionResults.length === 0 || file.assertionResults.some((a) => !names.has(a.fullName))) return file;
    return again;
  });
  const all = testResults.flatMap((file) => file.assertionResults);
  const count = (...statuses: string[]) => all.filter((a) => statuses.includes(a.status)).length;
  return {
    numTotalTests: all.length,
    numPassedTests: count("passed"),
    numFailedTests: count("failed"),
    numPendingTests: count("pending", "skipped"),
    numTodoTests: count("todo"),
    testResults,
  };
}
