// Sales reports for the shop's back office: turns a list of orders into per-tier and per-month summaries, a
// plain-text table for the dashboard and a CSV export. Real-size application code, so that the reference
// bundle has a file large enough to carry the Canaries and the Clone Beacon within the size budget.
import { discounted, format, priceOf } from "./pricing.ts";

/** One order as the shop's API returns it. */
export interface Order {
  id: string;
  /** ISO date, e.g. "2026-03-14". */
  date: string;
  tier: string;
  seats: number;
  /** Discount in percent, 0 to 100. */
  discountPct?: number;
  country?: string;
  refunded?: boolean;
}

/** The figures of one group of orders (a tier, a month or a country). */
export interface Summary {
  key: string;
  orders: number;
  seats: number;
  /** Net revenue in cents, after discounts and refunds. */
  revenue: number;
  refunds: number;
  /** Average net revenue per order, in cents (0 when there is no order). */
  average: number;
}

/** A finished report: its groups, the totals and the period it covers. */
export interface Report {
  title: string;
  from: string | null;
  to: string | null;
  groups: Summary[];
  total: Summary;
}

export type GroupBy = "tier" | "month" | "country";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Throws unless `date` is a real calendar date written as YYYY-MM-DD. */
export function checkDate(date: string): void {
  const match = DATE.exec(date);
  if (match === null) throw new Error(`invalid date: ${date}`);
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const probe = new Date(Date.UTC(year, month - 1, day));
  if (probe.getUTCFullYear() !== year || probe.getUTCMonth() !== month - 1 || probe.getUTCDate() !== day) {
    throw new Error(`invalid date: ${date}`);
  }
}

/** "2026-03-14" → "Mar 2026". */
export function monthLabel(date: string): string {
  checkDate(date);
  const month = Number(date.slice(5, 7));
  return `${MONTHS[month - 1]} ${date.slice(0, 4)}`;
}

/** The net value of one order in cents: seats × tier price, less its discount; 0 when refunded. */
export function orderValue(order: Order): number {
  if (!Number.isInteger(order.seats) || order.seats < 0) throw new Error(`invalid seats on order ${order.id}`);
  const pct = order.discountPct ?? 0;
  if (pct < 0 || pct > 100) throw new Error(`invalid discount on order ${order.id}`);
  if (order.refunded) return 0;
  return discounted(priceOf(order.tier) * order.seats, pct);
}

function keyOf(order: Order, by: GroupBy): string {
  if (by === "tier") return order.tier;
  if (by === "month") return order.date.slice(0, 7);
  return (order.country ?? "unknown").toUpperCase();
}

function emptySummary(key: string): Summary {
  return { key, orders: 0, seats: 0, revenue: 0, refunds: 0, average: 0 };
}

function add(summary: Summary, order: Order): void {
  summary.orders += 1;
  summary.seats += order.seats;
  summary.revenue += orderValue(order);
  if (order.refunded) summary.refunds += 1;
}

function finish(summary: Summary): Summary {
  return { ...summary, average: summary.orders === 0 ? 0 : Math.round(summary.revenue / summary.orders) };
}

/** Keeps the orders dated within [from, to] (inclusive; either end may be open). */
export function inPeriod(orders: readonly Order[], from: string | null, to: string | null): Order[] {
  if (from !== null) checkDate(from);
  if (to !== null) checkDate(to);
  if (from !== null && to !== null && from > to) throw new Error(`empty period: ${from} after ${to}`);
  return orders.filter((order) => {
    checkDate(order.date);
    return (from === null || order.date >= from) && (to === null || order.date <= to);
  });
}

/**
 * Summarises the orders of a period, grouped by tier, month or country. Groups are sorted by revenue (highest
 * first), then by key, so that the same orders always give the same report.
 */
export function buildReport(
  orders: readonly Order[],
  by: GroupBy,
  period: { from?: string | null; to?: string | null } = {},
): Report {
  const from = period.from ?? null;
  const to = period.to ?? null;
  const selected = inPeriod(orders, from, to);
  const groups = new Map<string, Summary>();
  const total = emptySummary("total");
  for (const order of selected) {
    const key = keyOf(order, by);
    let summary = groups.get(key);
    if (summary === undefined) {
      summary = emptySummary(key);
      groups.set(key, summary);
    }
    add(summary, order);
    add(total, order);
  }
  const sorted = [...groups.values()]
    .map(finish)
    .sort((a, b) => b.revenue - a.revenue || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const labels: Record<GroupBy, string> = {
    tier: "Revenue by tier",
    month: "Revenue by month",
    country: "Revenue by country",
  };
  return { title: labels[by], from, to, groups: sorted, total: finish(total) };
}

/** A share as a percentage with one decimal, e.g. 0.4567 → "45.7%". */
export function percent(part: number, whole: number): string {
  if (whole === 0) return "0.0%";
  return `${((part / whole) * 100).toFixed(1)}%`;
}

/** Each group's share of the total revenue, in the report's order. */
export function shares(report: Report): { key: string; share: string }[] {
  return report.groups.map((group) => ({ key: group.key, share: percent(group.revenue, report.total.revenue) }));
}

/** The change from one period's revenue to the next, e.g. "+12.5%", "-3.0%" or "new" when the first was 0. */
export function growth(previous: number, current: number): string {
  if (previous === 0) return current === 0 ? "0.0%" : "new";
  const change = ((current - previous) / previous) * 100;
  return `${change >= 0 ? "+" : ""}${change.toFixed(1)}%`;
}

function labelOf(report: Report, key: string): string {
  if (report.title === "Revenue by month" && /^\d{4}-\d{2}$/.test(key)) return monthLabel(`${key}-01`);
  return key;
}

function pad(text: string, width: number, right: boolean): string {
  const fill = " ".repeat(Math.max(0, width - [...text].length));
  return right ? fill + text : text + fill;
}

/** The report as a fixed-width text table, for the dashboard's "copy as text" button. */
export function renderTable(report: Report): string {
  const header = ["Group", "Orders", "Seats", "Revenue", "Average", "Share"];
  const rows = report.groups.map((group) => [
    labelOf(report, group.key),
    String(group.orders),
    String(group.seats),
    format(group.revenue),
    format(group.average),
    percent(group.revenue, report.total.revenue),
  ]);
  const total = report.total;
  rows.push([
    "Total",
    String(total.orders),
    String(total.seats),
    format(total.revenue),
    format(total.average),
    "100.0%",
  ]);
  const widths = header.map((title, column) =>
    Math.max(title.length, ...rows.map((row) => [...(row[column] ?? "")].length)),
  );
  const line = (cells: string[]) => cells.map((cell, column) => pad(cell, widths[column] ?? 0, column > 0)).join("  ");
  const rule = widths.map((width) => "-".repeat(width)).join("  ");
  const period =
    report.from === null && report.to === null ? "all time" : `${report.from ?? "…"} to ${report.to ?? "…"}`;
  return [
    `${report.title} (${period})`,
    line(header),
    rule,
    ...rows.slice(0, -1).map(line),
    rule,
    line(rows.at(-1) ?? []),
  ].join("\n");
}

/** Quotes a CSV field when it holds a separator, a quote or a line break (RFC 4180). */
export function csvField(value: string | number): string {
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** The report as CSV with a header row; amounts in cents, so that a spreadsheet can sum them exactly. */
export function toCsv(report: Report): string {
  const lines = [["group", "orders", "seats", "revenue_cents", "refunds", "average_cents"].join(",")];
  for (const group of [...report.groups, report.total]) {
    lines.push(
      [group.key, group.orders, group.seats, group.revenue, group.refunds, group.average].map(csvField).join(","),
    );
  }
  return `${lines.join("\r\n")}\r\n`;
}

/** The best-selling groups by seats, at most `count` of them. */
export function topBySeats(report: Report, count: number): Summary[] {
  return [...report.groups].sort((a, b) => b.seats - a.seats || (a.key < b.key ? -1 : 1)).slice(0, count);
}
