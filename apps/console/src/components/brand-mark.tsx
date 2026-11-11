// The brand mark: an "A" whose way back is cut off by a barrier. Shapes copied from brand/mark-on-dark.svg
// (test/brand-mark.test.tsx keeps the two in step). Decorative — the brand name always follows it as text.
export function BrandMark({ className = "size-6" }: { className?: string }) {
  return (
    <svg viewBox="6 6 52 52" aria-hidden="true" focusable="false" className={`shrink-0 ${className}`}>
      <path
        d="M13.00 52.00 L28.00 12.00 L36.00 12.00 L43.69 32.50 L36.31 32.50 L32.00 21.00 L20.38 52.00 Z"
        fill="currentColor"
      />
      <rect x="24.18" y="37.0" width="27.82" height="6.5" rx="0.8" className="fill-primary" />
    </svg>
  );
}
