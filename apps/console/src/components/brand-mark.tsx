// The brand mark: a shield around a code caret that doubles as the letter "A". The crossbar is a request trace
// that leaves through an opening in the shield. Shapes copied from brand/mark-on-dark.svg
// (test/brand-mark.test.tsx keeps the two in step). Decorative — the brand name always follows it as text.
export function BrandMark({ className = "size-6" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      strokeWidth="5.5"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={`shrink-0 ${className}`}
    >
      <path d="M53 29.5 V14 L32 7 L11 14 V34 C11 44 20 53 32 58 C44 53 53 44 53 40.5" stroke="currentColor" />
      <path d="M20.5 44 L32 19 L43.5 44" stroke="currentColor" strokeLinecap="round" />
      <path d="M27.5 35 H60" className="stroke-primary" strokeLinecap="round" />
    </svg>
  );
}
