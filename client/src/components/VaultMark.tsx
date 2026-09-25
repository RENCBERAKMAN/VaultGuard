interface VaultMarkProps {
  size?: number;
  className?: string;
}

export function VaultMark({ size = 40, className = "" }: VaultMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="vg-orbit" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
                    <stop offset="0" stopColor="#5B8DEF" />
          <stop offset="1" stopColor="#8B7FE8" />
        </linearGradient>
      </defs>
      <ellipse
        cx="24"
        cy="24"
        rx="21"
        ry="10"
        transform="rotate(-28 24 24)"
        stroke="url(#vg-orbit)"
        strokeWidth="1.4"
        opacity="0.55"
      />
      <circle cx="24" cy="24" r="7" stroke="currentColor" strokeWidth="1.5" />
      <path
        d="M20.5 24v-2.4a3.5 3.5 0 0 1 7 0V24"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <rect x="19.5" y="24" width="9" height="6" rx="1.3" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="41.5" cy="13.5" r="2" fill="url(#vg-orbit)" />
    </svg>
  );
}