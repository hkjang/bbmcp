/**
 * BrandMark is the bbmcp logo: a bucket (Bitbucket) whose contents are funnelled
 * through a gate into a single MCP node, with the gate drawn as a shield to say
 * "permission checked". It is a plain inline SVG so it needs no asset loading
 * and renders identically in an air-gapped install.
 */
export function BrandMark({ size = 32, title = 'bbmcp' }: { size?: number; title?: string }) {
  const id = 'bbmcp-brand'
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      role="img"
      aria-label={title}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id={`${id}-bg`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#2b7cff" />
          <stop offset="55%" stopColor="#1f6feb" />
          <stop offset="100%" stopColor="#0b4fbb" />
        </linearGradient>
        <linearGradient id={`${id}-sheen`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.28" />
          <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
        </linearGradient>
      </defs>

      <rect x="2" y="2" width="60" height="60" rx="15" fill={`url(#${id}-bg)`} />
      <rect x="2" y="2" width="60" height="30" rx="15" fill={`url(#${id}-sheen)`} />

      {/* Bucket: the repository side, narrowing downward. */}
      <path
        d="M15 15h34l-4.2 15.5H19.2L15 15z"
        fill="#ffffff"
        fillOpacity="0.95"
      />
      <path d="M26.4 21.2h11.2l-1.5 5.6h-8.2l-1.5-5.6z" fill="#1f6feb" />

      {/* Permission gate, drawn as a shield. */}
      <path
        d="M32 33.2l7.6 2.6v5.1c0 4.6-3.1 8.2-7.6 9.9-4.5-1.7-7.6-5.3-7.6-9.9v-5.1L32 33.2z"
        fill="#ffffff"
        fillOpacity="0.95"
      />
      <path
        d="M28.6 41.4l2.6 2.7 4.4-4.7"
        fill="none"
        stroke="#1f6feb"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* MCP node links leaving the gate. */}
      <circle cx="51" cy="44" r="3.4" fill="#ffffff" fillOpacity="0.95" />
      <circle cx="13" cy="44" r="3.4" fill="#ffffff" fillOpacity="0.95" />
      <path
        d="M41.2 42.2h6.2M16.4 42.2h6.2"
        stroke="#ffffff"
        strokeOpacity="0.95"
        strokeWidth="2.4"
        strokeLinecap="round"
      />
    </svg>
  )
}
