import React from 'react'

type AegisLogoProps = {
  compact?: boolean
  light?: boolean
  className?: string
}

export const AegisLogo: React.FC<AegisLogoProps> = ({ compact = false, light = false, className = '' }) => (
  <div className={`aegis-logo ${compact ? 'aegis-logo--compact' : ''} ${light ? 'aegis-logo--light' : ''} ${className}`.trim()} aria-label="AegisScan">
    <span className="aegis-logo__mark" aria-hidden="true">
      <svg viewBox="0 0 64 64" role="img">
        <defs>
          <linearGradient id="aegis-logo-gradient" x1="10" y1="10" x2="54" y2="54">
            <stop offset="0" stopColor="#7dd3fc" />
            <stop offset="0.5" stopColor="#38bdf8" />
            <stop offset="1" stopColor="#2563eb" />
          </linearGradient>
        </defs>
        <path d="M32 5 52 13v15c0 13.8-8.2 24.8-20 30C20.2 52.8 12 41.8 12 28V13L32 5Z" fill="none" stroke="url(#aegis-logo-gradient)" strokeWidth="4" strokeLinejoin="round" />
        <path d="M22 31.5 28.5 38 42 24.5" fill="none" stroke="currentColor" strokeWidth="4.2" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="32" cy="32" r="25" fill="none" stroke="currentColor" strokeOpacity=".12" strokeWidth="1.5" />
      </svg>
    </span>
    {!compact && (
      <span className="aegis-logo__wordmark">
        <strong>AegisScan</strong>
        <small>Security Validation Platform</small>
      </span>
    )}
  </div>
)
