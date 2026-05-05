import React from 'react'

interface QuantumLogoProps {
  size?: number
  className?: string
}

/**
 * Quantum-inspired logo: an atomic orbit / quantum superposition mark.
 * Three elliptical orbits at 0°, 60°, 120° around a central nucleus dot,
 * representing quantum states. A shield outline is subtly implied by the
 * outer boundary.
 */
export const QuantumLogo: React.FC<QuantumLogoProps> = ({ size = 32, className }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 32 32"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
  >
    {/* Orbit 1 — horizontal */}
    <ellipse
      cx="16" cy="16"
      rx="13" ry="5"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeOpacity="0.9"
    />
    {/* Orbit 2 — rotated 60° */}
    <ellipse
      cx="16" cy="16"
      rx="13" ry="5"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeOpacity="0.7"
      transform="rotate(60 16 16)"
    />
    {/* Orbit 3 — rotated 120° */}
    <ellipse
      cx="16" cy="16"
      rx="13" ry="5"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeOpacity="0.5"
      transform="rotate(120 16 16)"
    />
    {/* Nucleus */}
    <circle cx="16" cy="16" r="2.2" fill="currentColor" />
    {/* Electron dots */}
    <circle cx="29" cy="16" r="1.3" fill="currentColor" fillOpacity="0.85" />
    <circle cx="9.5" cy="7.2" r="1.3" fill="currentColor" fillOpacity="0.65" />
    <circle cx="9.5" cy="24.8" r="1.3" fill="currentColor" fillOpacity="0.45" />
  </svg>
)
