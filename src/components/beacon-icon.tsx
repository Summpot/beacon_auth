import { useId } from 'react';

export interface BeaconIconProps {
  className?: string;
  /** Accent color used for the "light" and beam gradients. */
  accentColor?: string;
  title?: string;
}

function sanitizeSvgId(id: string): string {
  // React 18 useId() may contain characters like ':' which are valid in HTML ids
  // but can be awkward in SVG url(#...). Sanitize for safety.
  return id.replace(/[^a-zA-Z0-9_-]/g, '');
}

export function BeaconIcon({
  className = 'w-16 h-16',
  accentColor = '#4eecd6',
  title = 'Beacon',
}: BeaconIconProps) {
  const reactId = useId();
  const id = sanitizeSvgId(reactId);

  const beamGradientId = `beamGradient-${id}`;
  const beamGradientInnerId = `beamGradientInner-${id}`;

  return (
    <svg
      className={className}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <title>{title}</title>

      <rect
        x="20"
        y="48"
        width="24"
        height="8"
        fill="#4a4a5a"
        stroke="#3a3a4a"
        strokeWidth="1"
      />
      <rect
        x="24"
        y="40"
        width="16"
        height="8"
        fill="#5a5a6a"
        stroke="#4a4a5a"
        strokeWidth="1"
      />

      <rect x="26" y="42" width="12" height="4" fill={accentColor}>
        <animate
          attributeName="opacity"
          values="0.8;1;0.8"
          dur="2s"
          repeatCount="indefinite"
        />
      </rect>

      <path
        d="M32 42 L24 8 L40 8 Z"
        fill={`url(#${beamGradientId})`}
        opacity="0.6"
      >
        <animate
          attributeName="opacity"
          values="0.4;0.7;0.4"
          dur="2s"
          repeatCount="indefinite"
        />
      </path>

      <path
        d="M32 42 L28 8 L36 8 Z"
        fill={`url(#${beamGradientInnerId})`}
        opacity="0.8"
      >
        <animate
          attributeName="opacity"
          values="0.6;1;0.6"
          dur="1.5s"
          repeatCount="indefinite"
        />
      </path>

      <defs>
        <linearGradient
          id={beamGradientId}
          x1="32"
          y1="42"
          x2="32"
          y2="8"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor={accentColor} />
          <stop offset="100%" stopColor={accentColor} stopOpacity="0" />
        </linearGradient>
        <linearGradient
          id={beamGradientInnerId}
          x1="32"
          y1="42"
          x2="32"
          y2="8"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#ffffff" />
          <stop offset="50%" stopColor={accentColor} />
          <stop offset="100%" stopColor={accentColor} stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  );
}
