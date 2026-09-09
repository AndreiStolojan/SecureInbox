/*
  One motion vocabulary for the whole app, mirrored from the CSS tokens in
  index.css (--ease-*, --duration-*). Import these instead of writing inline
  spring/tween objects so every entrance, press, and layout shift shares the
  same feel. All of it degrades to instant via <MotionConfig reducedMotion="user">
  (set in main.jsx) and the prefers-reduced-motion guard in index.css.
*/

/** Springs — carry entrances, layout, and presses. */
export const springSoft = { type: 'spring', stiffness: 380, damping: 32, mass: 0.9 };
export const springSnappy = { type: 'spring', stiffness: 520, damping: 30, mass: 0.8 };

/** Apple-style decelerate curve + standard durations (seconds, for Framer). */
export const ease = [0.32, 0.72, 0, 1];
export const dur = { fast: 0.18, base: 0.26, slow: 0.4 };

/** Tween for pure color/opacity crossfades where a spring would feel wrong. */
export const fadeTween = { duration: dur.base, ease };
