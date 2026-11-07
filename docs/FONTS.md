# Local typography

- Inter variable, Latin normal: `@fontsource-variable/inter` 5.3.0.
- JetBrains Mono, Latin 400 normal: `@fontsource/jetbrains-mono` 5.3.0.

WOFF2 assets are bundled locally under `agent_security_lab/web/`; the browser does
not contact Google Fonts, npm, or another font service. Both original SIL Open
Font License notices are included in the same directory and in package builds.
The font bytes have not been modified.

Inter is used for the interface and headings. JetBrains Mono is limited to the
payload editor, technical metadata and tool traces. Both have system fallbacks
and `font-display: swap`.

Motion is limited to short entrance, focus/hover, disclosure and working-state
effects. `prefers-reduced-motion: reduce` removes animations and transitions.
