<style>
  :root {
    /* Primary */
    --color-near-black: #141413;
    --color-terracotta: #c96442;
    --color-coral: #d97757;
    /* Secondary & Accent */
    --color-error: #b53333;
    --color-focus-blue: #3898ec;
    /* Surface & Background */
    --color-parchment: #f5f4ed;
    --color-ivory: #faf9f5;
    --color-white: #ffffff;
    --color-warm-sand: #e8e6dc;
    --color-dark-surface: #30302e;
    --color-deep-dark: #141413;
    /* Neutrals & Text */
    --color-charcoal-warm: #4d4c48;
    --color-olive-gray: #5e5d59;
    --color-stone-gray: #87867f;
    --color-dark-warm: #3d3d3a;
    --color-warm-silver: #b0aea5;
    /* Borders & Rings */
    --color-border-cream: #f0eee6;
    --color-border-warm: #e8e6dc;
    --color-border-dark: #30302e;
    --color-ring-warm: #d1cfc5;
    --color-ring-deep: #c2c0b6;
    /* Fonts */
    --font-serif: Georgia, 'Times New Roman', Times, serif;
    --font-sans: Arial, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    --font-mono: SFMono-Regular, Menlo, Monaco, Consolas, 'Courier New', monospace;
    /* Light mode tokens */
    --bg-page: #f5f4ed;
    --bg-card: #faf9f5;
    --bg-nav: rgba(245,244,237,0.92);
    --text-primary: #141413;
    --text-secondary: #5e5d59;
    --text-tertiary: #87867f;
    --border-color: #f0eee6;
    --border-subtle: #f0eee6;
    --section-label-color: #c96442;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg-page);
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 16px;
    line-height: 1.60;
    -webkit-font-smoothing: antialiased;
  }

  /* NAV */
  .nav {
    position: sticky;
    top: 0;
    z-index: 100;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 40px;
    background: var(--bg-nav);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border-color);
  }
  .nav-brand {
    font-family: var(--font-serif);
    font-size: 20px;
    font-weight: 500;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .nav-brand .logo-mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    background: var(--color-terracotta);
    border-radius: 8px;
    color: var(--color-ivory);
    font-family: var(--font-serif);
    font-size: 16px;
    font-weight: 500;
  }
  .nav-links { display: flex; gap: 32px; align-items: center; }
  .nav-links a {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 15px;
    font-weight: 400;
    font-family: var(--font-sans);
    transition: color 0.2s;
  }
  .nav-links a:hover { color: var(--text-primary); }
  .nav-cta {
    background: var(--color-terracotta);
    color: var(--color-ivory);
    padding: 8px 20px;
    border: none;
    border-radius: 12px;
    font-size: 15px;
    font-family: var(--font-sans);
    font-weight: 500;
    cursor: pointer;
    box-shadow: #c96442 0px 0px 0px 0px, #c96442 0px 0px 0px 1px;
  }

  /* HERO */
  .hero {
    position: relative;
    text-align: center;
    padding: 120px 40px 100px;
    overflow: hidden;
  }
  .hero::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 700px;
    height: 700px;
    transform: translate(-50%, -50%);
    background: radial-gradient(circle, rgba(201,100,66,0.06) 0%, rgba(217,119,87,0.03) 40%, transparent 70%);
    pointer-events: none;
  }
  .hero h1 {
    font-family: var(--font-serif);
    font-size: 64px;
    font-weight: 500;
    line-height: 1.10;
    letter-spacing: normal;
    margin-bottom: 24px;
    position: relative;
    color: var(--text-primary);
  }
  .hero h1 span { color: var(--color-terracotta); }
  .hero p {
    color: var(--text-secondary);
    font-family: var(--font-sans);
    font-size: 20px;
    line-height: 1.60;
    margin-bottom: 40px;
    position: relative;
  }
  .hero-buttons { display: flex; gap: 16px; justify-content: center; position: relative; }
  .btn-brand {
    background: var(--color-terracotta);
    color: var(--color-ivory);
    padding: 12px 24px;
    border: none;
    border-radius: 12px;
    font-size: 16px;
    font-family: var(--font-sans);
    font-weight: 500;
    cursor: pointer;
    box-shadow: #c96442 0px 0px 0px 0px, #c96442 0px 0px 0px 1px;
  }
  .btn-warm-sand {
    background: var(--color-warm-sand);
    color: var(--color-charcoal-warm);
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-family: var(--font-sans);
    font-weight: 500;
    cursor: pointer;
    box-shadow: #e8e6dc 0px 0px 0px 0px, #d1cfc5 0px 0px 0px 1px;
  }

  /* SECTIONS */
  .section {
    max-width: 1200px;
    margin: 0 auto;
    padding: 80px 40px;
  }
  .section-title {
    font-family: var(--font-sans);
    font-size: 14px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 2.5px;
    color: var(--section-label-color);
    margin-bottom: 12px;
  }
  .section-heading {
    font-family: var(--font-serif);
    font-size: 36px;
    font-weight: 500;
    line-height: 1.20;
    letter-spacing: normal;
    margin-bottom: 48px;
    color: var(--text-primary);
  }
  .section-divider {
    border: none;
    border-top: 1px solid var(--border-subtle);
    margin: 0 40px;
    max-width: 1200px;
    margin-left: auto;
    margin-right: auto;
  }

  /* COLOR PALETTE */
  .color-group { margin-bottom: 40px; }
  .color-group-title {
    font-family: var(--font-serif);
    font-size: 20px;
    font-weight: 500;
    line-height: 1.2;
    margin-bottom: 20px;
    color: var(--text-secondary);
  }
  .color-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 16px;
  }
  .color-swatch {
    border: 1px solid var(--border-color);
    border-radius: 12px;
    overflow: hidden;
  }
  .color-swatch-block {
    height: 80px;
    position: relative;
  }
  .color-swatch-info {
    padding: 12px;
    background: var(--bg-card);
  }
  .color-swatch-name { font-family: var(--font-sans); font-size: 13px; font-weight: 600; margin-bottom: 2px; }
  .color-swatch-hex { font-family: var(--font-mono); font-size: 12px; color: var(--text-tertiary); margin-bottom: 4px; }
  .color-swatch-role { font-size: 12px; color: var(--text-tertiary); line-height: 1.4; }

  /* TYPOGRAPHY */
  .type-sample { margin-bottom: 32px; padding-bottom: 32px; border-bottom: 1px solid var(--border-subtle); }
  .type-sample:last-child { border-bottom: none; }
  .type-sample-text { margin-bottom: 8px; }
  .type-sample-label {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-tertiary);
  }

  /* BUTTONS */
  .button-row {
    display: flex;
    flex-wrap: wrap;
    gap: 24px;
    align-items: flex-start;
  }
  .button-demo { text-align: center; }
  .button-demo-label {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-tertiary);
    margin-top: 10px;
    text-transform: uppercase;
    letter-spacing: 0.55px;
  }
  .btn-white {
    background: var(--color-white);
    color: var(--color-near-black);
    padding: 8px 16px;
    border: 1px solid var(--border-color);
    border-radius: 12px;
    font-size: 16px;
    font-family: var(--font-sans);
    font-weight: 500;
    cursor: pointer;
  }
  .btn-dark {
    background: var(--color-dark-surface);
    color: var(--color-ivory);
    padding: 9.6px 16.8px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-family: var(--font-sans);
    font-weight: 500;
    cursor: pointer;
    box-shadow: #30302e 0px 0px 0px 0px, #30302e 0px 0px 0px 1px;
  }

  /* CARDS */
  .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; }
  .card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 28px;
  }
  .card-standard { border: 1px solid var(--border-color); }
  .card-whisper {
    border: 1px solid var(--border-color);
    box-shadow: rgba(0,0,0,0.05) 0px 4px 24px;
  }
  .card-ring {
    border: none;
    box-shadow: 0px 0px 0px 1px var(--color-ring-warm);
  }
  .card h3 {
    font-family: var(--font-serif);
    font-size: 25px;
    font-weight: 500;
    line-height: 1.20;
    margin-bottom: 12px;
    color: var(--text-primary);
  }
  .card p { color: var(--text-secondary); font-size: 15px; line-height: 1.60; }
  .card-label {
    font-family: var(--font-sans);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.55px;
    color: var(--color-terracotta);
    margin-bottom: 16px;
    font-weight: 500;
  }

  /* SPACING */
  .spacing-row { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
  .spacing-item { text-align: center; }
  .spacing-box {
    background: rgba(201,100,66,0.10);
    border: 1px solid rgba(201,100,66,0.25);
    border-radius: 4px;
    margin-bottom: 8px;
  }
  .spacing-label {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-tertiary);
  }

  /* RADIUS */
  .radius-row { display: flex; flex-wrap: wrap; gap: 20px; align-items: center; }
  .radius-item { text-align: center; }
  .radius-box {
    width: 80px;
    height: 80px;
    background: var(--bg-card);
    border: 1px solid var(--color-border-warm);
    margin-bottom: 8px;
  }
  .radius-label {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-tertiary);
  }
  .radius-context {
    font-size: 11px;
    color: var(--text-tertiary);
    margin-top: 2px;
  }

  /* ELEVATION */
  .elevation-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 24px; }
  .elevation-card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 24px;
    min-height: 140px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .elevation-flat { border: none; background: var(--bg-page); }
  .elevation-contained { border: 1px solid var(--color-border-cream); }
  .elevation-ring { border: none; box-shadow: 0px 0px 0px 1px var(--color-ring-warm); }
  .elevation-whisper { border: 1px solid var(--color-border-cream); box-shadow: rgba(0,0,0,0.05) 0px 4px 24px; }
  .elevation-inset { border: none; box-shadow: inset 0px 0px 0px 1px rgba(0,0,0,0.15); }
  .elevation-name {
    font-family: var(--font-serif);
    font-size: 16px;
    font-weight: 500;
    margin-bottom: 8px;
  }
  .elevation-desc { font-size: 13px; color: var(--text-secondary); line-height: 1.5; }
  .elevation-level {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-terracotta);
    text-transform: uppercase;
    letter-spacing: 0.55px;
    margin-top: 12px;
  }

  /* RESPONSIVE */
  @media (max-width: 768px) {
    .nav { padding: 12px 20px; }
    .nav-links a:not(.nav-cta-wrapper) { display: none; }
    .hero { padding: 80px 20px 60px; }
    .hero h1 { font-size: 36px; }
    .section { padding: 60px 20px; }
    .section-heading { font-size: 28px; }
    .color-grid { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); }
    .card-grid { grid-template-columns: 1fr; }
    .hero-buttons { flex-direction: column; align-items: center; }
    .button-row { flex-direction: column; align-items: flex-start; }
  }

  /* getdesign.md nav additions */
  .nav-left { display: flex; align-items: center; gap: 20px; }
  .nav-brand-link,
  .nav-brand-link:link,
  .nav-brand-link:visited,
  .nav-brand-link:hover,
  .nav-brand-link:active { text-decoration: none; color: inherit; }
  .nav-github,
  .nav-github:link,
  .nav-github:visited,
  .nav-github:hover,
  .nav-github:active {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    color: inherit;
    text-decoration: none;
    padding: 5px 10px;
    border: 1px solid rgba(128, 128, 128, 0.3);
    border-radius: 6px;
    opacity: 0.75;
    transition: opacity 200ms ease, border-color 200ms ease;
    font-family: inherit;
    line-height: 1;
    white-space: nowrap;
  }
  .nav-github:hover { opacity: 1; border-color: rgba(128, 128, 128, 0.55); }
  .nav-github svg { display: block; flex-shrink: 0; }

  /* getdesign.md nav centering */
  .nav { display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; }
  .nav > .nav-left { justify-self: start; }
  .nav > .nav-links { justify-self: center; }
  .nav > :last-child { justify-self: end; }
</style>
