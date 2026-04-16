# Phase 5: React Frontend & FastAPI Backend — Implementation Plan

## Objective
Build a dynamic, dark-themed React frontend that matches the design aesthetic from the reference materials, but with a customizable UI (e.g., interchangeable titles). This frontend will fetch real-time data from a lightweight FastAPI layer that hooks into the core Python simulation.

## Architecture

1. **FastAPI Backend Layer (`sentinel_ds/api.py`)**
   - Exposes RESTful endpoints (e.g., `GET /api/metrics`, `GET /api/logs`, `GET /api/reports`) or Server-Sent Events (SSE) to push real-time simulation state from the Python core to the browser.
   
2. **React Frontend Layer (`sentinel_ds/frontend/`)**
   - Bootstrapped via Vite: `npx -y create-vite-app@latest ./frontend --template react`
   - **Styling**: Vanilla CSS (`index.css` and `App.css`) for ultimate flexibility. Focuses on premium modern web design paradigms (vibrant neon accents on curated dark backgrounds, glassmorphism, smooth micro-animations on hover, custom scrollbars, and modern typography like Inter or Roboto).

## Proposed UI Components

1. **Global Configuration & Styling**
   - The primary title and subtitle text can be configured via a `.env` file or a constants module (e.g. `VITE_DASHBOARD_TITLE="Custom Security Agent"`) so it doesn't rigidly say "SOC THREAT HUNTER" but maintains the slick font and layout of the screenshots.

2. **Header & Context Bar**
   - Configurable Title & Subtitle styled with tracking and premium weights.
   - Live rendering clock (ISO format or localized string).
   - Critical Threat Banner: A dynamically rendered banner that appears, pulsing red (`⛔ CRITICAL THREAT ACTIVE - IMMEDIATE CONTAINMENT REQUIRED`), when a high-confidence notification arrives.

3. **High-Level Statistics (KPI Cards)**
   - 4 horizontal cards spanning the top of the interface:
     - **EVENTS CAPTURED** (Blue styled number)
     - **FAILED REQUESTS** (Red styled number)
     - **ACTIVE THREATS** (Orange styled number)
     - **FLAGGED IPS** (Green styled number)

4. **Main Dashboard Split (Left/Right Pane)**
   - **Left Column: Network Telemetry**:
     - `LIVE TRAFFIC FEED`: A distinct terminal-like container (`overflowY: scroll`). Renders newly arrived log entries with colored prefixes (e.g., yellow timestamps, red blocked actions). Custom-styled thin scrollbar for a premium feel.
     - `ENDPOINT HIT COUNT`: A horizontal bar chart section using pure CSS widths to represent percentage fills for common endpoints (`/login`, `/api/auth/login`).
     
   - **Right Column: AI SOC Analyst Reports**:
     - Dynamically rendered rule violation cards mapping to the `threat_score` output. The cards sit on a pure dark, slightly elevated background with subtle border colors mapping to threat levels.
     - Each card contains:
       - **Threat Designation** (e.g., "UNAUTHORIZED ACCESS SCAN").
       - **Confidence Rating**: Rendered as a visual progress bar (styled red or orange depending on severity) dynamically updating.
       - **Triggered Context**: A row of CSS-styled pill tags mapping to specific rules (e.g., `rule_auth_scan`, `rule_untrusted_ip`).
       - **Mitigation Action**: A distinct box with a subtle green transparent background and border containing the Contextual Bandit's recommended fix.

## Verification
- Start the FastAPI backend (`uvicorn api:app`) and navigate to the React dev server (`localhost:5173`).
- Visually verify the aesthetic perfectly matches the premium dark-themed references, including CSS glows, specific element spacing, and fonts.
- Confirm the main title can be dynamically tweaked via environment variables without breaking the layout.
