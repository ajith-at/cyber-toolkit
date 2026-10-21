# Contributing

Thanks for helping. Bug reports, ideas and pull requests are welcome.

## Ground rules

- **Browser only, no keys.** The site must keep working as a static site with no backend and no API keys. Data sources must be public, keyless and CORS-enabled.
- **No build step.** Plain HTML, CSS and JavaScript ES modules. No frameworks or bundlers, and no runtime dependencies from npm.
- **No tracking.** Don't add analytics, third-party scripts or cookies.
- **Safe rendering.** Treat every API response as untrusted. Build DOM with the helpers in `js/ui.js` (which use `textContent`) and never pass external data to `innerHTML`.
- **Privacy.** If a change sends data to a new service, add it to the Privacy table in the README.

## Workflow

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Fork, then create a branch from `main`.
3. Make your change. New tools go in `modules/` plus one line in `js/registry.js` (see "Adding a module" in the README).
4. Run the tests locally:
   ```bash
   python3 -m http.server 8811 &
   node tests/smoke.js
   node tests/cors-probe.js   # if you added or changed a data source
   ```
   Check light mode, dark mode and a narrow (mobile) window. There must be no console errors.
5. Open a pull request that says what changed and why, with a screenshot for UI changes.

## Style

- Follow the existing code: 2-space indentation, single quotes, ES modules, small functions.
- Use the existing CSS variables in `css/tokens.css`. Don't add new colours.
- Status colours mean risk only: teal = low, slate = unknown, amber = caution, rose = high risk.
- Icons come from Lucide (outline). Add new ones to `js/icons.js`. No emoji as icons.
- Keep text short and plain.

## Licence

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
