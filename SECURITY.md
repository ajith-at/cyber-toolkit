# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Report it privately through GitHub instead:

1. Go to the repository's **Security** tab: https://github.com/ajith-at/cyber-toolkit/security
2. Click **Report a vulnerability** and describe the issue: what is affected, steps to reproduce, and the impact.

You should get a reply within a week. Once a fix is ready, we'll credit you in the release notes unless you'd rather stay anonymous.

If private reporting isn't available for some reason, open an issue that says only "security report, please contact me", with no details, and we'll arrange a private channel.

## Scope

In scope:

- Cross-site scripting or HTML injection from lookup results (RDAP, DNS, certificate data) or from the input box
- Ways to make the app send indicators to services other than those listed in the README's Privacy section
- Weaknesses in the Content Security Policy or in how external links are opened

Out of scope:

- Bugs in, or the availability of, the third-party services themselves (rdap.org, the registries, Google or Cloudflare DNS, Cert Spotter, or the reputation sites)
- Rate limits of those services
- Results that are wrong because the upstream data is wrong

## Supported versions

Only the latest version on `main` (deployed at https://u51.org/toolkit/) is supported.
