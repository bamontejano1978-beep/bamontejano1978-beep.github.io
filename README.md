# Integrity Labs — public site, version 2

Live: https://bamontejano1978-beep.github.io/

Version: `2.0.0-saas-piloto`, 22 November 2026.

This repository contains only the public static website. It contains no SaaS
engine, credentials, private conversations or customer data. The dashboard
screenshots use fictional pilot data. The conversation is a labelled illustration.

## Published content

- Home, product walkthrough and pilot request in Spanish and English.
- The previous interactive technical demo remains at `/demo/metodo/` and
  `/en/product-demo/method/`; it is separate from the conversational pilot.
- Existing benchmark, evidence verifier and privacy pages retain their routes.
- No published list prices. Scope, terms and cost are agreed before a pilot.
- The contact form prepares an email; the visitor must send it from their email app.

## Versions and rollback

GitHub Pages serves `main` at the domain root. The previous published version is
preserved by tag `landing-anterior-20261122`, commit
`97e461006c3218930c5e5296e826bdf98d11e703`.
The new version is tagged `landing-saas-v2-20261122`.

To reverse this update while retaining history, from a clean checkout:

```sh
git switch main
git pull --ff-only
git revert --no-edit landing-saas-v2-20261122
git push origin main
```

Review later changes before reverting if additional commits have been published.
The operator also retains ZIP snapshots of both versions outside this public repo.
