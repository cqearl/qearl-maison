Qearl Maison V64.4 — stable admin loading

Fixes:
1. Stops the expensive full legacy reconciliation on every Admin open.
2. Adds site_meta + legacy_seed_version marker in D1.
3. Admin first checks /api/admin/migration-status:
   - if V64.2 migration is already marked complete, it skips legacy import entirely.
   - if not, it runs the non-destructive V64.2 reconciliation once and then marks completion.
4. Keeps all existing D1 content, edits, image order, child pages, inline front-end add, and V64 performance work.
5. Improves Admin bootstrap error text for easier diagnosis.

Deploy:
- overwrite package files
- git add -A
- git commit / pull --rebase / push
- npx wrangler deploy

After deploy:
- open /admin/?v=644 once
- if migration marker was missing, one final reconciliation may run
- subsequent Admin loads will not run the legacy scan again
