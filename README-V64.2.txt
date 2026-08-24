Qearl Maison V64.2

1. Adds real child-page support.
   - Select a parent in PAGE SETTINGS.
   - Or click “+ subpage” on an existing page.
   - Child page gets /parent/child as its shareable URL.
   - Admin sidebar indents child pages.

2. Fixes archive truncation after a partial V64 import.
   V64 skipped the whole page when its slug already existed. V64.2 reconciles
   missing items and media non-destructively instead, preserving user edits/order.

3. Keeps V64.1 login/CORS fix and V64 image-performance work.

Deploy whole package, git add -A, push, then npx wrangler deploy.
Open Admin once after deployment to trigger the archive reconciliation.
