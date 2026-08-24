Qearl Maison V64.3

- Owner login now remains recognized when returning from /admin.
- On any D1-managed page or child page, the reader bar shows “+ 当前页新增”.
- Clicking it opens Add to archive locked to that exact current page.
- Title/body are inserted directly through the Admin item API.
- An empty child page gets its first section automatically.
- Images are compressed in-browser, uploaded with the existing Cloudinary signed upload flow,
  then attached to the new item.
- The current page refreshes immediately after saving.
- Visitors never see the add button.
- Root/public front-end implementations are synchronized to avoid two different behavior stacks.

V64.2 subpages/legacy reconciliation, V64.1 auth/CORS, and V64 performance optimizations remain.
