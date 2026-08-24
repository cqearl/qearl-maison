Qearl Maison V63
================
Fixes:
1) Admin existing-image reorder (left/right controls).
2) Admin can append new images to an existing item.
3) api.qearlune.xyz is explicitly routed to the qearl-maison Worker.
4) Cross-subdomain CORS/session handling fixed for qearlune.xyz -> api.qearlune.xyz.
5) Mobile Admin layout rebuilt for compact top bar, hero, cards and dialogs.
6) Admin API endpoints restored: bootstrap/pages/sections/items/media/reorder/public site.

Deploy:
- copy index.html, public/index.html, admin/index.html, public/admin/index.html,
  src/index.js and wrangler.jsonc
- git commit/push
- npx wrangler deploy

Cloudinary:
Admin image uploads require Worker secrets:
CLOUDINARY_CLOUD_NAME
CLOUDINARY_API_KEY
CLOUDINARY_API_SECRET
If they were already configured in Cloudflare, no action is needed.
