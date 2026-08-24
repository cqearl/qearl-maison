Qearl Maison V65 — unified publishing

Why the previous "Server error" kept returning:
The homepage Add-to-archive dialog still used the old /api/publish endpoint.
That endpoint encoded photos as base64 and wrote them into the old additions table,
while the rest of the site had already migrated to site_pages/site_items/site_media.
So there were two publishing systems fighting each other.

V65:
- Existing archive targets (Type Book / Theme Case / Mist / Insomnia / Moss / Jasmine / Miscellany)
  all publish through one managed D1 path: /api/admin/quick-publish.
- Images are uploaded first to Cloudinary, then their URLs are stored in site_media.
- No new publish operation stores image base64 in D1.
- Front-page publishing and "当前页新增" use the same function.
- Custom Keys is protected from generic append because it has a bespoke layout.
- Adds /api/admin/system-status to diagnose missing image-upload configuration.
- Upload-signature now returns the exact missing Cloudinary variables rather than generic Server error.
- V64.4 stable admin load, V64.3 inline add, V64.2 subpages, auth/CORS, and image performance remain.

IMPORTANT one-time Cloudinary configuration:
Worker needs all three:
CLOUDINARY_CLOUD_NAME
CLOUDINARY_API_KEY
CLOUDINARY_API_SECRET

Your earlier secret list showed CLOUDINARY_API_SECRET only.
CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY must be added once before photo uploads can work.
