Qearl Maison V64 — stable performance

Front-end
- 480px / 960px WebP display variants; originals remain untouched.
- srcset/sizes, lazy loading, async decoding and first-image priority.
- Cloudinary media uses lightweight transformed display URLs.
- Existing archive pages auto-migrate into D1 when Admin is opened.
- Managed D1 pages are preferred on the public site; static DOCS remain fallback.
- Custom Keys keeps its bespoke layout.

Admin
- Existing image reorder/delete and append-image flow retained.
- New uploads are compressed to WebP before Cloudinary upload.
- Admin thumbnails request smaller display images.
- Mobile Admin density is tightened.

Deploy
Copy ALL files/folders from this package, including:
assets/display, public/assets/display, data/legacy-seed.json,
public/data/legacy-seed.json, src/index.js and wrangler.jsonc.
Then git add -A, commit/push, and npx wrangler deploy.
