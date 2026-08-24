Qearl Maison V69

This version is intentionally based on the stable V66 UI so the Admin appearance does NOT change.

Core repair:
- Existing live page/item/media tables are left untouched.
- Drafts live in a separate site_drafts table.
- Save Draft never alters the currently published content.
- Preview merges site_drafts into the existing D1 content and uses the real front-end renderer.
- Publish copies the saved draft into the live record and removes the draft.
- New item drafts are supported and appear only in Owner preview until published.
- Existing items such as “第七只赤鸽” remain in site_items and therefore remain visible; no migration hides them.
- Managed archive pages are D1-authoritative; no silent fallback to stale DOCS.
- Custom Keys remains bespoke/static.

Admin:
- Keeps V66 cards/layout exactly as the base.
- Only adds 保存草稿 / 预览 / 发布 controls.
