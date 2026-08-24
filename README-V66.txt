Qearl Maison V66

Fixes the three issues reported after V65:

1. Admin item saving
- Text/item metadata is saved first.
- Image upload is a second step with progress.
- If image upload fails, the text edit is NOT lost.
- Error message now says exactly whether Cloudinary credential, upload, or DB media record failed.

2. Managed-page titles / TOC
- D1 item.title is now an explicit heading, not ordinary body text.
- Every item title receives an anchor and becomes a TOC entry.
- Clicking the TOC jumps to the correct item heading.

3. Empty TOC / content overlay
- Managed page TOC is generated from explicit item titles.
- Empty TOC no longer looks like a broken blank panel; it shows a small explanatory state.

All V65 unified publishing, V64.x child pages/auth/performance/admin stability remain.
