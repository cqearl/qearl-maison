Qearl Maison V64.1
Fixes browser CORS on POST /api/login and /api/logout responses.
OPTIONS and /api/me were already correct; successful/failed login responses were missing
Access-Control-Allow-Origin / Access-Control-Allow-Credentials, which Safari surfaces as "Load failed".

Also adds GET /api/health for future diagnostics.
All V64 image-performance/admin/data changes are preserved.

Deploy src/index.js via git push and npx wrangler deploy.
