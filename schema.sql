PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS content_overrides (
  page TEXT NOT NULL,
  block_index INTEGER NOT NULL,
  text_override TEXT,
  image_key_override TEXT,
  deleted INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(page,block_index)
);

CREATE TABLE IF NOT EXISTS additions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page TEXT NOT NULL,
  sort_order INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('text','image')),
  text_content TEXT,
  image_key TEXT,
  is_heading INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_additions_page_order ON additions(page,sort_order,id);

CREATE TABLE IF NOT EXISTS custom_pages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  sort_order INTEGER NOT NULL,
  published INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
