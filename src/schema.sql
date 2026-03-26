-- Echo Web Analytics v1.0.0 Schema

CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  name TEXT,
  public_dashboard INTEGER DEFAULT 0,
  allowed_origins TEXT DEFAULT '*',
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(tenant_id, domain)
);

CREATE TABLE IF NOT EXISTS pageviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id TEXT NOT NULL,
  pathname TEXT NOT NULL,
  hostname TEXT,
  referrer TEXT,
  referrer_domain TEXT,
  utm_source TEXT,
  utm_medium TEXT,
  utm_campaign TEXT,
  utm_term TEXT,
  utm_content TEXT,
  country TEXT,
  region TEXT,
  city TEXT,
  device_type TEXT,
  browser TEXT,
  os TEXT,
  screen_width INTEGER,
  visitor_id TEXT,
  session_id TEXT,
  is_bounce INTEGER DEFAULT 1,
  duration_ms INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS daily_stats (
  site_id TEXT NOT NULL,
  date TEXT NOT NULL,
  pageviews INTEGER DEFAULT 0,
  visitors INTEGER DEFAULT 0,
  sessions INTEGER DEFAULT 0,
  bounces INTEGER DEFAULT 0,
  avg_duration_ms INTEGER DEFAULT 0,
  UNIQUE(site_id, date)
);

CREATE TABLE IF NOT EXISTS daily_pages (
  site_id TEXT NOT NULL,
  date TEXT NOT NULL,
  pathname TEXT NOT NULL,
  pageviews INTEGER DEFAULT 0,
  visitors INTEGER DEFAULT 0,
  avg_duration_ms INTEGER DEFAULT 0,
  UNIQUE(site_id, date, pathname)
);

CREATE TABLE IF NOT EXISTS daily_referrers (
  site_id TEXT NOT NULL,
  date TEXT NOT NULL,
  referrer_domain TEXT NOT NULL,
  pageviews INTEGER DEFAULT 0,
  visitors INTEGER DEFAULT 0,
  UNIQUE(site_id, date, referrer_domain)
);

CREATE TABLE IF NOT EXISTS daily_sources (
  site_id TEXT NOT NULL,
  date TEXT NOT NULL,
  utm_source TEXT NOT NULL,
  utm_medium TEXT,
  utm_campaign TEXT,
  pageviews INTEGER DEFAULT 0,
  visitors INTEGER DEFAULT 0,
  UNIQUE(site_id, date, utm_source)
);

CREATE TABLE IF NOT EXISTS daily_devices (
  site_id TEXT NOT NULL,
  date TEXT NOT NULL,
  device_type TEXT NOT NULL,
  browser TEXT NOT NULL,
  os TEXT NOT NULL,
  pageviews INTEGER DEFAULT 0,
  visitors INTEGER DEFAULT 0,
  UNIQUE(site_id, date, device_type, browser, os)
);

CREATE TABLE IF NOT EXISTS daily_countries (
  site_id TEXT NOT NULL,
  date TEXT NOT NULL,
  country TEXT NOT NULL,
  pageviews INTEGER DEFAULT 0,
  visitors INTEGER DEFAULT 0,
  UNIQUE(site_id, date, country)
);

CREATE TABLE IF NOT EXISTS goals (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  name TEXT NOT NULL,
  event_type TEXT NOT NULL,
  match_value TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(site_id, name)
);

CREATE TABLE IF NOT EXISTS goal_conversions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  goal_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  visitor_id TEXT,
  session_id TEXT,
  metadata TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_pageviews_site_date ON pageviews(site_id, created_at);
CREATE INDEX IF NOT EXISTS idx_pageviews_visitor ON pageviews(site_id, visitor_id);
CREATE INDEX IF NOT EXISTS idx_pageviews_session ON pageviews(site_id, session_id);
CREATE INDEX IF NOT EXISTS idx_daily_stats_site ON daily_stats(site_id, date);
CREATE INDEX IF NOT EXISTS idx_daily_pages_site ON daily_pages(site_id, date);
CREATE INDEX IF NOT EXISTS idx_daily_referrers_site ON daily_referrers(site_id, date);
CREATE INDEX IF NOT EXISTS idx_daily_countries_site ON daily_countries(site_id, date);
CREATE INDEX IF NOT EXISTS idx_goals_site ON goals(site_id);
CREATE INDEX IF NOT EXISTS idx_conversions_goal ON goal_conversions(goal_id, created_at);
