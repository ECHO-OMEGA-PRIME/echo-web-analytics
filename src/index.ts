// Echo Web Analytics v1.0.0 — Privacy-first website analytics on Cloudflare Workers

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ECHO_API_KEY: string;
  ENVIRONMENT: string;
}

interface RLState { c: number; t: number; }

function uid(): string { return crypto.randomUUID().replace(/-/g, '').slice(0, 16); }
function sanitize(s: string, max = 500): string { return s.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '').slice(0, max); }
function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': '*' , 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'X-XSS-Protection': '1; mode=block', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } });
}
function err(msg: string, status = 400): Response { return json({ error: msg }, status); }

function authOk(req: Request, env: Env): boolean {
  return (req.headers.get('X-Echo-API-Key') || new URL(req.url).searchParams.get('key')) === env.ECHO_API_KEY;
}

async function rateLimit(kv: KVNamespace, key: string, max: number, windowMs: number): Promise<boolean> {
  const raw = await kv.get(`rl:${key}`);
  const now = Date.now();
  let state: RLState = raw ? JSON.parse(raw) : { c: 0, t: now };
  const elapsed = now - state.t;
  state.c = Math.max(0, state.c - (elapsed / windowMs) * max);
  state.t = now;
  if (state.c >= max) return false;
  state.c += 1;
  await kv.put(`rl:${key}`, JSON.stringify(state), { expirationTtl: Math.ceil(windowMs / 1000) * 2 });
  return true;
}

async function hashStr(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s + 'echo-wa-salt-v1'));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

function parseUA(ua: string): { device: string; browser: string; os: string } {
  let device = 'desktop', browser = 'Unknown', os = 'Unknown';
  if (/Mobile|Android|iPhone|iPad/i.test(ua)) device = /iPad|Tablet/i.test(ua) ? 'tablet' : 'mobile';
  if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/Chrome\//.test(ua)) browser = 'Chrome';
  else if (/Safari\//.test(ua)) browser = 'Safari';
  else if (/Opera|OPR/.test(ua)) browser = 'Opera';
  if (/Windows/.test(ua)) os = 'Windows';
  else if (/Mac OS/.test(ua)) os = 'macOS';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/iPhone|iPad/.test(ua)) os = 'iOS';
  else if (/Linux/.test(ua)) os = 'Linux';
  return { device, browser, os };
}

function extractDomain(url: string): string {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': '*' } });

    try {
    const url = new URL(req.url);
    const p = url.pathname;
    const m = req.method;

    // ── Public endpoints ──
    if (p === '/health' || p === '/') return json({ status: 'healthy', service: 'echo-web-analytics', version: '1.0.0', timestamp: new Date().toISOString() });

    // ── Tracking script (public, no auth) ──
    if (m === 'GET' && p === '/script.js') {
      const sid = url.searchParams.get('id');
      if (!sid) return err('Missing site id');
      const js = `(function(){var s='${sid}',u='${url.origin}',d=document,w=window;var vid=localStorage.getItem('_ewa_v');if(!vid){vid=Math.random().toString(36).slice(2)+Date.now().toString(36);localStorage.setItem('_ewa_v',vid)}var ssid=sessionStorage.getItem('_ewa_s');if(!ssid){ssid=Math.random().toString(36).slice(2);sessionStorage.setItem('_ewa_s',ssid)}var t0=Date.now();function send(ev,data){var b=Object.assign({site_id:s,visitor_id:vid,session_id:ssid,pathname:location.pathname,hostname:location.hostname,referrer:d.referrer||'',screen_width:w.innerWidth,event:ev},data||{});navigator.sendBeacon?navigator.sendBeacon(u+'/collect',JSON.stringify(b)):fetch(u+'/collect',{method:'POST',body:JSON.stringify(b),keepalive:true})}send('pageview');var pushState=history.pushState;history.pushState=function(){pushState.apply(this,arguments);send('pageview')};w.addEventListener('popstate',function(){send('pageview')});d.addEventListener('visibilitychange',function(){if(d.visibilityState==='hidden'){send('leave',{duration_ms:Date.now()-t0})}})})();`;
      return new Response(js, { headers: { 'Content-Type': 'application/javascript', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=3600' } });
    }

    // ── Collect endpoint (public, rate limited) ──
    if (m === 'POST' && p === '/collect') {
      const ip = req.headers.get('CF-Connecting-IP') || '0.0.0.0';
      const ipHash = await hashStr(ip);
      if (!await rateLimit(env.CACHE, `col:${ipHash}`, 30, 60000)) return json({ ok: true }); // silent rate limit

      const body = await req.json<any>().catch(() => null);
      if (!body?.site_id) return json({ ok: true }); // silent fail

      const site = await env.DB.prepare('SELECT id, domain FROM sites WHERE id=?').bind(body.site_id).first();
      if (!site) return json({ ok: true });

      const ua = req.headers.get('User-Agent') || '';
      // Skip bots
      if (/bot|crawler|spider|headless|phantom|selenium/i.test(ua)) return json({ ok: true });

      const { device, browser, os } = parseUA(ua);
      const country = req.headers.get('CF-IPCountry') || 'XX';
      const region = (req as any).cf?.region || '';
      const city = (req as any).cf?.city || '';
      const referrerDomain = body.referrer ? extractDomain(body.referrer) : '';
      const hostname = body.hostname ? sanitize(body.hostname, 200) : '';

      // Parse UTM params from referrer or current URL
      let utm_source = '', utm_medium = '', utm_campaign = '', utm_term = '', utm_content = '';
      try {
        const pageUrl = new URL(`https://${hostname}${body.pathname || '/'}`);
        utm_source = pageUrl.searchParams.get('utm_source') || '';
        utm_medium = pageUrl.searchParams.get('utm_medium') || '';
        utm_campaign = pageUrl.searchParams.get('utm_campaign') || '';
        utm_term = pageUrl.searchParams.get('utm_term') || '';
        utm_content = pageUrl.searchParams.get('utm_content') || '';
      } catch {}

      const visitorId = await hashStr((body.visitor_id || '') + ip + ua.slice(0, 50));

      if (body.event === 'leave' && body.duration_ms) {
        // Update duration on last pageview for this session
        (async () => {
          await env.DB.prepare("UPDATE pageviews SET duration_ms=?, is_bounce=0 WHERE site_id=? AND session_id=? AND id=(SELECT MAX(id) FROM pageviews WHERE site_id=? AND session_id=?)")
            .bind(Math.min(body.duration_ms, 3600000), body.site_id, body.session_id || '', body.site_id, body.session_id || '').run();
        })();
        return json({ ok: true });
      }

      // Insert pageview (fire and forget)
      (async () => {
        await env.DB.prepare('INSERT INTO pageviews (site_id, pathname, hostname, referrer, referrer_domain, utm_source, utm_medium, utm_campaign, utm_term, utm_content, country, region, city, device_type, browser, os, screen_width, visitor_id, session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(body.site_id, sanitize(body.pathname || '/', 500), hostname, sanitize(body.referrer || '', 1000), referrerDomain, utm_source, utm_medium, utm_campaign, utm_term, utm_content, country, region, city, device, browser, os, body.screen_width || 0, visitorId, body.session_id || '').run();

        // Check goals
        const goals = await env.DB.prepare('SELECT * FROM goals WHERE site_id=?').bind(body.site_id).all();
        for (const g of (goals.results || []) as any[]) {
          let match = false;
          if (g.event_type === 'pageview' && g.match_value) {
            match = (body.pathname || '/') === g.match_value || (body.pathname || '/').startsWith(g.match_value);
          }
          if (match) {
            await env.DB.prepare('INSERT INTO goal_conversions (goal_id, site_id, visitor_id, session_id) VALUES (?, ?, ?, ?)')
              .bind(g.id, body.site_id, visitorId, body.session_id || '').run();
          }
        }
      })();

      return json({ ok: true });
    }

    // ── Custom event tracking ──
    if (m === 'POST' && p === '/event') {
      const ip = req.headers.get('CF-Connecting-IP') || '0.0.0.0';
      if (!await rateLimit(env.CACHE, `ev:${await hashStr(ip)}`, 10, 60000)) return json({ ok: true });
      const body = await req.json<any>().catch(() => null);
      if (!body?.site_id || !body?.name) return json({ ok: true });
      const visitorId = await hashStr((body.visitor_id || '') + ip);
      const goals = await env.DB.prepare('SELECT * FROM goals WHERE site_id=? AND event_type=? AND match_value=?').bind(body.site_id, 'custom', body.name).all();
      for (const g of (goals.results || []) as any[]) {
        await env.DB.prepare('INSERT INTO goal_conversions (goal_id, site_id, visitor_id, session_id, metadata) VALUES (?, ?, ?, ?, ?)')
          .bind(g.id, body.site_id, visitorId, body.session_id || '', JSON.stringify(body.props || {})).run();
      }
      return json({ ok: true });
    }

    // ── Public dashboard (if site allows it) ──
    if (m === 'GET' && p.match(/^\/share\/[a-zA-Z0-9]+$/)) {
      const siteId = p.split('/')[2];
      const site = await env.DB.prepare('SELECT * FROM sites WHERE id=? AND public_dashboard=1').bind(siteId).first();
      if (!site) return err('Not found', 404);
      // Return aggregate data
      const period = url.searchParams.get('period') || '7d';
      const days = period === '30d' ? 30 : period === '24h' ? 1 : 7;
      const stats = await env.DB.prepare(`SELECT SUM(pageviews) as pv, SUM(visitors) as vis, SUM(sessions) as sess, SUM(bounces) as bounces, AVG(avg_duration_ms) as avg_dur FROM daily_stats WHERE site_id=? AND date >= date('now', '-${days} days')`).bind(siteId).first<any>();
      const pages = await env.DB.prepare(`SELECT pathname, SUM(pageviews) as pv, SUM(visitors) as vis FROM daily_pages WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY pathname ORDER BY pv DESC LIMIT 20`).bind(siteId).all();
      const referrers = await env.DB.prepare(`SELECT referrer_domain, SUM(pageviews) as pv FROM daily_referrers WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY referrer_domain ORDER BY pv DESC LIMIT 20`).bind(siteId).all();
      const countries = await env.DB.prepare(`SELECT country, SUM(pageviews) as pv FROM daily_countries WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY country ORDER BY pv DESC LIMIT 20`).bind(siteId).all();
      const daily = await env.DB.prepare(`SELECT * FROM daily_stats WHERE site_id=? AND date >= date('now', '-${days} days') ORDER BY date`).bind(siteId).all();
      return json({
        site: { id: (site as any).id, domain: (site as any).domain, name: (site as any).name },
        period, stats: { pageviews: stats?.pv || 0, visitors: stats?.vis || 0, sessions: stats?.sess || 0, bounce_rate: (stats?.sess || 0) > 0 ? ((stats?.bounces || 0) / (stats?.sess || 1) * 100).toFixed(1) + '%' : '0%', avg_duration_s: Math.round((stats?.avg_dur || 0) / 1000) },
        pages: pages.results || [], referrers: referrers.results || [], countries: countries.results || [], daily: daily.results || []
      });
    }

    // ── Authenticated endpoints ──
    if (!authOk(req, env)) return err('Unauthorized', 401);
    const tid = req.headers.get('X-Tenant-ID') || url.searchParams.get('tenant_id') || '';

    // ── Sites CRUD ──
    if (m === 'POST' && p === '/api/sites') {
      const body = await req.json<any>();
      if (!body?.domain) return err('domain required');
      const id = uid();
      await env.DB.prepare('INSERT INTO sites (id, tenant_id, domain, name, public_dashboard) VALUES (?, ?, ?, ?, ?)')
        .bind(id, tid, sanitize(body.domain, 200), body.name ? sanitize(body.name, 200) : body.domain, body.public_dashboard ? 1 : 0).run();
      return json({ id, script_tag: `<script defer src="https://echo-web-analytics.bmcii1976.workers.dev/script.js?id=${id}"></script>` });
    }
    if (m === 'GET' && p === '/api/sites') {
      const r = await env.DB.prepare('SELECT * FROM sites WHERE tenant_id=? ORDER BY created_at DESC').bind(tid).all();
      return json({ sites: r.results || [] });
    }
    if (m === 'DELETE' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+$/)) {
      const id = p.split('/')[3];
      await env.DB.prepare('DELETE FROM sites WHERE id=? AND tenant_id=?').bind(id, tid).run();
      return json({ ok: true });
    }

    // ── Dashboard API ──
    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/stats$/)) {
      const siteId = p.split('/')[3];
      const period = url.searchParams.get('period') || '7d';
      const days = period === '30d' ? 30 : period === '90d' ? 90 : period === '24h' ? 1 : 7;

      // Try KV cache
      const cacheKey = `stats:${siteId}:${period}`;
      const cached = await env.CACHE.get(cacheKey);
      if (cached) return json(JSON.parse(cached));

      const stats = await env.DB.prepare(`SELECT SUM(pageviews) as pv, SUM(visitors) as vis, SUM(sessions) as sess, SUM(bounces) as bounces, AVG(avg_duration_ms) as avg_dur FROM daily_stats WHERE site_id=? AND date >= date('now', '-${days} days')`).bind(siteId).first<any>();
      const daily = await env.DB.prepare(`SELECT * FROM daily_stats WHERE site_id=? AND date >= date('now', '-${days} days') ORDER BY date`).bind(siteId).all();
      const result = {
        pageviews: stats?.pv || 0, visitors: stats?.vis || 0, sessions: stats?.sess || 0,
        bounce_rate: (stats?.sess || 0) > 0 ? ((stats?.bounces || 0) / (stats?.sess || 1) * 100).toFixed(1) + '%' : '0%',
        avg_duration_s: Math.round((stats?.avg_dur || 0) / 1000),
        daily: daily.results || []
      };
      await env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 300 });
      return json(result);
    }

    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/pages$/)) {
      const siteId = p.split('/')[3];
      const days = parseInt(url.searchParams.get('days') || '7');
      const r = await env.DB.prepare(`SELECT pathname, SUM(pageviews) as pv, SUM(visitors) as vis, AVG(avg_duration_ms) as avg_dur FROM daily_pages WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY pathname ORDER BY pv DESC LIMIT 50`).bind(siteId).all();
      return json({ pages: r.results || [] });
    }

    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/referrers$/)) {
      const siteId = p.split('/')[3];
      const days = parseInt(url.searchParams.get('days') || '7');
      const r = await env.DB.prepare(`SELECT referrer_domain, SUM(pageviews) as pv, SUM(visitors) as vis FROM daily_referrers WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY referrer_domain ORDER BY pv DESC LIMIT 50`).bind(siteId).all();
      return json({ referrers: r.results || [] });
    }

    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/sources$/)) {
      const siteId = p.split('/')[3];
      const days = parseInt(url.searchParams.get('days') || '7');
      const r = await env.DB.prepare(`SELECT utm_source, utm_medium, utm_campaign, SUM(pageviews) as pv, SUM(visitors) as vis FROM daily_sources WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY utm_source ORDER BY pv DESC LIMIT 50`).bind(siteId).all();
      return json({ sources: r.results || [] });
    }

    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/devices$/)) {
      const siteId = p.split('/')[3];
      const days = parseInt(url.searchParams.get('days') || '7');
      const devices = await env.DB.prepare(`SELECT device_type, SUM(pageviews) as pv FROM daily_devices WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY device_type ORDER BY pv DESC`).bind(siteId).all();
      const browsers = await env.DB.prepare(`SELECT browser, SUM(pageviews) as pv FROM daily_devices WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY browser ORDER BY pv DESC LIMIT 10`).bind(siteId).all();
      const oses = await env.DB.prepare(`SELECT os, SUM(pageviews) as pv FROM daily_devices WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY os ORDER BY pv DESC LIMIT 10`).bind(siteId).all();
      return json({ devices: devices.results || [], browsers: browsers.results || [], operating_systems: oses.results || [] });
    }

    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/countries$/)) {
      const siteId = p.split('/')[3];
      const days = parseInt(url.searchParams.get('days') || '7');
      const r = await env.DB.prepare(`SELECT country, SUM(pageviews) as pv, SUM(visitors) as vis FROM daily_countries WHERE site_id=? AND date >= date('now', '-${days} days') GROUP BY country ORDER BY pv DESC LIMIT 50`).bind(siteId).all();
      return json({ countries: r.results || [] });
    }

    // ── Realtime (last 5 min from raw pageviews) ──
    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/realtime$/)) {
      const siteId = p.split('/')[3];
      const active = await env.DB.prepare("SELECT COUNT(DISTINCT visitor_id) as visitors, COUNT(*) as pageviews FROM pageviews WHERE site_id=? AND created_at >= datetime('now', '-5 minutes')").bind(siteId).first<any>();
      const pages = await env.DB.prepare("SELECT pathname, COUNT(*) as pv FROM pageviews WHERE site_id=? AND created_at >= datetime('now', '-5 minutes') GROUP BY pathname ORDER BY pv DESC LIMIT 10").bind(siteId).all();
      return json({ active_visitors: active?.visitors || 0, active_pageviews: active?.pageviews || 0, top_pages: pages.results || [] });
    }

    // ── Goals ──
    if (m === 'POST' && p === '/api/goals') {
      const body = await req.json<any>();
      const siteId = body.site_id;
      if (!siteId || !body.name) return err('site_id and name required');
      const id = uid();
      await env.DB.prepare('INSERT INTO goals (id, site_id, name, event_type, match_value) VALUES (?, ?, ?, ?, ?)')
        .bind(id, siteId, sanitize(body.name), body.event_type || 'pageview', body.match_value ? sanitize(body.match_value) : null).run();
      return json({ id });
    }
    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/goals$/)) {
      const siteId = p.split('/')[3];
      const r = await env.DB.prepare('SELECT g.*, (SELECT COUNT(*) FROM goal_conversions gc WHERE gc.goal_id=g.id) as conversions FROM goals g WHERE g.site_id=? ORDER BY g.created_at DESC').bind(siteId).all();
      return json({ goals: r.results || [] });
    }
    if (m === 'DELETE' && p.match(/^\/api\/goals\/[a-zA-Z0-9]+$/)) {
      const id = p.split('/')[3];
      await env.DB.prepare('DELETE FROM goals WHERE id=?').bind(id).run();
      await env.DB.prepare('DELETE FROM goal_conversions WHERE goal_id=?').bind(id).run();
      return json({ ok: true });
    }

    // ── Export ──
    if (m === 'GET' && p.match(/^\/api\/sites\/[a-zA-Z0-9]+\/export$/)) {
      const siteId = p.split('/')[3];
      const days = Math.min(parseInt(url.searchParams.get('days') || '30'), 90);
      const stats = await env.DB.prepare(`SELECT * FROM daily_stats WHERE site_id=? AND date >= date('now', '-${days} days') ORDER BY date`).bind(siteId).all();
      const pages = await env.DB.prepare(`SELECT * FROM daily_pages WHERE site_id=? AND date >= date('now', '-${days} days') ORDER BY date, pageviews DESC`).bind(siteId).all();
      return json({ daily_stats: stats.results || [], daily_pages: pages.results || [] });
    }

    return err('Not found', 404);
    } catch (e: unknown) {
      const msg = (e as Error).message || String(e);
      if (msg.includes('JSON')) return err('Invalid JSON body', 400);
      console.error(`[echo-web-analytics] ${msg}`);
      return err('Internal server error', 500);
    }
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    // Aggregate yesterday's raw pageviews into daily tables
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const sites = await env.DB.prepare('SELECT id FROM sites').all();

    for (const s of (sites.results || []) as any[]) {
      const sid = s.id;

      // Daily stats
      const stats = await env.DB.prepare("SELECT COUNT(*) as pv, COUNT(DISTINCT visitor_id) as vis, COUNT(DISTINCT session_id) as sess, SUM(CASE WHEN is_bounce=1 THEN 1 ELSE 0 END) as bounces, AVG(duration_ms) as avg_dur FROM pageviews WHERE site_id=? AND date(created_at)=?").bind(sid, yesterday).first<any>();
      if (stats && stats.pv > 0) {
        await env.DB.prepare('INSERT INTO daily_stats (site_id, date, pageviews, visitors, sessions, bounces, avg_duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(site_id, date) DO UPDATE SET pageviews=excluded.pageviews, visitors=excluded.visitors, sessions=excluded.sessions, bounces=excluded.bounces, avg_duration_ms=excluded.avg_duration_ms')
          .bind(sid, yesterday, stats.pv, stats.vis, stats.sess, stats.bounces || 0, Math.round(stats.avg_dur || 0)).run();
      }

      // Daily pages
      const pages = await env.DB.prepare("SELECT pathname, COUNT(*) as pv, COUNT(DISTINCT visitor_id) as vis, AVG(duration_ms) as avg_dur FROM pageviews WHERE site_id=? AND date(created_at)=? GROUP BY pathname").bind(sid, yesterday).all();
      for (const pg of (pages.results || []) as any[]) {
        await env.DB.prepare('INSERT INTO daily_pages (site_id, date, pathname, pageviews, visitors, avg_duration_ms) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(site_id, date, pathname) DO UPDATE SET pageviews=excluded.pageviews, visitors=excluded.visitors, avg_duration_ms=excluded.avg_duration_ms')
          .bind(sid, yesterday, pg.pathname, pg.pv, pg.vis, Math.round(pg.avg_dur || 0)).run();
      }

      // Daily referrers
      const refs = await env.DB.prepare("SELECT referrer_domain, COUNT(*) as pv, COUNT(DISTINCT visitor_id) as vis FROM pageviews WHERE site_id=? AND date(created_at)=? AND referrer_domain!='' GROUP BY referrer_domain").bind(sid, yesterday).all();
      for (const r of (refs.results || []) as any[]) {
        await env.DB.prepare('INSERT INTO daily_referrers (site_id, date, referrer_domain, pageviews, visitors) VALUES (?, ?, ?, ?, ?) ON CONFLICT(site_id, date, referrer_domain) DO UPDATE SET pageviews=excluded.pageviews, visitors=excluded.visitors')
          .bind(sid, yesterday, r.referrer_domain, r.pv, r.vis).run();
      }

      // Daily sources
      const sources = await env.DB.prepare("SELECT utm_source, utm_medium, utm_campaign, COUNT(*) as pv, COUNT(DISTINCT visitor_id) as vis FROM pageviews WHERE site_id=? AND date(created_at)=? AND utm_source!='' GROUP BY utm_source").bind(sid, yesterday).all();
      for (const src of (sources.results || []) as any[]) {
        await env.DB.prepare('INSERT INTO daily_sources (site_id, date, utm_source, utm_medium, utm_campaign, pageviews, visitors) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(site_id, date, utm_source) DO UPDATE SET pageviews=excluded.pageviews, visitors=excluded.visitors')
          .bind(sid, yesterday, src.utm_source, src.utm_medium || '', src.utm_campaign || '', src.pv, src.vis).run();
      }

      // Daily devices
      const devs = await env.DB.prepare("SELECT device_type, browser, os, COUNT(*) as pv, COUNT(DISTINCT visitor_id) as vis FROM pageviews WHERE site_id=? AND date(created_at)=? GROUP BY device_type, browser, os").bind(sid, yesterday).all();
      for (const d of (devs.results || []) as any[]) {
        await env.DB.prepare('INSERT INTO daily_devices (site_id, date, device_type, browser, os, pageviews, visitors) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(site_id, date, device_type, browser, os) DO UPDATE SET pageviews=excluded.pageviews, visitors=excluded.visitors')
          .bind(sid, yesterday, d.device_type, d.browser, d.os, d.pv, d.vis).run();
      }

      // Daily countries
      const countries = await env.DB.prepare("SELECT country, COUNT(*) as pv, COUNT(DISTINCT visitor_id) as vis FROM pageviews WHERE site_id=? AND date(created_at)=? AND country!='XX' GROUP BY country").bind(sid, yesterday).all();
      for (const c of (countries.results || []) as any[]) {
        await env.DB.prepare('INSERT INTO daily_countries (site_id, date, country, pageviews, visitors) VALUES (?, ?, ?, ?, ?) ON CONFLICT(site_id, date, country) DO UPDATE SET pageviews=excluded.pageviews, visitors=excluded.visitors')
          .bind(sid, yesterday, c.country, c.pv, c.vis).run();
      }

      // Cleanup raw pageviews older than 48 hours
      await env.DB.prepare("DELETE FROM pageviews WHERE site_id=? AND created_at < datetime('now', '-48 hours')").bind(sid).run();
    }
  }
};
