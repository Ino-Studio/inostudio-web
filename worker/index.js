// inostudio.lv: static assets plus the contact form endpoint.

const LIMITS = { name: 200, email: 254, phone: 50, message: 5000 };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.hostname === 'www.inostudio.lv') {
      url.hostname = 'inostudio.lv';
      return Response.redirect(url.toString(), 301);
    }

    if (url.pathname === '/api/contact') {
      if (request.method !== 'POST') return json({ ok: false, error: 'method' }, 405);
      return handleContact(request, env);
    }

    return env.ASSETS.fetch(request);
  },
};

async function handleContact(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'invalid' }, 400);
  }

  // Honeypot: real visitors never see this field
  if (body.website) return json({ ok: true });

  const f = {};
  for (const key of Object.keys(LIMITS)) {
    f[key] = typeof body[key] === 'string' ? body[key].trim() : '';
    if (f[key].length > LIMITS[key]) return json({ ok: false, error: 'invalid' }, 400);
  }
  if (!f.name || !f.message || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(f.email)) {
    return json({ ok: false, error: 'invalid' }, 400);
  }

  const captcha = await verifyRecaptcha(body.token, request, env);
  if (!captcha.ok) {
    console.warn('recaptcha rejected', captcha);
    return json({ ok: false, error: 'captcha' }, 403);
  }

  const lines = [
    `Vārds: ${f.name}`,
    `E-pasts: ${f.email}`,
    ...(f.phone ? [`Tālrunis: ${f.phone}`] : []),
    `Valoda: ${body.lang === 'en' ? 'EN' : 'LV'}`,
    '',
    f.message,
  ];

  try {
    await env.EMAIL.send({
      to: env.CONTACT_TO,
      from: { email: env.CONTACT_FROM, name: 'inostudio.lv' },
      replyTo: { email: f.email, name: f.name },
      subject: `inostudio.lv pieteikums: ${f.name}`,
      text: lines.join('\n'),
      html: renderHtml(f, body.lang),
    });
  } catch (err) {
    console.error('email send failed', err && err.message);
    return json({ ok: false, error: 'send' }, 502);
  }

  return json({ ok: true });
}

async function verifyRecaptcha(token, request, env) {
  if (typeof token !== 'string' || !token) return { ok: false, reason: 'no-token' };

  const form = new URLSearchParams({ secret: env.RECAPTCHA_SECRET, response: token });
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) form.set('remoteip', ip);

  const res = await fetch('https://www.google.com/recaptcha/api/siteverify', { method: 'POST', body: form });
  const r = await res.json();

  const hosts = env.RECAPTCHA_HOSTNAMES.split(',');
  const minScore = Number(env.RECAPTCHA_MIN_SCORE);
  const ok = r.success === true && r.action === 'contact' && r.score >= minScore && hosts.includes(r.hostname);
  return { ok, score: r.score, action: r.action, hostname: r.hostname, errors: r['error-codes'] };
}

function renderHtml(f, lang) {
  const row = (label, value) =>
    `<tr><td style="padding:4px 16px 4px 0;color:#888;vertical-align:top">${label}</td><td style="padding:4px 0">${value}</td></tr>`;
  return `<div style="font-family:Arial,sans-serif;font-size:15px;color:#111">
<table style="border-collapse:collapse">
${row('Vārds', esc(f.name))}
${row('E-pasts', `<a href="mailto:${esc(f.email)}">${esc(f.email)}</a>`)}
${f.phone ? row('Tālrunis', esc(f.phone)) : ''}
${row('Valoda', lang === 'en' ? 'EN' : 'LV')}
</table>
<p style="white-space:pre-wrap;border-top:1px solid #e0e0de;padding-top:16px;margin-top:16px">${esc(f.message)}</p>
</div>`;
}

function esc(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function json(data, status = 200) {
  return Response.json(data, { status, headers: { 'Cache-Control': 'no-store' } });
}
