const MAX = { name: 100, email: 254, budget: 100, message: 5000 };
const WINDOW_MS = 10 * 60 * 1000;
const MAX_PER_WINDOW = 5;
const hits = new Map();

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const tooMany = (ip) => {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  hits.set(ip, recent);
  return recent.length > MAX_PER_WINDOW;
};

const sameOrigin = (req) => {
  const origin = req.headers.origin;
  if (!origin) return false;
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
};

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  if (!sameOrigin(req)) return res.status(403).json({ error: "Forbidden" });

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (tooMany(ip)) return res.status(429).json({ error: "Too many requests" });

  const body = req.body || {};

  // Honeypot: real users never fill this hidden field. Pretend success so bots move on.
  if (body.website) return res.status(200).json({ ok: true });

  const fields = {};
  for (const key of Object.keys(MAX)) {
    const value = typeof body[key] === "string" ? body[key].trim() : "";
    if (!value || value.length > MAX[key]) return res.status(400).json({ error: "Invalid input" });
    fields[key] = value;
  }
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(fields.email) || /[\r\n]/.test(fields.name + fields.email)) {
    return res.status(400).json({ error: "Invalid input" });
  }

  const { RESEND_API_KEY, CONTACT_TO_EMAIL, CONTACT_FROM_EMAIL } = process.env;
  if (!RESEND_API_KEY || !CONTACT_TO_EMAIL) {
    return res.status(500).json({ error: "Server not configured" });
  }

  const html =
    `<p><strong>Name:</strong> ${escapeHtml(fields.name)}</p>` +
    `<p><strong>Email:</strong> ${escapeHtml(fields.email)}</p>` +
    `<p><strong>Budget:</strong> ${escapeHtml(fields.budget)}</p>` +
    `<p><strong>Message:</strong></p><p>${escapeHtml(fields.message).replace(/\n/g, "<br>")}</p>`;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: CONTACT_FROM_EMAIL || "Portfolio Contact <onboarding@resend.dev>",
      to: [CONTACT_TO_EMAIL],
      reply_to: fields.email,
      subject: `Portfolio Contact Form - ${fields.name.slice(0, 60)}`,
      html,
    }),
  });

  if (!response.ok) return res.status(502).json({ error: "Failed to send" });
  return res.status(200).json({ ok: true });
};
