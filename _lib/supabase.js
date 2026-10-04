// Minimal Supabase REST (PostgREST) client. Server-side only: it uses the
// secret/service-role key, which bypasses row-level security.

const TIMEOUT_MS = 2500;

function config() {
  const url = process.env.SUPABASE_URL?.replace(/\/+$/, "");
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  return url && key ? { url, key } : null;
}

function headers(key, extra = {}) {
  return {
    apikey: key,
    // Legacy service_role keys are JWTs and go in Authorization too; the newer
    // sb_secret_ keys must only be sent as apikey.
    ...(key.startsWith("eyJ") ? { Authorization: `Bearer ${key}` } : {}),
    ...extra
  };
}

export function isSupabaseConfigured() {
  return Boolean(config());
}

// Never throws: logging a check must not break the check itself.
export async function logCheck(row) {
  const cfg = config();
  if (!cfg) return;

  try {
    const response = await fetch(`${cfg.url}/rest/v1/checks`, {
      method: "POST",
      headers: headers(cfg.key, { "Content-Type": "application/json", Prefer: "return=minimal" }),
      body: JSON.stringify(row),
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });

    if (!response.ok) {
      console.error("SUPABASE INSERT ERROR:", response.status, await response.text().catch(() => ""));
    }
  } catch (error) {
    console.error("SUPABASE INSERT ERROR:", error);
  }
}

// Number of successfully completed checks. Uses a HEAD request so no rows are
// transferred; PostgREST returns the total in the Content-Range header.
export async function countCompletedChecks() {
  const cfg = config();
  if (!cfg) throw new Error("Supabase is not configured");

  const response = await fetch(`${cfg.url}/rest/v1/checks?status=eq.ok&select=id`, {
    method: "HEAD",
    headers: headers(cfg.key, { Prefer: "count=exact", Range: "0-0" }),
    signal: AbortSignal.timeout(TIMEOUT_MS)
  });

  const total = Number(response.headers.get("content-range")?.split("/")[1]);
  if (!response.ok || !Number.isFinite(total)) {
    throw new Error(`Supabase count failed with status ${response.status}`);
  }

  return total;
}
