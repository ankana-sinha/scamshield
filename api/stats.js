import { countCompletedChecks } from "./_lib/supabase.js";

// Cached on Vercel's CDN for at most 10s, never served stale after that, so the
// count is never more than 10s old while bursts still share one Supabase query.
const CACHE_CONTROL = "public, s-maxage=10";

export default async function handler(req, res) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const checksProcessed = await countCompletedChecks();
    res.setHeader("Cache-Control", CACHE_CONTROL);
    return res.status(200).json({ checksProcessed });
  } catch (error) {
    console.error("STATS ERROR:", error);
    res.setHeader("Cache-Control", "no-store");
    return res.status(503).json({ error: "Stats are unavailable right now." });
  }
}
