import { countCompletedChecks } from "./_lib/supabase.js";

// Served from Vercel's CDN cache: fresh for 60s, then served stale while one
// background request refreshes it, so page loads almost never wait on Supabase.
const CACHE_CONTROL = "public, s-maxage=60, stale-while-revalidate=600";

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
