const API_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";

// Primary model first, then fallbacks (override with OPENAI_FALLBACK_MODELS="a,b").
const MODELS = [
  process.env.OPENAI_MODEL || "gemini-flash-latest",
  ...(process.env.OPENAI_FALLBACK_MODELS || "gemini-flash-lite-latest,gemini-2.5-flash")
    .split(",")
    .map((m) => m.trim())
    .filter(Boolean)
].filter((m, i, all) => all.indexOf(m) === i);

const ATTEMPTS_PER_MODEL = 2;
const RETRY_DELAY_MS = 800;

// Overload / rate-limit / transient server errors: worth retrying or trying another model.
const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

const SYSTEM_PROMPT = `You are ScamShield, a financial safety assistant for elderly users in India.

Analyze the message for potential financial scams, fraud, impersonation, phishing, fake KYC requests, UPI fraud, lottery scams, suspicious links, OTP requests, or pressure to transfer money.

Give a cautious, easy-to-understand assessment.

Never claim certainty that a message is safe or fraudulent.
If there is meaningful uncertainty, advise the user not to share OTPs, PINs, passwords, CVV, or transfer money until independently verified.

Return:
Risk Level: Low / Medium / High
Why: 2-4 simple bullet points
What to do: 2-4 practical actions

Use simple language suitable for an elderly Indian user.`;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

class ModelError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function callModel(model, message) {
  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: message }
      ]
    })
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    console.error("OPENAI ERROR:", model, response.status, data);
    const apiError = Array.isArray(data) ? data[0]?.error : data?.error;
    throw new ModelError(apiError?.message || "Unknown OpenAI error", response.status);
  }

  return data;
}

async function callWithFallback(message) {
  let lastError;

  for (const model of MODELS) {
    for (let attempt = 1; attempt <= ATTEMPTS_PER_MODEL; attempt++) {
      try {
        return { data: await callModel(model, message), model };
      } catch (error) {
        lastError = error;

        // 404 = model not available for this key: skip straight to the next model.
        if (error.status === 404) break;
        // Bad request / auth errors won't be fixed by retrying or switching models.
        if (error.status && !RETRYABLE_STATUS.has(error.status)) throw error;

        if (attempt < ATTEMPTS_PER_MODEL) await sleep(RETRY_DELAY_MS * attempt);
      }
    }
  }

  throw lastError;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { message } = req.body || {};

    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Message is required" });
    }

    if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({ error: "OPENAI_API_KEY is not configured" });
    }

    const { data, model } = await callWithFallback(message);

    const result =
      data?.choices?.[0]?.message?.content ||
      "Unable to analyze this message.";

    return res.status(200).json({ result, model });
  } catch (error) {
    console.error("SCAMSHIELD ERROR:", error);

    if (error instanceof ModelError) {
      return res.status(error.status === 429 || error.status === 503 ? 503 : 500).json({
        error: "OpenAI request failed",
        details: error.message
      });
    }

    return res.status(500).json({
      error: error?.message || "ScamShield could not complete the check."
    });
  }
}
