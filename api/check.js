export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { message } = req.body || {};

    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Message is required" });
    }

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        temperature: 0.2,
        messages: [
          {
            role: "system",
            content: `You are ScamShield, a financial safety assistant for elderly users in India.

Analyze the message for potential financial scams, fraud, impersonation, phishing, fake KYC requests, UPI fraud, lottery scams, suspicious links, OTP requests, or pressure to transfer money.

Give a cautious, easy-to-understand assessment.

Never claim certainty that a message is safe or fraudulent.
If there is meaningful uncertainty, advise the user not to share OTPs, PINs, passwords, CVV, or transfer money until independently verified.

Return:
Risk Level: Low / Medium / High
Why: 2-4 simple bullet points
What to do: 2-4 practical actions

Use simple language suitable for an elderly Indian user.`
          },
          {
            role: "user",
            content: message
          }
        ]
      })
    });

    const data = await response.json();

   if (!response.ok) {
  console.error("OPENAI ERROR:", response.status, data);

  return res.status(500).json({
    error: "OpenAI request failed",
    details: data?.error?.message || "Unknown OpenAI error"
  });
}

    const result =
      data?.choices?.[0]?.message?.content ||
      "Unable to analyze this message.";

    return res.status(200).json({ result });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "ScamShield could not complete the check."
    });
  }
}
