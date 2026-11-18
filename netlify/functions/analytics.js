
const crypto = require("crypto");

const PROPERTY_ID = "564923343";

function jsonResponse(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify(body)
  };
}

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function getAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);

  const header = base64url(JSON.stringify({
    alg: "RS256",
    typ: "JWT"
  }));

  const claim = base64url(JSON.stringify({
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/analytics.readonly",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  }));

  const unsignedToken = `${header}.${claim}`;

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsignedToken);

  const signature = signer
    .sign(serviceAccount.private_key, "base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  const jwt = `${unsignedToken}.${signature}`;

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt
    })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error("Google authentication failed: " + JSON.stringify(data));
  }

  return data.access_token;
}

async function googleReport(token, reportType, body) {
  const endpoint =
    `https://analyticsdata.googleapis.com/v1beta/properties/${PROPERTY_ID}:${reportType}`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(`${reportType} failed: ${JSON.stringify(data)}`);
  }

  return data;
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return jsonResponse(405, { error: "Method not allowed" });
  }

  try {
    const input = JSON.parse(event.body || "{}");
    const submittedPassword = input.password || "";
    const adminPassword = process.env.KAVENROX_ADMIN_PASSWORD;

    if (!adminPassword) {
      throw new Error("Admin password is not configured");
    }

    const submittedHash = crypto
      .createHash("sha256")
      .update(submittedPassword)
      .digest();

    const expectedHash = crypto
      .createHash("sha256")
      .update(adminPassword)
      .digest();

    if (!crypto.timingSafeEqual(submittedHash, expectedHash)) {
      return jsonResponse(401, { error: "Incorrect password" });
    }

    const rawCredentials = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;

    if (!rawCredentials) {
      throw new Error("Google credentials are missing");
    }

    const serviceAccount = JSON.parse(rawCredentials);
    const token = await getAccessToken(serviceAccount);

    const [overview, realtime] = await Promise.all([
      googleReport(token, "runReport", {
        dateRanges: [
          { startDate: "30daysAgo", endDate: "today" }
        ],
        metrics: [
          { name: "totalUsers" },
          { name: "screenPageViews" },
          { name: "sessions" }
        ]
      }),

      googleReport(token, "runRealtimeReport", {
        metrics: [
          { name: "activeUsers" }
        ]
      })
    ]);

    const values = overview.rows?.[0]?.metricValues || [];
    const activeUsers =
      realtime.rows?.[0]?.metricValues?.[0]?.value || "0";

    return jsonResponse(200, {
      visitors: values[0]?.value || "0",
      pageViews: values[1]?.value || "0",
      sessions: values[2]?.value || "0",
      activeUsers,
      period: "Last 30 days"
    });

  } catch (error) {
    console.error("KAVENROX Analytics error:", error);

    return jsonResponse(500, {
      error: "Unable to load Analytics data. Please check the configuration."
    });
  }
};
