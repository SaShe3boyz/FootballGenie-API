const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;
const API_TOKEN = process.env.FOOTBALL_DATA_API_TOKEN;

app.use(express.json({ limit: "10kb" }));

// Basic in-memory rate limiter.
// Limits each IP address to 60 requests per 15 minutes.
const requests = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_REQUESTS = 60;

app.use((req, res, next) => {
const now = Date.now();
const ip = req.ip;

let record = requests.get(ip);

if (!record || now - record.start >= WINDOW_MS) {
record = { start: now, count: 0 };
}

record.count++;
requests.set(ip, record);

if (record.count > MAX_REQUESTS) {
return res.status(429).json({
error: "Too many requests. Please try again later."
});
}

next();
});

// Remove expired entries periodically.
setInterval(() => {
const now = Date.now();

for (const [ip, record] of requests.entries()) {
if (now - record.start >= WINDOW_MS) {
requests.delete(ip);
}
}
}, WINDOW_MS).unref();

app.get("/", (req, res) => {
res.json({
app: "Football Genie API",
status: "online",
message: "Football data service is running"
});
});

app.get("/api/competitions", async (req, res) => {
if (!API_TOKEN) {
return res.status(500).json({
error: "Football data API token is not configured."
});
}

try {
const response = await fetch(
"https://api.football-data.org/v4/competitions",
{
headers: { "X-Auth-Token": API_TOKEN },
signal: AbortSignal.timeout(10000)
}
);

const data = await response.json();

if (!response.ok) {
  return res.status(response.status).json({
    error: "Football data provider returned an error.",
    details: data.message || "Request failed"
  });
}

res.json(data);

} catch (error) {
console.error("Competition request failed:", error.message);

res.status(502).json({
  error: "Unable to retrieve football competitions."
});

}
});

app.get("/api/matches", async (req, res) => {
if (!API_TOKEN) {
return res.status(500).json({
error: "Football data API token is not configured."
});
}

const { dateFrom, dateTo } = req.query;

if (
(dateFrom && !/^\d{4}-\d{2}-\d{2}$/.test(dateFrom)) ||
(dateTo && !/^\d{4}-\d{2}-\d{2}$/.test(dateTo))
) {
return res.status(400).json({
error: "Dates must use YYYY-MM-DD format."
});
}

const params = new URLSearchParams();

const startDate = dateFrom ||
    new Date().toISOString().slice(0, 10);

const endBase = new Date(startDate + "T00:00:00Z");

endBase.setUTCDate(endBase.getUTCDate() + 21);

const endDate = dateTo ||
    endBase.toISOString().slice(0, 10);

params.set("dateFrom", startDate);
params.set("dateTo", endDate);

const query = params.toString();
const url =
"https://api.football-data.org/v4/matches" +
(query ? "?${query}" : "");

try {
const response = await fetch(url, {
headers: { "X-Auth-Token": API_TOKEN },
signal: AbortSignal.timeout(10000)
});

const data = await response.json();

if (!response.ok) {
  return res.status(response.status).json({
    error: "Football data provider returned an error.",
    details: data.message || "Request failed"
  });
}

res.json(data);

} catch (error) {
console.error("Match request failed:", error.message);

res.status(502).json({
  error: "Unable to retrieve football matches."
});

}
});

app.listen(PORT, "0.0.0.0", () => {
console.log("Football Genie API is running on port " + PORT);
});
