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

const defaultStart = new Date();
defaultStart.setUTCDate(defaultStart.getUTCDate() - 3);

const startDate = dateFrom ||
    defaultStart.toISOString().slice(0, 10);

const firstEndDate = new Date(startDate + "T00:00:00Z");
firstEndDate.setUTCDate(firstEndDate.getUTCDate() + 10);

const endDate = dateTo ||
    firstEndDate.toISOString().slice(0, 10);

// The provider limits each date-range request, so use two consecutive
// windows by default. This gives the app a longer view of each competition
// without exceeding the provider's per-request date-range limit.
const windows = [];
if (!dateFrom && !dateTo) {
    const secondStart = new Date(firstEndDate);
    secondStart.setUTCDate(secondStart.getUTCDate() + 1);
    const secondEnd = new Date(secondStart);
    secondEnd.setUTCDate(secondEnd.getUTCDate() + 10);

    windows.push(
        { from: startDate, to: endDate },
        {
            from: secondStart.toISOString().slice(0, 10),
            to: secondEnd.toISOString().slice(0, 10)
        }
    );
} else {
    const effectiveEnd = dateTo || endDate;
    windows.push({ from: startDate, to: effectiveEnd });
}

try {
    const allMatches = new Map();
    let combinedData = null;
    let playedCount = 0;

    for (const window of windows) {
        const params = new URLSearchParams();
        params.set("dateFrom", window.from);
        params.set("dateTo", window.to);

        const url =
            "https://api.football-data.org/v4/matches?" +
            params.toString();

        const response = await fetch(url, {
            headers: { "X-Auth-Token": API_TOKEN },
            signal: AbortSignal.timeout(10000)
        });

        const responseText = await response.text();
        let data;

        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            console.error(
                "Football provider returned non-JSON:",
                response.status,
                responseText.slice(0, 300)
            );

            return res.status(502).json({
                error: "Football data provider returned a non-JSON response.",
                providerStatus: response.status
            });
        }

        if (!response.ok) {
            return res.status(response.status).json({
                error: "Football data provider returned an error.",
                details: data.message || "Request failed"
            });
        }

        if (!combinedData) {
            combinedData = data;
        }

        const matches = Array.isArray(data.matches) ? data.matches : [];
        for (const match of matches) {
            if (match && match.id != null) {
                allMatches.set(match.id, match);
            }
        }

        playedCount += Number(data.resultSet?.played || 0);
    }

    const matches = Array.from(allMatches.values()).sort(
        (a, b) => new Date(a.utcDate) - new Date(b.utcDate)
    );

    const firstDate = matches.length
        ? matches[0].utcDate.slice(0, 10)
        : startDate;
    const lastDate = matches.length
        ? matches[matches.length - 1].utcDate.slice(0, 10)
        : (windows[windows.length - 1].to);

    res.json({
        ...combinedData,
        filters: {
            ...(combinedData.filters || {}),
            dateFrom: startDate,
            dateTo: windows[windows.length - 1].to
        },
        resultSet: {
            ...(combinedData.resultSet || {}),
            count: matches.length,
            first: firstDate,
            last: lastDate,
            played: playedCount
        },
        matches
    });

} catch (error) {
    console.error("Football matches error:", error);

    res.status(502).json({
        error: "Unable to retrieve football matches.",
        details: error.message || "Unknown server error."
    });
}
});

const responseText = await response.text();

let data;

try {
    data = JSON.parse(responseText);
} catch (parseError) {
    console.error(
        "Football provider returned non-JSON:",
        response.status,
        responseText.slice(0, 300)
    );

    return res.status(502).json({
        error: "Football data provider returned a non-JSON response.",
        providerStatus: response.status
    });
}
if (!response.ok) {
  return res.status(response.status).json({
    error: "Football data provider returned an error.",
    details: data.message || "Request failed"
  });
}

res.json(data);

} catch (error) {
    console.error("Football matches error:", error);

    res.status(502).json({
        error: "Unable to retrieve football matches.",
        details: error.message || "Unknown server error."
    });
}
});

app.listen(PORT, "0.0.0.0", () => {
console.log("Football Genie API is running on port " + PORT);
});
