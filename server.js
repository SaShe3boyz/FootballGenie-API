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


// Return recent finished-match performance for one team.
// The provider token remains on the server and is never sent to the app.
app.get("/api/team-stats", async (req, res) => {
    if (!API_TOKEN) {
        return res.status(500).json({
            error: "Football data API token is not configured."
        });
    }

    const teamId = String(req.query.teamId || "");
    const requestedLimit = Number(req.query.limit || 10);

    if (!/^\d+$/.test(teamId) || Number(teamId) <= 0) {
        return res.status(400).json({
            error: "A valid numeric teamId is required."
        });
    }

    if (!Number.isInteger(requestedLimit) || requestedLimit < 5 || requestedLimit > 20) {
        return res.status(400).json({
            error: "limit must be a whole number between 5 and 20."
        });
    }

    try {
        const params = new URLSearchParams();
        params.set("status", "FINISHED");
        params.set("limit", String(requestedLimit));

        const response = await fetch(
            "https://api.football-data.org/v4/teams/" +
            encodeURIComponent(teamId) +
            "/matches?" + params.toString(),
            {
                headers: { "X-Auth-Token": API_TOKEN },
                signal: AbortSignal.timeout(10000)
            }
        );

        const responseText = await response.text();
        let data;

        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            console.error(
                "Team matches provider returned non-JSON:",
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

        const team = data.team || { id: Number(teamId), name: "Team " + teamId };
        const matches = Array.isArray(data.matches) ? data.matches : [];
        let played = 0;
        let wins = 0;
        let draws = 0;
        let losses = 0;
        let goalsFor = 0;
        let goalsAgainst = 0;
        let cleanSheets = 0;
        let over25 = 0;
        let btts = 0;
        let form = "";

        const recentMatches = matches
            .filter(match => match && match.status === "FINISHED")
            .sort((a, b) => new Date(b.utcDate) - new Date(a.utcDate))
            .map(match => {
                const isHome = Number(match.homeTeam && match.homeTeam.id) === Number(teamId);
                const isAway = Number(match.awayTeam && match.awayTeam.id) === Number(teamId);
                if (!isHome && !isAway) return null;

                const homeGoals = match.score && match.score.fullTime
                    ? match.score.fullTime.home
                    : null;
                const awayGoals = match.score && match.score.fullTime
                    ? match.score.fullTime.away
                    : null;

                if (homeGoals == null || awayGoals == null) return null;

                const scored = isHome ? homeGoals : awayGoals;
                const conceded = isHome ? awayGoals : homeGoals;
                const outcome = scored > conceded ? "W" : (scored === conceded ? "D" : "L");

                played++;
                goalsFor += scored;
                goalsAgainst += conceded;
                if (outcome === "W") wins++;
                else if (outcome === "D") draws++;
                else losses++;
                if (conceded === 0) cleanSheets++;
                if (homeGoals + awayGoals > 2) over25++;
                if (homeGoals > 0 && awayGoals > 0) btts++;
                form += outcome;

                return {
                    matchId: match.id,
                    date: match.utcDate,
                    competition: match.competition ? match.competition.name : "",
                    opponent: isHome
                        ? (match.awayTeam ? match.awayTeam.name : "Unknown")
                        : (match.homeTeam ? match.homeTeam.name : "Unknown"),
                    venue: isHome ? "HOME" : "AWAY",
                    score: String(homeGoals) + "-" + String(awayGoals),
                    goalsFor: scored,
                    goalsAgainst: conceded,
                    result: outcome
                };
            })
            .filter(Boolean);

        res.json({
            team: { id: Number(teamId), name: team.name },
            sampleSize: played,
            form: form,
            record: { wins, draws, losses },
            goals: {
                scored: goalsFor,
                conceded: goalsAgainst,
                averageScored: played ? Number((goalsFor / played).toFixed(2)) : 0,
                averageConceded: played ? Number((goalsAgainst / played).toFixed(2)) : 0
            },
            cleanSheets: cleanSheets,
            over25Percent: played ? Number((over25 * 100 / played).toFixed(1)) : 0,
            bttsPercent: played ? Number((btts * 100 / played).toFixed(1)) : 0,
            matches: recentMatches
        });
    } catch (error) {
        console.error("Team stats request failed:", error.message);
        return res.status(502).json({
            error: "Unable to retrieve recent team performance.",
            details: error.message || "Unknown server error."
        });
    }
});

app.listen(PORT, "0.0.0.0", () => {
console.log("Football Genie API is running on port " + PORT);
});
