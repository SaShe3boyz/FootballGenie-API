const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const API_TOKEN = process.env.FOOTBALL_DATA_API_TOKEN;
const OWNER_DASHBOARD_TOKEN = process.env.OWNER_DASHBOARD_TOKEN;

// Neon PostgreSQL connection. Credentials are supplied only through Render environment variables.
const dbPool = process.env.DATABASE_URL
    ? new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        max: 5,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000
    })
    : null;

// Best-effort system event logging. Logging failures never break the football API.
async function logSystemEvent(eventType, severity, message, details = {}) {
    if (!dbPool) return;
    try {
        await dbPool.query(
            "INSERT INTO system_events (event_type, severity, message, details) VALUES ($1, $2, $3, $4::jsonb)",
            [String(eventType).slice(0, 80), String(severity).slice(0, 20), String(message).slice(0, 2000), JSON.stringify(details || {})]
        );
    } catch (error) {
        console.error("System event logging failed:", error.message);
    }
}

if (dbPool) {
    dbPool.on("error", error => {
        console.error("Unexpected idle database connection error:", error.message);
        void logSystemEvent("database_connection_error", "error", "Unexpected idle database connection error.", { error: error.message });
    });
} else {
    console.warn("DATABASE_URL is not configured; database features are unavailable.");
}


app.use(express.json({ limit: "32kb" }));

// Owner endpoints require a secret bearer token stored only in Render environment variables.
function requireOwner(req, res, next) {
    if (!OWNER_DASHBOARD_TOKEN || OWNER_DASHBOARD_TOKEN.length < 32) {
        return res.status(503).json({
            error: "Owner access is not configured. Set a strong OWNER_DASHBOARD_TOKEN in Render."
        });
    }

    const authorization = req.get("authorization") || "";
    const match = authorization.match(/^Bearer\s+(.+)$/i);
    if (!match) {
        return res.status(401).json({ error: "Owner authentication required." });
    }

    const supplied = Buffer.from(match[1]);
    const expected = Buffer.from(OWNER_DASHBOARD_TOKEN);
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
        return res.status(401).json({ error: "Invalid owner credentials." });
    }

    next();
}

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


 // Lightweight owner dashboard interface. Sensitive data is loaded only after bearer-token authentication.
app.get("/owner", (req, res) => {
    res.type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Football Genie • Owner Dashboard</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0c1827;color:#eef4ff;font:16px system-ui, sans-serif}
main{max-width:900px;margin:auto;padding:22px}.brand{color:#73d5ff;letter-spacing:2px;font-weight:800}.panel{background:#14263a;border:1px solid #29435c;border-radius:14px;padding:18px;margin:16px 0}
h1{font-size:1.65rem;margin:8px 0}h2{font-size:1.1rem;margin-top:0}label{display:block;margin:12px 0 6px;color:#b9cbe0}
input,textarea,select,button{font:inherit;width:100%;border-radius:8px;padding:11px;border:1px solid #42617e;background:#0c1827;color:#fff}
button{background:#087eaa;border:0;font-weight:700;margin-top:12px;cursor:pointer}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.metric{font-size:1.5rem;font-weight:800;color:#73d5ff}.muted{color:#b9cbe0;font-size:.92rem}.item{padding:12px 0;border-top:1px solid #29435c;overflow-wrap:anywhere}.status{font-weight:700}.error{color:#ff9c9c}.ok{color:#90efb0}#dashboard{display:none}code{overflow-wrap:anywhere}
</style></head><body><main>
<div class="brand">⚽ FOOTBALL GENIE</div><h1>Owner Dashboard</h1><p class="muted">Private system overview • Secure owner access</p>
<section class="panel"><h2>Owner sign-in</h2><p class="muted">Enter the OWNER_DASHBOARD_TOKEN you saved in Render. It is kept only in this browser tab's session storage.</p>
<label for="token">Owner security key</label><input id="token" type="password" autocomplete="current-password" placeholder="Paste your private key">
<button id="connect">Connect securely</button><p id="notice" role="status" class="muted"></p></section>
<div id="dashboard">
<section class="panel"><h2>System overview</h2><div class="grid">
<div><div class="muted">API</div><div id="api" class="metric">—</div></div>
<div><div class="muted">Database</div><div id="db" class="metric">—</div></div>
<div><div class="muted">Validation runs</div><div id="runs" class="metric">—</div></div>
<div><div class="muted">Unread notifications</div><div id="unread" class="metric">—</div></div>
<div><div class="muted">System events</div><div id="eventsCount" class="metric">—</div></div>
</div><p id="checked" class="muted"></p><button id="refresh">Refresh dashboard</button><button id="logout" style="background:#42546a">Sign out</button></section>
<section class="panel"><h2>Create owner notification</h2><label for="ntitle">Title</label><input id="ntitle" maxlength="160" placeholder="Notification title">
<label for="nmessage">Message</label><textarea id="nmessage" maxlength="4000" rows="3" placeholder="Write a note for the owner"></textarea>
<label for="ntype">Type</label><select id="ntype"><option value="info">Information</option><option value="success">Success</option><option value="warning">Warning</option><option value="error">Error</option></select>
<button id="saveNotice">Save notification</button></section>
<section class="panel"><h2>Recent notifications</h2><div id="notifications" class="muted">Connect to load notifications.</div></section>
<section class="panel"><h2>Recent system events</h2><div id="eventList" class="muted">Connect to load events.</div></section>
</div></main>
<script>
const $=id=>document.getElementById(id);let token=sessionStorage.getItem("fg_owner_token")||"";
$("token").value=token;
function safeText(value){return String(value==null?"":value)}
async function api(path,options={}){const headers=Object.assign({"Authorization":"Bearer "+token},options.headers||{});if(options.body)headers["Content-Type"]="application/json";const response=await fetch(path,Object.assign({},options,{headers}));const data=await response.json().catch(()=>({error:"Server returned an unreadable response."}));if(!response.ok)throw new Error(data.error||("Request failed ("+response.status+")"));return data}
function listInto(id,items,fields){const box=$(id);box.replaceChildren();if(!items.length){box.textContent="No records yet.";return}for(const item of items){const div=document.createElement("div");div.className="item";for(const [key,label] of fields){const line=document.createElement("div");line.textContent=label+": "+safeText(item[key]);div.appendChild(line)}box.appendChild(div)}}
async function refresh(){ $("notice").textContent="Loading secure owner data…";try{const [summary,notes,events]=await Promise.all([api("/api/owner/dashboard"),api("/api/owner/notifications"),api("/api/owner/events")]);$("api").textContent=summary.api;$("db").textContent=summary.database;$("runs").textContent=summary.metrics.total_validation_runs;$("unread").textContent=summary.metrics.unread_notifications;$("eventsCount").textContent=summary.metrics.total_events;$("checked").textContent="Checked: "+new Date(summary.checkedAt).toLocaleString();listInto("notifications",notes.notifications,[["title","Title"],["message","Message"],["notification_type","Type"],["created_at","Created"]]);listInto("eventList",events.events,[["event_type","Event"],["severity","Severity"],["message","Message"],["created_at","Created"]]);$("dashboard").style.display="block";$("notice").className="muted ok";$("notice").textContent="Owner access verified."; }catch(e){$("notice").className="muted error";$("notice").textContent=e.message;$("dashboard").style.display="none";}}
$("connect").addEventListener("click",()=>{token=$("token").value.trim();if(!token){$("notice").textContent="Enter your owner key.";return}sessionStorage.setItem("fg_owner_token",token);refresh()});
$("refresh").addEventListener("click",refresh);
$("logout").addEventListener("click",()=>{sessionStorage.removeItem("fg_owner_token");token="";$("token").value="";$("dashboard").style.display="none";$("notice").textContent="Signed out."});
$("saveNotice").addEventListener("click",async()=>{try{await api("/api/owner/notifications",{method:"POST",body:JSON.stringify({title:$("ntitle").value,message:$("nmessage").value,notification_type:$("ntype").value})});$("ntitle").value="";$("nmessage").value="";$("notice").textContent="Notification saved.";await refresh()}catch(e){$("notice").className="muted error";$("notice").textContent=e.message}});
if(token)refresh();
</script></body></html>`);
});

app.get("/", (req, res) => {
res.json({
app: "Football Genie API",
status: "online",
message: "Football data service is running"
});
});

// Safe connectivity check; does not expose database credentials or query results.
app.get("/api/health/database", async (req, res) => {
    if (!dbPool) {
        return res.status(503).json({ status: "unavailable", message: "Database is not configured." });
    }
    try {
        await dbPool.query("SELECT 1");
        return res.json({ status: "connected" });
    } catch (error) {
        console.error("Database health check failed:", error.message);
        return res.status(503).json({ status: "unavailable", message: "Database connection failed." });
    }
});


// Keep one current prediction per known external fixture; local/manual predictions may have no fixture ID.
dbPool && dbPool.query(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_prediction_history_external_unique ON prediction_history (match_external_id) WHERE match_external_id IS NOT NULL"
).catch(error => console.error("Prediction history index setup failed:", error.message));

// Save a prediction snapshot from the Android app. Actual results are only writable through owner-authenticated routes.
function readOptionalNumber(value, min, max) {
    if (value === undefined || value === null || value === "") return null;
    const number = Number(value);
    return Number.isFinite(number) && number >= min && number <= max ? number : NaN;
}

app.post("/api/predictions", async (req, res) => {
    if (!dbPool) return res.status(503).json({ error: "Database is not configured." });

    const body = req.body || {};
    const homeTeam = String(body.homeTeam || body.home_team || body.home || "").trim().slice(0, 100);
    const awayTeam = String(body.awayTeam || body.away_team || body.away || "").trim().slice(0, 100);
    const competition = String(body.competition || "Unknown").trim().slice(0, 120) || "Unknown";
    const matchExternalId = body.matchExternalId == null ? null : String(body.matchExternalId).slice(0, 120);
    const kickoffRaw = body.kickoffAt || body.kickoff_at || null;
    const kickoffAt = kickoffRaw ? new Date(kickoffRaw) : null;

    if (!homeTeam || !awayTeam) {
        return res.status(400).json({ error: "homeTeam and awayTeam are required." });
    }
    if (kickoffRaw && Number.isNaN(kickoffAt.getTime())) {
        return res.status(400).json({ error: "kickoffAt must be a valid date/time." });
    }

    const values = {
        predictedHomeGoals: readOptionalNumber(body.predictedHomeGoals ?? body.predicted_home_goals, 0, 20),
        predictedAwayGoals: readOptionalNumber(body.predictedAwayGoals ?? body.predicted_away_goals, 0, 20),
        homeWinProbability: readOptionalNumber(body.homeWinProbability ?? body.home_win_probability, 0, 100),
        drawProbability: readOptionalNumber(body.drawProbability ?? body.draw_probability, 0, 100),
        awayWinProbability: readOptionalNumber(body.awayWinProbability ?? body.away_win_probability, 0, 100),
        over25Probability: readOptionalNumber(body.over25Probability ?? body.over_25_probability, 0, 100),
        under25Probability: readOptionalNumber(body.under25Probability ?? body.under_25_probability, 0, 100),
        bttsProbability: readOptionalNumber(body.bttsProbability ?? body.btts_probability, 0, 100)
    };
    if (Object.values(values).some(value => Number.isNaN(value))) {
        return res.status(400).json({ error: "Goal estimates must be between 0 and 20; probabilities must be between 0 and 100." });
    }

    try {
        const saved = await dbPool.query(
            `INSERT INTO prediction_history (
                match_external_id, competition, home_team, away_team, kickoff_at,
                predicted_home_goals, predicted_away_goals,
                home_win_probability, draw_probability, away_win_probability,
                over_25_probability, under_25_probability, btts_probability,
                source, notes
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'android_app',$14)
            ON CONFLICT (match_external_id) WHERE match_external_id IS NOT NULL
            DO UPDATE SET
                competition = EXCLUDED.competition,
                home_team = EXCLUDED.home_team,
                away_team = EXCLUDED.away_team,
                kickoff_at = EXCLUDED.kickoff_at,
                predicted_home_goals = EXCLUDED.predicted_home_goals,
                predicted_away_goals = EXCLUDED.predicted_away_goals,
                home_win_probability = EXCLUDED.home_win_probability,
                draw_probability = EXCLUDED.draw_probability,
                away_win_probability = EXCLUDED.away_win_probability,
                over_25_probability = EXCLUDED.over_25_probability,
                under_25_probability = EXCLUDED.under_25_probability,
                btts_probability = EXCLUDED.btts_probability,
                notes = EXCLUDED.notes,
                created_at = NOW()
            WHERE prediction_history.prediction_status <> 'evaluated'
            RETURNING id, prediction_status, created_at`,
            [
                matchExternalId, competition, homeTeam, awayTeam, kickoffAt,
                values.predictedHomeGoals, values.predictedAwayGoals,
                values.homeWinProbability, values.drawProbability, values.awayWinProbability,
                values.over25Probability, values.under25Probability, values.bttsProbability,
                String(body.notes || "").slice(0, 1000) || null
            ]
        );
        const prediction = saved.rows[0];
        void logSystemEvent("prediction_saved", "success", "A prediction was saved to prediction history.", {
            predictionId: prediction.id, homeTeam, awayTeam, competition
        });
        return res.status(201).json({ status: "saved", prediction });
    } catch (error) {
        console.error("Saving prediction failed:", error.message);
        void logSystemEvent("prediction_save_failed", "error", "A prediction could not be saved.", { error: error.message });
        return res.status(503).json({ error: "Unable to save prediction history right now." });
    }
});

// Private owner-only prediction history.
app.get("/api/owner/predictions", requireOwner, async (req, res) => {
    if (!dbPool) return res.status(503).json({ error: "Database is not configured." });
    try {
        const result = await dbPool.query(
            `SELECT id, match_external_id, competition, home_team, away_team, kickoff_at,
                    predicted_home_goals, predicted_away_goals,
                    home_win_probability, draw_probability, away_win_probability,
                    over_25_probability, under_25_probability, btts_probability,
                    actual_home_goals, actual_away_goals, prediction_status,
                    source, notes, created_at, evaluated_at
             FROM prediction_history
             ORDER BY created_at DESC
             LIMIT 100`
        );
        return res.json({ predictions: result.rows });
    } catch (error) {
        console.error("Owner prediction history failed:", error.message);
        return res.status(503).json({ error: "Unable to load prediction history." });
    }
});

// Actual scores can only be entered by the authenticated owner until verified result syncing is added.
app.post("/api/owner/predictions/:id/result", requireOwner, async (req, res) => {
    if (!dbPool) return res.status(503).json({ error: "Database is not configured." });
    const id = Number(req.params.id);
    const body = req.body || {};
    const homeGoals = body.actualHomeGoals;
    const awayGoals = body.actualAwayGoals;
    if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).json({ error: "A valid prediction ID is required." });
    }
    if (!Number.isInteger(homeGoals) || !Number.isInteger(awayGoals) ||
        homeGoals < 0 || awayGoals < 0 || homeGoals > 20 || awayGoals > 20) {
        return res.status(400).json({ error: "Actual scores must be whole numbers between 0 and 20." });
    }
    try {
        const updated = await dbPool.query(
            `UPDATE prediction_history
             SET actual_home_goals = $1, actual_away_goals = $2,
                 prediction_status = 'evaluated', evaluated_at = NOW()
             WHERE id = $3 AND prediction_status <> 'cancelled'
             RETURNING id, home_team, away_team, actual_home_goals, actual_away_goals,
                       prediction_status, evaluated_at`,
            [homeGoals, awayGoals, id]
        );
        if (!updated.rowCount) return res.status(404).json({ error: "Prediction not found or cancelled." });
        void logSystemEvent("prediction_result_recorded", "success", "An actual match result was recorded by the owner.", {
            predictionId: id, actualHomeGoals: homeGoals, actualAwayGoals: awayGoals
        });
        return res.json({ status: "evaluated", prediction: updated.rows[0] });
    } catch (error) {
        console.error("Recording prediction result failed:", error.message);
        return res.status(503).json({ error: "Unable to record the actual result." });
    }
});

// Private owner dashboard summary. No owner data is returned without bearer-token authentication.
app.get("/api/owner/dashboard", requireOwner, async (req, res) => {
    if (!dbPool) {
        return res.status(503).json({ error: "Database is not configured." });
    }
    try {
        const result = await dbPool.query(`
            SELECT
                (SELECT COUNT(*)::int FROM system_events) AS total_events,
                (SELECT COUNT(*)::int FROM validation_runs) AS total_validation_runs,
                (SELECT COUNT(*)::int FROM owner_notifications WHERE is_read = FALSE) AS unread_notifications,
                (SELECT COUNT(*)::int FROM prediction_history) AS total_predictions,
                (SELECT COUNT(*)::int FROM prediction_history WHERE prediction_status = 'pending') AS pending_predictions,
                (SELECT COUNT(*)::int FROM prediction_history WHERE prediction_status = 'evaluated') AS evaluated_predictions
        `);
        return res.json({
            app: "Football Genie",
            ownerAccess: "authenticated",
            api: "online",
            database: "connected",
            metrics: result.rows[0],
            checkedAt: new Date().toISOString()
        });
    } catch (error) {
        console.error("Owner dashboard summary failed:", error.message);
        return res.status(503).json({ error: "Unable to load owner dashboard data." });
    }
});

// Private owner notification list.
app.get("/api/owner/notifications", requireOwner, async (req, res) => {
    if (!dbPool) return res.status(503).json({ error: "Database is not configured." });
    try {
        const result = await dbPool.query(
            "SELECT id, title, message, notification_type, is_read, created_at FROM owner_notifications ORDER BY created_at DESC LIMIT 50"
        );
        return res.json({ notifications: result.rows });
    } catch (error) {
        console.error("Owner notifications query failed:", error.message);
        return res.status(503).json({ error: "Unable to load owner notifications." });
    }
});

// Private owner system-event history.
app.get("/api/owner/events", requireOwner, async (req, res) => {
    if (!dbPool) return res.status(503).json({ error: "Database is not configured." });
    try {
        const result = await dbPool.query(
            "SELECT id, event_type, severity, message, details, created_at FROM system_events ORDER BY created_at DESC LIMIT 50"
        );
        return res.json({ events: result.rows });
    } catch (error) {
        console.error("Owner event history query failed:", error.message);
        return res.status(503).json({ error: "Unable to load owner event history." });
    }
});

// Owner can create a notification after authenticating.
app.post("/api/owner/notifications", requireOwner, async (req, res) => {
    if (!dbPool) return res.status(503).json({ error: "Database is not configured." });
    const title = typeof req.body.title === "string" ? req.body.title.trim() : "";
    const message = typeof req.body.message === "string" ? req.body.message.trim() : "";
    const notificationType = typeof req.body.notification_type === "string"
        ? req.body.notification_type.trim()
        : "info";
    if (!title || title.length > 160 || !message || message.length > 4000) {
        return res.status(400).json({ error: "Title (1–160 characters) and message (1–4000 characters) are required." });
    }
    if (!["info", "success", "warning", "error"].includes(notificationType)) {
        return res.status(400).json({ error: "notification_type must be info, success, warning, or error." });
    }
    try {
        const result = await dbPool.query(
            "INSERT INTO owner_notifications (title, message, notification_type) VALUES ($1, $2, $3) RETURNING id, title, message, notification_type, is_read, created_at",
            [title, message, notificationType]
        );
        return res.status(201).json({ notification: result.rows[0] });
    } catch (error) {
        console.error("Owner notification creation failed:", error.message);
        return res.status(503).json({ error: "Unable to save owner notification." });
    }
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

// Short-lived cache keeps repeated fixture loads fast and reduces provider calls.
const matchesCache = new Map();
const MATCH_CACHE_TTL_MS = 3 * 60 * 1000;

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
        return res.status(400).json({ error: "Dates must use YYYY-MM-DD format." });
    }

    const defaultStart = new Date();
    defaultStart.setUTCDate(defaultStart.getUTCDate() - 3);
    const startDate = dateFrom || defaultStart.toISOString().slice(0, 10);
    const firstEndDate = new Date(startDate + "T00:00:00Z");
    firstEndDate.setUTCDate(firstEndDate.getUTCDate() + 10);
    const endDate = dateTo || firstEndDate.toISOString().slice(0, 10);

    const windows = [];
    if (!dateFrom && !dateTo) {
        const secondStart = new Date(firstEndDate);
        secondStart.setUTCDate(secondStart.getUTCDate() + 1);
        const secondEnd = new Date(secondStart);
        secondEnd.setUTCDate(secondEnd.getUTCDate() + 10);
        windows.push(
            { from: startDate, to: endDate },
            { from: secondStart.toISOString().slice(0, 10), to: secondEnd.toISOString().slice(0, 10) }
        );
    } else {
        windows.push({ from: startDate, to: dateTo || endDate });
    }

    const cacheKey = windows.map(w => w.from + ":" + w.to).join("|");
    const cached = matchesCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
        res.set("X-Football-Genie-Cache", "HIT");
        return res.json(cached.data);
    }

    try {
        // Fetch both date windows concurrently instead of waiting for one before starting the other.
        const windowResults = await Promise.all(windows.map(async window => {
            const params = new URLSearchParams({
                dateFrom: window.from,
                dateTo: window.to
            });
            const response = await fetch(
                "https://api.football-data.org/v4/matches?" + params.toString(),
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
                throw new Error("Football provider returned non-JSON (HTTP " + response.status + ").");
            }
            if (!response.ok) {
                const providerError = new Error(data.message || "Football data provider request failed.");
                providerError.status = response.status;
                throw providerError;
            }
            return data;
        }));

        const allMatches = new Map();
        let combinedData = windowResults[0] || {};
        let playedCount = 0;
        for (const data of windowResults) {
            for (const match of (Array.isArray(data.matches) ? data.matches : [])) {
                if (match && match.id != null) allMatches.set(match.id, match);
            }
            playedCount += Number(data.resultSet && data.resultSet.played || 0);
        }

        const matches = Array.from(allMatches.values()).sort(
            (a, b) => new Date(a.utcDate) - new Date(b.utcDate)
        );
        const lastWindow = windows[windows.length - 1];
        const firstDate = matches.length ? matches[0].utcDate.slice(0, 10) : startDate;
        const lastDate = matches.length ? matches[matches.length - 1].utcDate.slice(0, 10) : lastWindow.to;

        const result = {
            ...combinedData,
            filters: {
                ...(combinedData.filters || {}),
                dateFrom: startDate,
                dateTo: lastWindow.to
            },
            resultSet: {
                ...(combinedData.resultSet || {}),
                count: matches.length,
                first: firstDate,
                last: lastDate,
                played: playedCount
            },
            matches
        };

        matchesCache.set(cacheKey, { data: result, expiresAt: Date.now() + MATCH_CACHE_TTL_MS });
        // Keep the cache small and discard expired entries.
        for (const [key, value] of matchesCache.entries()) {
            if (Date.now() >= value.expiresAt || matchesCache.size > 20) matchesCache.delete(key);
        }
        res.set("X-Football-Genie-Cache", "MISS");
        return res.json(result);
    } catch (error) {
        console.error("Football matches error:", error.message);
        // If the provider is temporarily slow, use recently cached fixtures rather than leave the app waiting.
        const stale = matchesCache.get(cacheKey);
        if (stale && Date.now() - (stale.expiresAt - MATCH_CACHE_TTL_MS) < 24 * 60 * 60 * 1000) {
            res.set("X-Football-Genie-Cache", "STALE");
            return res.json(stale.data);
        }
        return res.status(error.status || 502).json({
            error: "Unable to retrieve football matches.",
            details: error.message || "Unknown server error."
        });
    }
});

// Return current competition home/away scoring baselines and team strength rates.
// These season rates let the app adjust recent form for the level of opposition.
app.get("/api/competition-strength", async (req, res) => {
    if (!API_TOKEN) {
        return res.status(500).json({ error: "Football data API token is not configured." });
    }

    const competitionId = String(req.query.competitionId || "");
    if (!/^\d+$/.test(competitionId) || Number(competitionId) <= 0) {
        return res.status(400).json({ error: "A valid numeric competitionId is required." });
    }

    try {
        const response = await fetch(
            "https://api.football-data.org/v4/competitions/" +
            encodeURIComponent(competitionId) + "/standings",
            {
                headers: { "X-Auth-Token": API_TOKEN },
                signal: AbortSignal.timeout(10000)
            }
        );
        const responseText = await response.text();
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (error) {
            return res.status(502).json({ error: "Football data provider returned a non-JSON response." });
        }
        if (!response.ok) {
            return res.status(response.status).json({
                error: "Competition standings are unavailable.",
                details: data.message || "Request failed"
            });
        }

        const standings = Array.isArray(data.standings) ? data.standings : [];
        const homeRows = (standings.find(item => item.type === "HOME") || {}).table || [];
        const awayRows = (standings.find(item => item.type === "AWAY") || {}).table || [];
        const totalRows = (standings.find(item => item.type === "TOTAL") || {}).table || [];

        const average = (rows, field) => {
            const played = rows.reduce((sum, row) => sum + (Number(row.playedGames) || 0), 0);
            const goals = rows.reduce((sum, row) => sum + (Number(row[field]) || 0), 0);
            return played > 0 ? goals / played : 0;
        };
        const homeLeagueGoals = average(homeRows, "goalsFor");
        const awayLeagueGoals = average(awayRows, "goalsFor");
        if (!homeRows.length || !awayRows.length || homeLeagueGoals <= 0 || awayLeagueGoals <= 0) {
            return res.status(422).json({ error: "Usable home/away competition standings are unavailable." });
        }

        const teamMap = {};
        for (const row of homeRows) {
            if (!row.team || row.team.id == null) continue;
            const played = Number(row.playedGames) || 0;
            teamMap[String(row.team.id)] = {
                teamId: Number(row.team.id),
                homePlayed: played,
                homeScored: played ? (Number(row.goalsFor) || 0) / played : homeLeagueGoals,
                homeConceded: played ? (Number(row.goalsAgainst) || 0) / played : awayLeagueGoals
            };
        }
        for (const row of awayRows) {
            if (!row.team || row.team.id == null) continue;
            const played = Number(row.playedGames) || 0;
            const id = String(row.team.id);
            if (!teamMap[id]) teamMap[id] = { teamId: Number(row.team.id) };
            teamMap[id].awayPlayed = played;
            teamMap[id].awayScored = played ? (Number(row.goalsFor) || 0) / played : awayLeagueGoals;
            teamMap[id].awayConceded = played ? (Number(row.goalsAgainst) || 0) / played : homeLeagueGoals;
        }

        res.json({
            competition: data.competition || { id: Number(competitionId) },
            homeLeagueGoalsPerMatch: Number(homeLeagueGoals.toFixed(3)),
            awayLeagueGoalsPerMatch: Number(awayLeagueGoals.toFixed(3)),
            teams: Object.values(teamMap)
        });
    } catch (error) {
        console.error("Competition strength request failed:", error.message);
        return res.status(502).json({ error: "Unable to retrieve competition standings." });
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

        const matches = Array.isArray(data.matches) ? data.matches : [];
        const matchingTeamMatch = matches.find(match =>
            Number(match.homeTeam && match.homeTeam.id) === Number(teamId) ||
            Number(match.awayTeam && match.awayTeam.id) === Number(teamId)
        );
        const inferredTeamName = matchingTeamMatch
            ? (Number(matchingTeamMatch.homeTeam && matchingTeamMatch.homeTeam.id) === Number(teamId)
                ? matchingTeamMatch.homeTeam.name
                : matchingTeamMatch.awayTeam.name)
            : "Team " + teamId;
        const team = data.team || { id: Number(teamId), name: inferredTeamName };
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
        let homeVenuePlayed = 0;
        let homeVenueGoalsFor = 0;
        let homeVenueGoalsAgainst = 0;
        let awayVenuePlayed = 0;
        let awayVenueGoalsFor = 0;
        let awayVenueGoalsAgainst = 0;

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
                if (isHome) {
                    homeVenuePlayed++;
                    homeVenueGoalsFor += scored;
                    homeVenueGoalsAgainst += conceded;
                } else {
                    awayVenuePlayed++;
                    awayVenueGoalsFor += scored;
                    awayVenueGoalsAgainst += conceded;
                }
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
                    opponentId: isHome
                        ? (match.awayTeam ? match.awayTeam.id : null)
                        : (match.homeTeam ? match.homeTeam.id : null),
                    competitionId: match.competition && match.competition.id
                        ? match.competition.id : null,
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
            venueStats: {
                home: {
                    sampleSize: homeVenuePlayed,
                    averageScored: homeVenuePlayed ? Number((homeVenueGoalsFor / homeVenuePlayed).toFixed(2)) : 0,
                    averageConceded: homeVenuePlayed ? Number((homeVenueGoalsAgainst / homeVenuePlayed).toFixed(2)) : 0
                },
                away: {
                    sampleSize: awayVenuePlayed,
                    averageScored: awayVenuePlayed ? Number((awayVenueGoalsFor / awayVenuePlayed).toFixed(2)) : 0,
                    averageConceded: awayVenuePlayed ? Number((awayVenueGoalsAgainst / awayVenuePlayed).toFixed(2)) : 0
                }
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


// Groq is the primary AI provider for Football Genie.
async function requestGroqAnswer(systemInstruction, userContent) {
    if (!process.env.GROQ_API_KEY) return null;
    const model = process.env.GROQ_MODEL || "openai/gpt-oss-120b";
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
            "Authorization": "Bearer " + process.env.GROQ_API_KEY,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            model,
            temperature: 0.2,
            max_tokens: 3000,
            messages: [
                { role: "system", content: systemInstruction },
                { role: "user", content: userContent }
            ]
        }),
        signal: AbortSignal.timeout(45000)
    });
    const textBody = await response.text();
    let data;
    try { data = JSON.parse(textBody); }
    catch (_) { throw new Error("Groq returned an unreadable response."); }
    if (!response.ok) {
        throw new Error("Groq HTTP " + response.status + ": " +
            String(data.error && data.error.message || "provider request failed").slice(0, 220));
    }
    const answer = data.choices && data.choices[0] && data.choices[0].message
        ? String(data.choices[0].message.content || "").trim() : "";
    if (!answer) throw new Error("Groq returned an empty answer.");
    return { answer, model };
}

async function sendGroqFallback(res, systemInstruction, userContent, evidence) {
    if (!process.env.GROQ_API_KEY) return false;
    try {
        const result = await requestGroqAnswer(systemInstruction, userContent);
        console.warn("AI provider fallback used: Groq", result.model);
        res.json({ answer: result.answer, provider: "groq", model: result.model, evidenceUsed: evidence });
        return true;
    } catch (error) {
        console.error("Groq fallback failed:", error.message);
        return false;
    }
}

// Evidence-grounded conversational analysis. Provider keys stay on the server.
// Groq is primary; OpenAI is an optional fallback if Groq is unavailable.
app.post("/api/ai/analyze", async (req, res) => {
    const prompt = String(req.body && req.body.question || "").trim();
    const context = req.body && req.body.match && typeof req.body.match === "object"
        ? req.body.match : {};
    if (!prompt || prompt.length > 1200) {
        return res.status(400).json({ error: "A question between 1 and 1200 characters is required." });
    }
    const home = String(context.home || "Home team").slice(0, 100);
    const away = String(context.away || "Away team").slice(0, 100);
    const numericFields = ["homeXg", "awayXg", "homeWin", "draw", "awayWin", "over25", "under25", "btts"];
    const evidence = {};
    for (const field of numericFields) {
        const value = Number(context[field]);
        evidence[field] = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : null;
    }
    const validationSummary = String(req.body && req.body.validationSummary || "").slice(0, 12000);
    const completedHistory = (Array.isArray(req.body && req.body.completedHistory)
        ? req.body.completedHistory : []).slice(0, 15).map(item => {
            const clean = {
                home: String(item && item.home || "").slice(0, 80),
                away: String(item && item.away || "").slice(0, 80)
            };
            for (const field of ["predictedHome", "predictedAway", "actualHome", "actualAway"]) {
                const value = Number(item && item[field]);
                clean[field] = Number.isFinite(value) ? Math.max(-1, Math.min(20, value)) : null;
            }
            for (const field of ["homeXg", "awayXg", "homeP", "drawP", "awayP", "overP", "bttsP"]) {
                const value = Number(item && item[field]);
                clean[field] = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : null;
            }
            return clean;
        });

    const systemInstruction = "You are Football Genie, powered by Groq when the Groq provider is configured. If asked which provider you use, answer Groq only when the request is being served by Groq; do not claim to know private infrastructure beyond that. You are a careful football-model analyst. Explain predictions using only the evidence provided. Separate observed data from model estimates. Do not invent injuries, line-ups, live match events, possession, shots, or external facts. Expected goals are estimates, not actual goals. If completed match history is supplied, compare predicted versus actual scores, identify recurring error patterns and suggest testable improvements, clearly noting small-sample limitations. You may recommend experiments but must never claim that you changed or trained the app's model. Explain uncertainty and avoid guarantees or betting certainty. If the evidence is insufficient, say what is missing. Keep the answer practical and readable on a phone.";
    const userContent = "Question: " + prompt +
        "\nSaved validation report summary (user-provided app metrics):\n" + validationSummary +
        "\nMatch evidence (percentages are model probabilities, not live facts):\n" +
        JSON.stringify({ home, away, ...evidence }) +
        "\nCompleted saved predictions with actual scores (historical evidence only; newest first):\n" +
        JSON.stringify(completedHistory);

    void logSystemEvent("ai_analysis_requested", "info", "AI analysis request received.", { questionLength: prompt.length });
    try {
        // Groq is the primary AI provider. OpenAI is an optional independent fallback.
        let groqFailureMessage = "";
        if (process.env.GROQ_API_KEY) {
            try {
                const result = await requestGroqAnswer(systemInstruction, userContent);
                void logSystemEvent("ai_analysis_succeeded", "success", "AI analysis completed successfully.", { provider: "groq", model: result.model });
                return res.json({
                    answer: result.answer,
                    provider: "groq",
                    model: result.model,
                    evidenceUsed: evidence
                });
            } catch (groqError) {
                groqFailureMessage = String(groqError && groqError.message || "Unknown Groq error");
                console.error("Groq primary provider failed; trying OpenAI fallback:", groqFailureMessage);
            }
        }

        if (process.env.OPENAI_API_KEY) {
            const model = process.env.OPENAI_MODEL || "gpt-4o-mini";
            const response = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + process.env.OPENAI_API_KEY,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    model,
                    temperature: 0.2,
                    max_tokens: 3000,
                    messages: [
                        { role: "system", content: systemInstruction },
                        { role: "user", content: userContent }
                    ]
                }),
                signal: AbortSignal.timeout(22000)
            });
            const textBody = await response.text();
            let data;
            try { data = JSON.parse(textBody); }
            catch (_) { throw new Error("OpenAI returned an unreadable response."); }
            if (!response.ok) {
                console.error("OpenAI provider error:", response.status, data.error && data.error.message);
                return res.status(502).json({ error: "The AI analyst could not complete this request. Please try again." });
            }
            const answer = data.choices && data.choices[0] && data.choices[0].message
                ? String(data.choices[0].message.content || "").trim() : "";
            if (!answer) return res.status(502).json({ error: "The AI analyst returned an empty answer." });
            return res.json({ answer, provider: "openai", model, evidenceUsed: evidence });
        }

        if (process.env.GROQ_API_KEY && groqFailureMessage) {
            return res.status(502).json({
                code: "AI_PROVIDER_FAILED",
                error: "Groq could not complete this analysis: " + groqFailureMessage.slice(0, 180) + ". Please try again."
            });
        }

        return res.status(503).json({
            code: "AI_NOT_CONFIGURED",
            error: "Cloud AI is not configured. Add GROQ_API_KEY for Groq, or OPENAI_API_KEY for the optional OpenAI fallback."
        });
    } catch (error) {
        console.error("AI analysis request failed:", error.name, error.message);
        void logSystemEvent("ai_analysis_failed", "error", "AI analysis request failed.", { errorName: error.name, error: String(error.message || "").slice(0, 300) });
        return res.status(502).json({
            error: "AI analysis failed: " + String(error.name || "Error") +
                (error.message ? " - " + String(error.message).slice(0, 180) : "")
        });
    }
});

app.listen(PORT, "0.0.0.0", () => {
console.log("Football Genie API is running on port " + PORT);
    void logSystemEvent("api_started", "success", "Football Genie API started successfully.", { port: PORT });
    if (dbPool) {
        dbPool.query("SELECT 1")
            .then(() => {
                console.log("Neon PostgreSQL connection verified.");
                void logSystemEvent("database_connected", "success", "Neon PostgreSQL connection verified.");
            })
            .catch(error => {
                console.error("Neon PostgreSQL connection failed:", error.message);
                void logSystemEvent("database_connection_failed", "error", "Neon PostgreSQL connection failed.", { error: error.message });
            });
    }
});
