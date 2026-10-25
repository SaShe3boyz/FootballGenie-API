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
const retryAfterSeconds = Math.max(1, Math.ceil((WINDOW_MS - (now - record.start)) / 1000));
res.set("Retry-After", String(retryAfterSeconds));
return res.status(429).json({
status: "rate_limited",
error: "Too many requests from this connection. Please wait before retrying.",
retryAfterSeconds,
limit: MAX_REQUESTS,
windowSeconds: Math.floor(WINDOW_MS / 1000)
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
<div><div class="muted">Total predictions</div><div id="totalPredictions" class="metric">—</div></div>
<div><div class="muted">Pending predictions</div><div id="pendingPredictions" class="metric">—</div></div>
<div><div class="muted">Evaluated predictions</div><div id="evaluatedPredictions" class="metric">—</div></div>
</div><p id="checked" class="muted"></p><button id="refresh">Refresh dashboard</button><button id="logout" style="background:#42546a">Sign out</button></section>
<section class="panel"><h2>Create owner notification</h2><label for="ntitle">Title</label><input id="ntitle" maxlength="160" placeholder="Notification title">
<label for="nmessage">Message</label><textarea id="nmessage" maxlength="4000" rows="3" placeholder="Write a note for the owner"></textarea>
<label for="ntype">Type</label><select id="ntype"><option value="info">Information</option><option value="success">Success</option><option value="warning">Warning</option><option value="error">Error</option></select>
<button id="saveNotice">Save notification</button></section>
<section class="panel"><h2>Recent notifications</h2><div id="notifications" class="muted">Connect to load notifications.</div></section>
<section class="panel"><h2>Prediction History</h2><p class="muted">Latest saved predictions from the central database. Accuracy will be calculated only from matches with recorded actual scores.</p><div id="predictionList" class="muted">Connect to load predictions.</div></section>
<section class="panel"><h2>Recent system events</h2><div id="eventList" class="muted">Connect to load events.</div></section>
</div></main>
<script>
const $=id=>document.getElementById(id);let token=sessionStorage.getItem("fg_owner_token")||"";
$("token").value=token;
function safeText(value){return String(value==null?"":value)}
async function api(path,options={}){const headers=Object.assign({"Authorization":"Bearer "+token},options.headers||{});if(options.body)headers["Content-Type"]="application/json";const response=await fetch(path,Object.assign({},options,{headers}));const data=await response.json().catch(()=>({error:"Server returned an unreadable response."}));if(!response.ok)throw new Error(data.error||("Request failed ("+response.status+")"));return data}
function listInto(id,items,fields){const box=$(id);box.replaceChildren();if(!items.length){box.textContent="No records yet.";return}for(const item of items){const div=document.createElement("div");div.className="item";for(const [key,label] of fields){const line=document.createElement("div");line.textContent=label+": "+safeText(item[key]);div.appendChild(line)}box.appendChild(div)}}
async function refresh(){ $("notice").textContent="Loading secure owner data…";try{const [summary,notes,events,predictionData]=await Promise.all([api("/api/owner/dashboard"),api("/api/owner/notifications"),api("/api/owner/events"),api("/api/owner/predictions")]);$("api").textContent=summary.api;$("db").textContent=summary.database;$("runs").textContent=summary.metrics.total_validation_runs;$("unread").textContent=summary.metrics.unread_notifications;$("eventsCount").textContent=summary.metrics.total_events;$("totalPredictions").textContent=summary.metrics.total_predictions;$("pendingPredictions").textContent=summary.metrics.pending_predictions;$("evaluatedPredictions").textContent=summary.metrics.evaluated_predictions;$("checked").textContent="Checked: "+new Date(summary.checkedAt).toLocaleString();listInto("notifications",notes.notifications,[["title","Title"],["message","Message"],["notification_type","Type"],["created_at","Created"]]);listInto("eventList",events.events,[["event_type","Event"],["severity","Severity"],["message","Message"],["created_at","Created"]]);listInto("predictionList",predictionData.predictions,[["home_team","Home team"],["away_team","Away team"],["competition","Competition"],["kickoff_at","Kickoff"],["predicted_home_goals","Predicted home goals"],["predicted_away_goals","Predicted away goals"],["home_win_probability","Home win %"],["draw_probability","Draw %"],["away_win_probability","Away win %"],["over_25_probability","Over 2.5 %"],["under_25_probability","Under 2.5 %"],["btts_probability","BTTS %"],["prediction_status","Status"],["actual_home_goals","Actual home goals"],["actual_away_goals","Actual away goals"],["created_at","Saved at"]]);$("dashboard").style.display="block";$("notice").className="muted ok";$("notice").textContent="Owner access verified. Prediction history loaded."; }catch(e){$("notice").className="muted error";$("notice").textContent=e.message;$("dashboard").style.display="none";}}
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


// Allow different users to predict the same fixture, but only once per user/install.
// The Android app supplies a stable anonymous client ID until account sign-in is introduced.
const predictionSchemaReady = dbPool
    ? dbPool.query("ALTER TABLE prediction_history ADD COLUMN IF NOT EXISTS client_id TEXT")
        .then(() => dbPool.query("DROP INDEX IF EXISTS idx_prediction_history_external_unique"))
        .then(() => dbPool.query("CREATE INDEX IF NOT EXISTS idx_prediction_history_external_idx ON prediction_history (match_external_id)"))
        .then(() => dbPool.query("CREATE INDEX IF NOT EXISTS idx_prediction_history_client_idx ON prediction_history (client_id)"))
        .then(() => dbPool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_prediction_history_client_fixture_unique ON prediction_history (client_id, match_external_id) WHERE client_id IS NOT NULL AND match_external_id IS NOT NULL"))
        .catch(error => {
            console.error("Prediction history schema migration failed:", error.message);
            throw error;
        })
    : Promise.resolve();

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
    const clientIdRaw = body.clientId ?? body.client_id ?? null;
    const clientId = clientIdRaw == null ? null : String(clientIdRaw).trim().slice(0, 120) || null;
    if (matchExternalId && !clientId) {
        return res.status(400).json({ error: "clientId is required for fixture predictions so duplicate submissions can be prevented." });
    }
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
        await predictionSchemaReady;
        const saved = await dbPool.query(
            `INSERT INTO prediction_history (
                match_external_id, client_id, competition, home_team, away_team, kickoff_at,
                predicted_home_goals, predicted_away_goals,
                home_win_probability, draw_probability, away_win_probability,
                over_25_probability, under_25_probability, btts_probability,
                source, notes
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'android_app',$15)
            RETURNING id, prediction_status, created_at`,
            [
                matchExternalId, clientId, competition, homeTeam, awayTeam, kickoffAt,
                values.predictedHomeGoals, values.predictedAwayGoals,
                values.homeWinProbability, values.drawProbability, values.awayWinProbability,
                values.over25Probability, values.under25Probability, values.bttsProbability,
                String(body.notes || "").slice(0, 1000) || null
            ]
        );
        const prediction = saved.rows[0];
        void logSystemEvent("prediction_saved", "success", "A prediction was saved to prediction history.", {
            predictionId: prediction.id, clientId, homeTeam, awayTeam, competition
        });
        return res.status(201).json({ status: "saved", prediction });
    } catch (error) {
        if (error && error.code === "23505") {
            return res.status(409).json({ error: "You have already saved a prediction for this fixture." });
        }
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
                    source, notes, client_id, created_at, evaluated_at
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

// Short-lived cache keeps repeated fixture loads fast while allowing live statuses to update frequently.
const matchesCache = new Map();
const MATCH_CACHE_TTL_MS = 90 * 1000;

app.get("/api/matches", async (req, res) => {
    if (!API_TOKEN) {
        return res.status(500).json({ error: "Football data API token is not configured." });
    }

    const { dateFrom, dateTo } = req.query;
    const forceRefresh = ["1", "true", "yes"].includes(String(req.query.refresh || "").toLowerCase());
    if (
        (dateFrom && !/^\\d{4}-\\d{2}-\\d{2}$/.test(dateFrom)) ||
        (dateTo && !/^\\d{4}-\\d{2}-\\d{2}$/.test(dateTo))
    ) {
        return res.status(400).json({ error: "Dates must use YYYY-MM-DD format." });
    }

    // Keep recent completed games available for result syncing, but cover today and the next
    // 20 days so the list remains useful throughout the current matchday and upcoming rounds.
    const now = new Date();
    const defaultStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
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
    if (!forceRefresh && cached && Date.now() < cached.expiresAt) {
        res.set("X-Football-Genie-Cache", "HIT");
        res.set("X-Football-Genie-Data-Age-Seconds", String(Math.floor((Date.now() - cached.fetchedAt) / 1000)));
        return res.json(cached.data);
    }

    try {
        const windowResults = await Promise.all(windows.map(async window => {
            const params = new URLSearchParams({ dateFrom: window.from, dateTo: window.to });
            const response = await fetch(
                "https://api.football-data.org/v4/matches?" + params.toString(),
                {
                    headers: { "X-Auth-Token": API_TOKEN },
                    signal: AbortSignal.timeout(15000)
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

        // Query LIVE separately from date windows. Some provider schedules omit or lag
        // live status when using date filters, so this independent status query gives live
        // matches priority and prevents the schedule from hiding matches in progress.
        let liveMatches = [];
        try {
            const liveResponse = await fetch(
                "https://api.football-data.org/v4/matches?status=LIVE",
                {
                    headers: { "X-Auth-Token": API_TOKEN },
                    signal: AbortSignal.timeout(10000)
                }
            );
            const liveText = await liveResponse.text();
            let liveData = {};
            try {
                liveData = JSON.parse(liveText);
            } catch (_) {
                liveData = {};
            }
            if (liveResponse.ok && Array.isArray(liveData.matches)) {
                liveMatches = liveData.matches;
            } else {
                console.warn("Live matches refresh was unavailable (HTTP " + liveResponse.status + ").");
            }
        } catch (liveError) {
            // A live-query failure must not block scheduled fixture retrieval.
            console.warn("Live matches refresh failed:", liveError.message);
        }

        const allMatches = new Map();
        const combinedData = windowResults[0] || {};
        let playedCount = 0;
        for (const data of windowResults) {
            for (const match of (Array.isArray(data.matches) ? data.matches : [])) {
                if (match && match.id != null) allMatches.set(match.id, match);
            }
            playedCount += Number(data.resultSet && data.resultSet.played || 0);
        }
        // Merge independently queried live matches by ID, overriding stale status/details
        // from a date-window result if the same match appears in both responses.
        for (const match of liveMatches) {
            if (match && match.id != null) allMatches.set(match.id, match);
        }

        const all = Array.from(allMatches.values());
        const liveStatuses = new Set(["IN_PLAY", "PAUSED", "EXTRA_TIME", "PENALTY_SHOOTOUT"]);
        const finishedStatuses = new Set(["FINISHED", "AWARDED"]);
        const nowMs = Date.now();
        const kickoff = match => Date.parse(match.utcDate || "") || 0;
        // Put live games first, then future fixtures by kickoff, then recent completed games
        // newest-first. This prevents three days of finished matches hiding today's live games.
        all.sort((a, b) => {
            const aLive = liveStatuses.has(a.status);
            const bLive = liveStatuses.has(b.status);
            if (aLive !== bLive) return aLive ? -1 : 1;

            const aFuture = !finishedStatuses.has(a.status) && kickoff(a) >= nowMs;
            const bFuture = !finishedStatuses.has(b.status) && kickoff(b) >= nowMs;
            if (aFuture !== bFuture) return aFuture ? -1 : 1;
            if (aFuture && bFuture) return kickoff(a) - kickoff(b);
            if (finishedStatuses.has(a.status) && finishedStatuses.has(b.status)) return kickoff(b) - kickoff(a);
            return kickoff(a) - kickoff(b);
        });

        const lastWindow = windows[windows.length - 1];
        const result = {
            ...combinedData,
            filters: {
                ...(combinedData.filters || {}),
                dateFrom: startDate,
                dateTo: lastWindow.to
            },
            resultSet: {
                ...(combinedData.resultSet || {}),
                count: all.length,
                first: all.length ? new Date(Math.min(...all.map(kickoff))).toISOString().slice(0, 10) : startDate,
                last: all.length ? new Date(Math.max(...all.map(kickoff))).toISOString().slice(0, 10) : lastWindow.to,
                played: playedCount
            },
            liveCount: all.filter(match => liveStatuses.has(match.status)).length,
            matches: all
        };

        const fetchedAt = Date.now();
        matchesCache.set(cacheKey, { data: result, fetchedAt, expiresAt: fetchedAt + MATCH_CACHE_TTL_MS });
        for (const [key, value] of matchesCache.entries()) {
            if (Date.now() >= value.expiresAt || matchesCache.size > 20) matchesCache.delete(key);
        }
        res.set("X-Football-Genie-Cache", "MISS");
        res.set("X-Football-Genie-Data-Age-Seconds", "0");
        return res.json(result);
    } catch (error) {
        console.error("Football matches error:", error.message);
        // Do not disguise old fixtures as live data when the provider is unavailable.
        return res.status(error.status || 502).json({
            status: "fixtures_provider_unavailable",
            error: "Unable to retrieve fresh football matches.",
            details: error.message || "Unknown server error.",
            staleFixturesServed: false
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


// Resolve a real fixture from team names/date before querying injuries.
// This avoids mixing football-data.org IDs with API-Football IDs.
const resolvedFixtureCache = new Map();
const RESOLVED_FIXTURE_CACHE_TTL_MS = 15 * 60 * 1000;
function normalizeTeamName(value) {
    return String(value || "").toLowerCase()
        .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
        .replace(/\b(fc|afc|cf|sc|club|football club)\b/g, " ")
        .replace(/[^a-z0-9]+/g, " ").trim().replace(/\s+/g, " ");
}
app.get("/api/match-intelligence/resolve-fixture", async (req, res) => {
    // Fixture lookup now uses the existing Football-Data.org provider already configured for Football Genie.
    // Its match IDs are NOT API-Football fixture IDs and must not be passed to the API-Football injuries route.
    const providerKey = process.env.FOOTBALL_DATA_API_TOKEN;
    if (!providerKey) {
        return res.status(503).json({ status: "not_configured", error: "Football-Data.org is not configured.", requiredEnvironmentVariable: "FOOTBALL_DATA_API_TOKEN" });
    }
    const homeTeam = String(req.query.homeTeam || "").trim().slice(0, 100);
    const awayTeam = String(req.query.awayTeam || "").trim().slice(0, 100);
    const date = String(req.query.date || "").trim();
    if (!homeTeam || !awayTeam || !/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date + "T00:00:00Z"))) {
        return res.status(400).json({ error: "Provide homeTeam, awayTeam, and date in YYYY-MM-DD format." });
    }
    const cacheKey = [normalizeTeamName(homeTeam), normalizeTeamName(awayTeam), date].join("|");
    const cached = resolvedFixtureCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
        res.set("X-Football-Genie-Cache", "HIT");
        return res.json(cached.data);
    }
    try {
        // Football-Data.org treats dateTo as exclusive, so request the following day to include the requested date.
        const dayAfter = new Date(date + "T00:00:00Z");
        dayAfter.setUTCDate(dayAfter.getUTCDate() + 1);
        const params = new URLSearchParams({ dateFrom: date, dateTo: dayAfter.toISOString().slice(0, 10) });
        const providerResponse = await fetch("https://api.football-data.org/v4/matches?" + params.toString(), {
            headers: { "X-Auth-Token": providerKey },
            signal: AbortSignal.timeout(12000)
        });
        const textBody = await providerResponse.text();
        let data;
        try { data = JSON.parse(textBody); }
        catch (_) { return res.status(502).json({ status: "provider_error", error: "Football-Data.org returned an unreadable response." }); }
        if (!providerResponse.ok || (data && data.errorCode)) {
            console.warn("Football-Data.org fixture resolution failed:", JSON.stringify({ status: providerResponse.status, errorCode: data && data.errorCode, message: data && data.message }).slice(0, 500));
            return res.status(502).json({
                status: "provider_error",
                error: "Football-Data.org could not return fixtures for this date.",
                providerStatus: providerResponse.status,
                providerMessage: data && data.message ? String(data.message).slice(0, 250) : undefined
            });
        }
        const fixtures = Array.isArray(data.matches) ? data.matches : [];
        const targetHome = normalizeTeamName(homeTeam);
        const targetAway = normalizeTeamName(awayTeam);
        const candidates = fixtures.filter(item =>
            normalizeTeamName(item && item.homeTeam && (item.homeTeam.name || item.homeTeam.shortName)) === targetHome &&
            normalizeTeamName(item && item.awayTeam && (item.awayTeam.name || item.awayTeam.shortName)) === targetAway
        );
        let result;
        if (candidates.length === 1) {
            const item = candidates[0];
            result = {
                status: "fixture_resolved",
                verifiedAt: new Date().toISOString(),
                source: "Football-Data.org",
                fixture: {
                    fixtureId: item.id,
                    fixtureIdProvider: "Football-Data.org",
                    date: item.utcDate,
                    status: item.status,
                    homeTeam: item.homeTeam && item.homeTeam.name,
                    homeTeamId: item.homeTeam && item.homeTeam.id,
                    awayTeam: item.awayTeam && item.awayTeam.name,
                    awayTeamId: item.awayTeam && item.awayTeam.id,
                    competition: item.competition && item.competition.name,
                    season: item.season && item.season.startDate ? Number(item.season.startDate.slice(0, 4)) : undefined
                },
                nextStep: "This is a Football-Data.org match ID. Do not use it as an API-Football fixtureId; injury data needs a matching ID from its own provider."
            };
        } else {
            result = {
                status: candidates.length ? "ambiguous_fixture" : "fixture_not_found",
                verifiedAt: new Date().toISOString(),
                source: "Football-Data.org",
                query: { homeTeam, awayTeam, date },
                candidateCount: candidates.length,
                providerFixtureCount: fixtures.length,
                sampleFixtures: candidates.length ? undefined : fixtures.slice(0, 8).map(item => ({
                    homeTeam: item && item.homeTeam && item.homeTeam.name,
                    awayTeam: item && item.awayTeam && item.awayTeam.name,
                    competition: item && item.competition && item.competition.name,
                    kickoff: item && item.utcDate
                })),
                interpretation: candidates.length
                    ? "More than one exact home/away team-name match was found; no fixture was selected."
                    : fixtures.length === 0
                        ? "Football-Data.org returned zero matches for this date, which may be due to its competition coverage or account access."
                        : "Matches were returned for this date, but no exact home/away team-name match was found. Check sampleFixtures for provider spelling or aliases."
            };
        }
        resolvedFixtureCache.set(cacheKey, { expiresAt: Date.now() + RESOLVED_FIXTURE_CACHE_TTL_MS, data: result });
        return res.json(result);
    } catch (error) {
        console.error("Football-Data.org fixture resolution request failed:", error.message);
        return res.status(502).json({ status: "provider_error", error: "Unable to resolve the fixture right now." });
    }
});

// Source-backed injury and suspension intelligence via API-Football (API-Sports).
// Use API-Football IDs here; IDs from football-data.org are not interchangeable.
const injuryCache = new Map();
const INJURY_CACHE_TTL_MS = 15 * 60 * 1000;
// Diagnostic endpoint: verify API-Football fixture access without exposing provider credentials.
app.get("/api/match-intelligence/provider-check", async (req, res) => {
    const providerKey = process.env.API_FOOTBALL_API_KEY || process.env.APIFOOTBALL_API_KEY;
    if (!providerKey) {
        return res.status(503).json({
            status: "not_configured",
            error: "API-Football provider key is not configured.",
            requiredEnvironmentVariable: "API_FOOTBALL_API_KEY"
        });
    }
    const teamId = String(req.query.teamId || "42").trim();
    const season = String(req.query.season || "2024").trim();
    if (!/^\d+$/.test(teamId) || !/^\d{4}$/.test(season)) {
        return res.status(400).json({ error: "teamId must be numeric and season must be a four-digit year." });
    }
    try {
        const params = new URLSearchParams({ team: teamId, season });
        const response = await fetch("https://v3.football.api-sports.io/fixtures?" + params.toString(), {
            headers: { "x-apisports-key": providerKey },
            signal: AbortSignal.timeout(12000)
        });
        const bodyText = await response.text();
        let data;
        try { data = JSON.parse(bodyText); }
        catch (_) { return res.status(502).json({ status: "provider_error", error: "Provider returned unreadable data." }); }
        if (!response.ok || (Array.isArray(data.errors) && data.errors.length)) {
            return res.status(502).json({
                status: "provider_error",
                providerStatus: response.status,
                errors: data.errors || [],
                message: "API-Football could not verify fixture access for this query."
            });
        }
        const fixtures = Array.isArray(data.response) ? data.response : [];
        return res.json({
            status: fixtures.length ? "fixtures_found" : "no_fixtures_returned",
            source: "API-Football / API-Sports",
            query: { teamId: Number(teamId), season: Number(season) },
            count: fixtures.length,
            sampleFixtures: fixtures.slice(0, 5).map(item => ({
                fixtureId: item.fixture && item.fixture.id,
                date: item.fixture && item.fixture.date,
                status: item.fixture && item.fixture.status && item.fixture.status.short,
                home: item.teams && item.teams.home && item.teams.home.name,
                away: item.teams && item.teams.away && item.teams.away.name,
                league: item.league && item.league.name
            })),
            providerErrors: data.errors || [],
            interpretation: fixtures.length
                ? "Fixture records are available. Their API-Football fixture IDs can be used to test fixture-specific injury records."
                : "No fixture records were returned. Check provider coverage, season availability, and API plan limits before drawing conclusions."
        });
    } catch (error) {
        console.error("API-Football provider check failed:", error.message);
        return res.status(502).json({ status: "provider_error", error: "Could not reach the fixture provider." });
    }
});

app.get("/api/match-intelligence/injuries", async (req, res) => {
    const providerKey = process.env.API_FOOTBALL_API_KEY || process.env.APIFOOTBALL_API_KEY;
    if (!providerKey) {
        return res.status(503).json({
            status: "not_configured",
            error: "Injury intelligence provider is not configured.",
            requiredEnvironmentVariable: "API_FOOTBALL_API_KEY",
            setup: "Add an API-Football/API-Sports key to the Render environment, then redeploy."
        });
    }

    const fixtureId = String(req.query.fixtureId || "").trim();
    const teamId = String(req.query.teamId || "").trim();
    const season = String(req.query.season || "").trim();
    if (fixtureId && !/^\d+$/.test(fixtureId)) {
        return res.status(400).json({ error: "fixtureId must be a numeric API-Football fixture ID." });
    }
    if (!fixtureId && (!/^\d+$/.test(teamId) || !/^\d{4}$/.test(season))) {
        return res.status(400).json({
            error: "Provide fixtureId, or provide teamId and season using API-Football IDs."
        });
    }

    const params = new URLSearchParams();
    if (fixtureId) params.set("fixture", fixtureId);
    else {
        params.set("team", teamId);
        params.set("season", season);
    }
    const cacheKey = params.toString();
    const cached = injuryCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
        res.set("X-Football-Genie-Cache", "HIT");
        return res.json(cached.data);
    }

    try {
        const response = await fetch("https://v3.football.api-sports.io/injuries?" + params.toString(), {
            headers: { "x-apisports-key": providerKey },
            signal: AbortSignal.timeout(12000)
        });
        const bodyText = await response.text();
        let data;
        try { data = JSON.parse(bodyText); }
        catch (_) {
            return res.status(502).json({ status: "provider_error", error: "Injury provider returned an unreadable response." });
        }
        if (!response.ok) {
            return res.status(response.status === 401 || response.status === 403 ? 502 : response.status).json({
                status: "provider_error",
                error: "Injury provider request failed.",
                providerStatus: response.status
            });
        }
        if (Array.isArray(data.errors) && data.errors.length) {
            console.warn("API-Football injury provider returned errors:", JSON.stringify(data.errors).slice(0, 500));
            return res.status(502).json({
                status: "provider_error",
                error: "Injury provider could not verify availability for this request."
            });
        }

        const records = Array.isArray(data.response) ? data.response : [];
        const injuries = records.map(item => ({
            player: item.player && item.player.name || "Unknown player",
            playerId: item.player && item.player.id != null ? item.player.id : null,
            team: item.team && item.team.name || "Unknown team",
            teamId: item.team && item.team.id != null ? item.team.id : null,
            type: item.player && item.player.type || item.type || "Unavailable",
            reason: item.player && item.player.reason || item.reason || "Reason not supplied",
            fixtureId: item.fixture && item.fixture.id != null ? item.fixture.id : null,
            fixtureDate: item.fixture && item.fixture.date || null
        }));

        const result = {
            status: records.length ? "data_found" : "no_records_returned",
            verifiedAt: new Date().toISOString(),
            source: "API-Football / API-Sports",
            query: fixtureId ? { fixtureId: Number(fixtureId) } : { teamId: Number(teamId), season: Number(season) },
            count: injuries.length,
            injuries,
            interpretation: records.length
                ? "The provider returned player unavailability records. Check each record's fixture/date and reason before applying a match impact."
                : "The provider returned no records for this query. This does not prove that both teams have no injuries or suspensions; coverage may be incomplete."
        };
        injuryCache.set(cacheKey, { expiresAt: Date.now() + INJURY_CACHE_TTL_MS, data: result });
        return res.json(result);
    } catch (error) {
        console.error("Injury intelligence request failed:", error.message);
        return res.status(502).json({
            status: "provider_error",
            error: "Unable to retrieve injury intelligence right now."
        });
    }
});

// Free-first football news discovery using Google News RSS. RSS results are leads, not proof of player availability.
// Keep recent, team-relevant stories and label the evidence so the app can distinguish stale reports.
const footballNewsCache = new Map();
const FOOTBALL_NEWS_CACHE_TTL_MS = 5 * 60 * 1000;
const FOOTBALL_NEWS_MAX_AGE_DAYS = 7;

const FOOTBALL_NEWS_MAX_ARTICLE_FETCHES = 8;
async function extractFullNewsStory(articleUrl, publisherUrl = null, articleTitle = "", allowPublisherResolve = true) {
    if (!/^https?:\/\//i.test(String(articleUrl || ""))) return null;
    try {
        const response = await fetch(articleUrl, {
            headers: {
                "User-Agent": "Mozilla/5.0 (compatible; FootballGenie/1.0; +https://football-genie-api.onrender.com)",
                "Accept": "text/html,application/xhtml+xml"
            },
            signal: AbortSignal.timeout(6500),
            redirect: "follow"
        });
        if (!response.ok) return null;
        const type = response.headers.get("content-type") || "";
        if (!/text\/html|application\/xhtml\+xml/i.test(type)) return null;
        const html = (await response.text()).slice(0, 1500000);
        // Google News' article wrapper contains links to the original publisher.
        // Resolve the matching story URL so extraction reads the publisher page,
        // not just the aggregator's navigation and headline.
        if (allowPublisherResolve && publisherUrl) {
            try {
                const expectedHost = new URL(publisherUrl).hostname.toLowerCase().replace(/^www\./, "");
                const currentHost = new URL(articleUrl).hostname.toLowerCase().replace(/^www\./, "");
                if (expectedHost && currentHost.endsWith("news.google.com")) {
                    const titleTokens = String(articleTitle || "").toLowerCase()
                        .replace(/[^a-z0-9]+/g, " ").split(/\s+/).filter(token => token.length > 3);
                    const hrefs = [...html.matchAll(/(?:href|content)\s*=\s*["']([^"']+)["']/gi)]
                        .map(match => {
                            try { return new URL(decodeNewsXml(match[1]), response.url || articleUrl); }
                            catch (_) { return null; }
                        })
                        .filter(url => url && (url.hostname.toLowerCase().replace(/^www\./, "") === expectedHost ||
                            url.hostname.toLowerCase().replace(/^www\./, "").endsWith("." + expectedHost)) &&
                            url.pathname.length > 8 && !/\.(?:jpg|jpeg|png|gif|svg|webp|css|js)$/i.test(url.pathname));
                    let bestUrl = null;
                    let bestScore = 0;
                    for (const candidate of hrefs) {
                        const pathText = decodeURIComponent(candidate.pathname).toLowerCase().replace(/[^a-z0-9]+/g, " ");
                        const score = titleTokens.filter(token => pathText.includes(token)).length;
                        if (score > bestScore) { bestScore = score; bestUrl = candidate.toString(); }
                    }
                    if (bestUrl && bestScore >= 2) {
                        return await extractFullNewsStory(bestUrl, null, articleTitle, false);
                    }
                }
            } catch (_) {}
        }
        const decodeHtml = value => String(value || "")
            .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
            .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
            .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
            .replace(/<[^>]+>/g, " ")
            .replace(/&nbsp;|&#160;/gi, " ")
            .replace(/&amp;/gi, "&").replace(/&quot;/gi, '"')
            .replace(/&#39;|&apos;/gi, "'").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
            .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
            .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
            .replace(/\s+/g, " ").trim();
        const candidates = [];
        const articleBodyMatches = [...html.matchAll(/"articleBody"\s*:\s*"((?:\\.|[^"\\])*)"/gi)];
        for (const match of articleBodyMatches) {
            try { candidates.push(decodeHtml(JSON.parse('"' + match[1] + '"'))); } catch (_) {}
        }
        for (const match of html.matchAll(/<article\b[^>]*>([\s\S]*?)<\/article>/gi)) {
            const text = decodeHtml(match[1]);
            if (text.length > 300) candidates.push(text);
        }
        // Google News can render the publisher story inside its wrapper without
        // an <article> element or articleBody JSON-LD. Use a few meaningful lead
        // paragraphs as a compact in-app detail preview, excluding boilerplate.
        const paragraphs = [...html.matchAll(/<p\b[^>]*>([\s\S]*?)<\/p>/gi)]
            .map(match => decodeHtml(match[1]))
            .filter(text => text.length > 45 &&
                !/^(related news|subscribe|sign up|stay up to date|follow us|privacy policy|terms (and|\&)|cookie policy|copyright)/i.test(text))
            .slice(0, 5);
        const paragraphPreview = paragraphs.join(" ");
        if (paragraphPreview.length > 300) candidates.push(paragraphPreview.slice(0, 2600));
        const ogDescription = (html.match(/<meta\b[^>]*(?:property|name)=["'](?:og:description|description)["'][^>]*content=["']([^"']+)["'][^>]*>/i) || [])[1];
        if (ogDescription) candidates.push(decodeHtml(ogDescription));
        const clean = candidates.sort((a, b) => b.length - a.length)[0];
        if (!clean || clean.length < 350) return null;
        return clean.slice(0, 1200);
    } catch (_) {
        return null;
    }
}

function decodeNewsXml(value) {
    return String(value || "")
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&#39;|&apos;/g, "'")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
        .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
        .trim();
}

function newsXmlTag(block, tag) {
    // RegExp is built from a string, so backslashes must be doubled here.
    // The previous single-slash pattern silently failed to match normal XML tags.
    const match = block.match(new RegExp("<(?:[A-Za-z0-9_.-]+:)?" + tag + "(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[A-Za-z0-9_.-]+:)?" + tag + ">", "i"));
    return match ? decodeNewsXml(match[1]) : "";
}
function footballTeamAliases(team) {
    const normalized = normalizeTeamName(team);
    const aliases = new Set([normalized]);
    const aliasGroups = [
        ["manchester city", "man city", "city"],
        ["manchester united", "man utd", "man united"],
        ["aston villa", "villa"],
        ["tottenham hotspur", "tottenham", "spurs"],
        ["west ham united", "west ham"],
        ["newcastle united", "newcastle"],
        ["nottingham forest", "nottm forest", "forest"],
        ["brighton and hove albion", "brighton"],
        ["wolverhampton wanderers", "wolves", "wolverhampton"],
        ["leicester city", "leicester"],
        ["crystal palace", "palace"],
        ["ipswich town", "ipswich"]
    ];
    for (const group of aliasGroups) {
        if (group.some(alias => normalizeTeamName(alias) === normalized)) {
            group.forEach(alias => aliases.add(normalizeTeamName(alias)));
        }
    }
    return [...aliases].filter(Boolean);
}
function textMentionsFootballTeam(text, team) {
    const normalizedText = normalizeTeamName(text);
    return footballTeamAliases(team).some(alias =>
        alias && (" " + normalizedText + " ").includes(" " + alias + " "));
}

function classifyFootballNews(title, snippet) {
    const text = (String(title || "") + " " + String(snippet || "")).toLowerCase();
    const categories = [];
    if (/injur|injured|injury|fitness|knock|hamstring|ankle|knee|recover|return to train|medical/.test(text)) categories.push("injury");
    if (/suspend|suspension|red card|yellow-card ban|banned for/.test(text)) categories.push("suspension");
    if (/line.?up|starting xi|starting eleven|team news|confirmed xi|confirmed line.?up|squad named|squad announcement/.test(text)) categories.push("lineup");
    if (/manager|coach|press conference|reveals|speaks ahead|comments|manager says|head coach/.test(text)) categories.push("manager_comment");
    if (/training|training ground|training session|pre-match preparation|prepares for|preparing for/.test(text)) categories.push("training");
    if (/transfer|signs for|signing|contract extension|loan deal|transfer window/.test(text)) categories.push("transfer");
    if (/form| unbeaten|winless|last five|last 5|recent results|match report|match reaction|performance/.test(text)) categories.push("form");
    if (/preview|previewing|ahead of|matchday|fixture preview|tactical|opposition analysis/.test(text)) categories.push("match_preview");
    if (/squad|captain|returns to the club|club announcement|official statement|club statement|milestone|academy|youth team/.test(text)) categories.push("squad_update");
    if (/predicted|prediction|could miss|doubt|questionable|expected to/.test(text)) categories.push("unconfirmed_report");
    if (!categories.length) categories.push("general");
    const certainty = /confirmed|official|will miss|ruled out|suspended for|returns to training|back in training/.test(text)
        ? "reported_as_confirmed_check_original_source"
        : /could miss|doubt|questionable|predicted|expected to|fear|may miss|rumou?r/.test(text)
            ? "unconfirmed_or_prediction"
            : "not_established";
    return { categories: [...new Set(categories)], certainty };
}

app.get("/api/match-intelligence/news", async (req, res) => {
    const homeTeam = String(req.query.homeTeam || "").trim().slice(0, 100);
    const awayTeam = String(req.query.awayTeam || "").trim().slice(0, 100);
    if (!homeTeam || !awayTeam) {
        return res.status(400).json({
            error: "homeTeam and awayTeam are required.",
            example: "/api/match-intelligence/news?homeTeam=Arsenal&awayTeam=Chelsea"
        });
    }
    if (homeTeam.length < 2 || awayTeam.length < 2 || homeTeam.toLowerCase() === awayTeam.toLowerCase()) {
        return res.status(400).json({ error: "Provide two different valid team names." });
    }

    const cacheKey = homeTeam.toLowerCase() + "|" + awayTeam.toLowerCase();
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    const forceRefresh = /^(1|true|yes)$/i.test(String(req.query.forceRefresh || ""));
    const cached = footballNewsCache.get(cacheKey);
    if (!forceRefresh && cached && Date.now() < cached.expiresAt) {
        res.set("X-Football-Genie-Cache", "HIT");
        return res.json({
            ...cached.data,
            cache: {
                status: "cached",
                fetchedAt: cached.fetchedAt,
                ageSeconds: Math.max(0, Math.floor((Date.now() - cached.fetchedAtMs) / 1000)),
                ttlSecondsRemaining: Math.max(0, Math.ceil((cached.expiresAt - Date.now()) / 1000)),
                forceRefreshAvailable: true
            }
        });
    }
    res.set("X-Football-Genie-Cache", forceRefresh ? "BYPASS" : "MISS");

    // General Team News: club announcements, manager comments, training/preparation,
    // recent form, match previews, squad developments and availability when reported.
    // Official club sources are preferred; third-party results are filtered for relevance.
    const homeSearchNames = footballTeamAliases(homeTeam).map(name => '"' + name + '"').join(" OR ");
    const awaySearchNames = footballTeamAliases(awayTeam).map(name => '"' + name + '"').join(" OR ");
    const generalNewsTerms = '("team news" OR "club news" OR manager OR coach OR "press conference" OR training OR "match preview" OR form OR squad OR transfer OR "club statement" OR injury OR suspension OR lineup OR "match reaction")';
    const query = '((' + homeSearchNames + ') OR (' + awaySearchNames +
        ')) ' + generalNewsTerms + ' -women -"women\'s" -WSL -ladies';
    const googleUrl = "https://news.google.com/rss/search?" + new URLSearchParams({
        q: query + " when:30d", hl: "en", gl: "GB", ceid: "GB:en"
    }).toString();
    // Use only the selected news sources: Google News search plus established
    // football coverage from BBC Sport, Sky Sports and The Athletic. Providers
    // that repeatedly fail or return unsuitable results are intentionally excluded.
    const homeTeamQuery = '(' + homeSearchNames + ') ' + generalNewsTerms + ' -women -"women\'s" -WSL -ladies';
    const awayTeamQuery = '(' + awaySearchNames + ') ' + generalNewsTerms + ' -women -"women\'s" -WSL -ladies';
    const teamGoogleUrl = teamQuery => "https://news.google.com/rss/search?" + new URLSearchParams({
        q: teamQuery + " when:30d", hl: "en", gl: "GB", ceid: "GB:en"
    }).toString();

    // Official club pages are the preferred absentee source when a supported club
    // can be identified. Google News is used only to discover official-domain pages;
    // the returned item must still be checked at the club's original page.
    const officialClubDomains = [
        {
            aliases: ["aston villa", "aston villa fc"],
            domain: "avfc.co.uk",
            name: "Official Aston Villa website discovery"
        },
        {
            aliases: ["manchester city", "manchester city fc", "man city"],
            domain: "mancity.com/news/mens",
            name: "Official Manchester City website discovery"
        },
        {
            aliases: ["rb leipzig", "rb leipzig fc", "rasenballsport leipzig", "rasenballsport leipzig e.v."],
            domain: "rbleipzig.com",
            name: "Official RB Leipzig website discovery"
        },
        {
            aliases: ["borussia monchengladbach", "borussia mönchengladbach", "borussia m'gladbach", "monchengladbach", "mönchengladbach", "gladbach"],
            domain: "borussia.com",
            name: "Official Borussia Mönchengladbach website discovery"
        },
        {
            aliases: ["arsenal", "arsenal fc", "the arsenal", "the gunners"],
            domain: "arsenal.com/news",
            name: "Official Arsenal website discovery"
        },
        {
            aliases: ["everton", "everton fc", "everton football club", "the toffees"],
            domain: "evertonfc.com/news",
            name: "Official Everton website discovery"
        },
        {
            aliases: ["liverpool","liverpool fc","the reds"],
            domain: "liverpoolfc.com",
            name: "Official Liverpool website discovery"
        },
        {
            aliases: ["chelsea","chelsea fc","the blues"],
            domain: "chelseafc.com",
            name: "Official Chelsea website discovery"
        },
        {
            aliases: ["manchester united","manchester united fc","man utd","man united","the red devils"],
            domain: "manutd.com",
            name: "Official Manchester United website discovery"
        },
        {
            aliases: ["tottenham","tottenham hotspur","tottenham hotspur fc","spurs"],
            domain: "tottenhamhotspur.com",
            name: "Official Tottenham Hotspur website discovery"
        },
        {
            aliases: ["newcastle","newcastle united","newcastle united fc"],
            domain: "newcastleunited.com",
            name: "Official Newcastle United website discovery"
        },
        {
            aliases: ["real madrid","real madrid cf"],
            domain: "realmadrid.com",
            name: "Official Real Madrid website discovery"
        },
        {
            aliases: ["barcelona","fc barcelona","barca","barça"],
            domain: "fcbarcelona.com",
            name: "Official FC Barcelona website discovery"
        },
        {
            aliases: ["atletico madrid","atlético madrid","atletico de madrid"],
            domain: "atleticodemadrid.com",
            name: "Official Atletico Madrid website discovery"
        },
        {
            aliases: ["bayern munich","bayern münchen","fc bayern","bayern"],
            domain: "fcbayern.com",
            name: "Official Bayern Munich website discovery"
        },
        {
            aliases: ["borussia dortmund","dortmund","bvb"],
            domain: "bvb.de",
            name: "Official Borussia Dortmund website discovery"
        },
        {
            aliases: ["paris saint-germain","paris saint germain","psg"],
            domain: "psg.fr",
            name: "Official Paris Saint-Germain website discovery"
        },
        {
            aliases: ["juventus","juventus fc"],
            domain: "juventus.com",
            name: "Official Juventus website discovery"
        },
        {
            aliases: ["inter","inter milan","internazionale","fc internazionale milano"],
            domain: "inter.it",
            name: "Official Inter Milan website discovery"
        },
        {
            aliases: ["ac milan","milan"],
            domain: "acmilan.com",
            name: "Official AC Milan website discovery"
        },
        {
            aliases: ["napoli","ssc napoli"],
            domain: "sscnapoli.it",
            name: "Official Napoli website discovery"
        },
        {
            aliases: ["bayer leverkusen","leverkusen"],
            domain: "bayer04.de",
            name: "Official Bayer Leverkusen website discovery"
        },
        {
            aliases: ["eintracht frankfurt","frankfurt"],
            domain: "eintracht.de",
            name: "Official Eintracht Frankfurt website discovery"
        },
        {
            aliases: ["athletic club","athletic bilbao","athletic club bilbao"],
            domain: "athletic-club.eus",
            name: "Official Athletic Club website discovery"
        },
        {
            aliases: ["real sociedad"],
            domain: "realsociedad.eus",
            name: "Official Real Sociedad website discovery"
        },
        {
            aliases: ["sevilla","sevilla fc"],
            domain: "sevillafc.es",
            name: "Official Sevilla FC website discovery"
        },
        {
            aliases: ["villarreal","villarreal cf"],
            domain: "villarrealcf.es",
            name: "Official Villarreal CF website discovery"
        },
        {
            aliases: ["girona","girona fc"],
            domain: "gironafc.cat",
            name: "Official Girona FC website discovery"
        },
        {
            aliases: ["lazio","ss lazio"],
            domain: "sslazio.it",
            name: "Official Lazio website discovery"
        },
        {
            aliases: ["roma","as roma"],
            domain: "asroma.com",
            name: "Official AS Roma website discovery"
        },
        {
            aliases: ["olympique marseille","marseille"],
            domain: "om.fr",
            name: "Official Olympique Marseille website discovery"
        },
        {
            aliases: ["olympique lyonnais","lyon"],
            domain: "ol.fr",
            name: "Official Olympique Lyonnais website discovery"
        },
        {
            aliases: ["monaco","as monaco"],
            domain: "asmonaco.com",
            name: "Official AS Monaco website discovery"
        },
        {
            aliases: ["benfica","sl benfica"],
            domain: "slbenfica.pt",
            name: "Official Benfica website discovery"
        },
        {
            aliases: ["porto","fc porto"],
            domain: "fcporto.pt",
            name: "Official Porto website discovery"
        },
        {
            aliases: ["sporting cp","sporting lisbon","sporting clube de portugal"],
            domain: "sporting.pt",
            name: "Official Sporting CP website discovery"
        }
    ];
    // Generic official-source discovery is deliberately separate from the small
    // club-domain fast-path above. Search official club domains for both selected
    // teams even when a club is not in the fast-path registry; the absentee route
    // still accepts only verified club-owned article URLs.
    const requestedTeams = [homeTeam, awayTeam];
    const officialProviders = officialClubDomains.flatMap(entry => {
        const team = requestedTeams.find(name =>
            entry.aliases.some(alias => normalizeTeamName(alias) === normalizeTeamName(name)));
        if (!team) return [];
        const query = 'site:' + entry.domain + ' "' + team + '" ("team news" OR "club news" OR manager OR coach OR training OR "match preview" OR squad OR transfer OR "club statement" OR injury OR suspension OR lineup)';
        return [{
            name: entry.name,
            url: teamGoogleUrl(query),
            timeoutMs: 6500,
            searchTeam: team,
            officialPublisherDomain: entry.domain
        }];
    });
    const gdeltQuery = '(' + homeSearchNames + ' OR ' + awaySearchNames + ') (injury OR injured OR "team news" OR unavailable OR "ruled out")';
    const gdeltUrl = "https://api.gdeltproject.org/api/v2/doc/doc?" + new URLSearchParams({
        query: gdeltQuery,
        mode: "ArtList",
        format: "json",
        maxrecords: "10",
        sort: "DateDesc"
    }).toString();
    // Keep Bing's query plain: homeSearchNames/awaySearchNames already contain
    // quoted aliases joined by OR, so wrapping them again creates malformed nested quotes.
    const bingQuery = '"' + homeTeam + '" "' + awayTeam + '" football injury team news';
    const bingHomeQuery = '"' + homeTeam + '" football injury news team news';
    const bingAwayQuery = '"' + awayTeam + '" football injury news team news';
    const bingUrl = query => "https://www.bing.com/news/search?q=" + encodeURIComponent(query) + "&format=rss";
    const officialBingProviders = officialClubDomains.flatMap(entry => {
        const team = requestedTeams.find(name =>
            entry.aliases.some(alias => normalizeTeamName(alias) === normalizeTeamName(name)));
        if (!team) return [];
        const query = 'site:' + entry.domain + ' "' + team + '" ("team news" OR "club news" OR manager OR coach OR training OR "match preview" OR squad OR transfer OR "club statement" OR injury OR suspension OR lineup)';
        return [{
            name: "Bing News RSS - " + entry.name,
            url: bingUrl(query),
            timeoutMs: 6500,
            searchTeam: team,
            officialPublisherDomain: entry.domain
        }];
    });
    // Approved free-first publication sources only: Google News, BBC Sport,
    // Sky Sports and The Athletic. Bing and GDELT were removed from live searches.
    const providers = [
        { name: "Google News RSS - fixture", url: googleUrl, timeoutMs: 6500 },
        { name: "Google News RSS - home team", url: teamGoogleUrl(homeTeamQuery), timeoutMs: 6500, searchTeam: homeTeam },
        { name: "Google News RSS - away team", url: teamGoogleUrl(awayTeamQuery), timeoutMs: 6500, searchTeam: awayTeam },
        ...officialProviders,
        { name: "BBC Sport Football RSS", url: "https://feeds.bbci.co.uk/sport/football/rss.xml", timeoutMs: 6500 },
        { name: "Sky Sports Football RSS", url: "https://www.skysports.com/rss/11095", timeoutMs: 6500 },
        { name: "The Athletic Football RSS", url: "https://www.nytimes.com/athletic/rss/football/", timeoutMs: 6500 }
    ];
    const providerErrors = [];
    const providersAttempted = [];
    let xml = "";
    let providerUsed = "";
    let providerFeedDiagnostics = [];

    // Query providers concurrently so one slow publisher cannot make the entire
    // endpoint exceed the mobile client's timeout. Keep provider order for selection.
    providersAttempted.push(...providers.map(provider => provider.name));
    const providerResults = await Promise.all(providers.map(async provider => {
        try {
            const response = await fetch(provider.url, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (compatible; FootballGenie/1.0; +https://github.com/SaShe3boyz/FootballGenie-API)",
                    "Accept": provider.format === "json" ? "application/json" : "application/rss+xml, application/xml, text/xml"
                },
                signal: AbortSignal.timeout(provider.timeoutMs || 7000)
            });
            const contentType = response.headers.get("content-type") || "";
            if (!response.ok) {
                return { provider: provider.name, error: { provider: provider.name, status: response.status, contentType } };
            }
            const responseBody = await response.text();
            let candidateXml = responseBody;
            if (provider.name.startsWith("Bing News RSS")) {
                // Unwrap Bing's tracking URL to the actual publisher article before parsing.
                candidateXml = candidateXml.replace(/<link>([\s\S]*?)<\/link>/gi, (whole, rawLink) => {
                    const decodedLink = decodeNewsXml(rawLink.trim());
                    try {
                        const parsedLink = new URL(decodedLink);
                        if (parsedLink.hostname.toLowerCase() === "www.bing.com" &&
                            parsedLink.pathname.toLowerCase().includes("apiclick.aspx")) {
                            const destination = parsedLink.searchParams.get("url");
                            if (destination && /^https?:\/\//i.test(destination)) {
                                return "<link>" + destination.replace(/&/g, "&amp;") + "</link>";
                            }
                        }
                    } catch (_) {}
                    return whole;
                });
            }
            if (provider.format === "json") {
                let gdeltData;
                try { gdeltData = JSON.parse(responseBody); }
                catch (_) {
                    return { provider: provider.name, error: { provider: provider.name, error: "unexpected_json_format", contentType } };
                }
                const articles = Array.isArray(gdeltData.articles) ? gdeltData.articles : [];
                if (!articles.length) {
                    return { provider: provider.name, error: { provider: provider.name, error: "no_articles_returned", contentType } };
                }
                const escapeXml = value => String(value || "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
                const itemsXml = articles.map(article => {
                    const rawDate = String(article.seendate || "");
                    const normalizedDate = rawDate.replace(
                        /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$/,
                        "$1-$2-$3T$4:$5:$6Z"
                    );
                    const parsedDate = rawDate ? new Date(normalizedDate) : null;
                    const isoDate = parsedDate && !Number.isNaN(parsedDate.getTime())
                        ? parsedDate.toISOString() : "";
                    return "<item><title>" + escapeXml(article.title) + "</title>" +
                        "<link>" + escapeXml(article.url) + "</link>" +
                        "<pubDate>" + escapeXml(isoDate) + "</pubDate>" +
                        "<source>" + escapeXml(article.domain || "GDELT News Search") + "</source>" +
                        "<description>" + escapeXml(article.title) + "</description></item>";
                }).join("");
                candidateXml = "<rss><channel>" + itemsXml + "</channel></rss>";
            }
            // Bing News may return namespaced <News:News> records instead of RSS <item> elements.
            // Normalize those records into ordinary RSS items before the shared filters run.
            if (provider.name.startsWith("Bing News RSS") && !/<(?:[A-Za-z0-9_.-]+:)?item\b/i.test(candidateXml)) {
                const records = [...candidateXml.matchAll(/<(?:[A-Za-z0-9_.-]+:)?News(?:\s[^>]*)?>([\s\S]*?)<\/(?:[A-Za-z0-9_.-]+:)?News>/gi)];
                const escapeFeedXml = value => String(value || "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
                const readNamespaced = (block, names) => {
                    for (const name of names) {
                        const value = newsXmlTag(block, name);
                        if (value) return value;
                    }
                    return "";
                };
                const normalizedItems = records.map(record => {
                    const block = record[1];
                    const title = readNamespaced(block, ["Title", "title"]);
                    const link = readNamespaced(block, ["Url", "URL", "Link", "link"]);
                    const description = readNamespaced(block, ["Description", "Snippet", "description"]);
                    const source = readNamespaced(block, ["Source", "Provider", "source"]);
                    const rawDate = readNamespaced(block, ["FirstPublished", "Date", "Published", "pubDate"]);
                    const parsedDate = rawDate ? new Date(rawDate) : null;
                    const isoDate = parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate.toISOString() : "";
                    if (!title || !link) return "";
                    return "<item><title>" + escapeFeedXml(title) + "</title><link>" + escapeFeedXml(link) +
                        "</link><pubDate>" + escapeFeedXml(isoDate) + "</pubDate><source>" +
                        escapeFeedXml(source || "Bing News RSS") + "</source><description>" +
                        escapeFeedXml(description || title) + "</description></item>";
                }).filter(Boolean);
                if (normalizedItems.length) candidateXml = "<rss><channel>" + normalizedItems.join("") + "</channel></rss>";
            }
            const hasRssItems = /<(?:[A-Za-z0-9_.-]+:)?item(?:\s[^>]*)?>[\s\S]*?<\/(?:[A-Za-z0-9_.-]+:)?item>/i.test(candidateXml);
            const hasAtomEntries = /<(?:[A-Za-z0-9_.-]+:)?entry(?:\s[^>]*)?>[\s\S]*?<\/(?:[A-Za-z0-9_.-]+:)?entry>/i.test(candidateXml);
            const looksLikeFeed = (/<rss[\s>]/i.test(candidateXml) && hasRssItems) ||
                (/<feed[\s>]/i.test(candidateXml) && hasAtomEntries) || hasRssItems || hasAtomEntries;
            if (!looksLikeFeed) {
                const emptyBingNewsFeed = provider.name.startsWith("Bing News RSS") &&
                    /<rss[\s>]/i.test(candidateXml) && !hasRssItems;
                return {
                    provider: provider.name,
                    error: {
                        provider: provider.name,
                        error: emptyBingNewsFeed ? "no_items_returned" : "unexpected_feed_format",
                        contentType,
                        ...(emptyBingNewsFeed ? {} : { bodyPreview: responseBody.replace(/\s+/g, " ").slice(0, 140) })
                    }
                };
            }
            return { provider: provider.name, xml: candidateXml, searchTeam: provider.searchTeam || null };
        } catch (error) {
            return {
                provider: provider.name,
                error: {
                    provider: provider.name,
                    error: /timeout|abort/i.test(String(error && error.message || "")) ? "timeout" : "unavailable"
                }
            };
        }
    }));
    providerErrors.push(...providerResults.filter(result => result.error).map(result => result.error));
    // Combine successful feeds rather than stopping at the first one. This lets
    // the team/relevance filters find useful reports in independent publications
    // when a search provider returns broad or unrelated headlines.
    const successfulProviders = providerResults.filter(result => result.xml)
        // Parse Bing early so its original publisher links are not pushed beyond
        // the shared candidate cap by 200+ Google News search results.
        .sort((a, b) => (a.provider === "Bing News RSS" ? -1 : 0) - (b.provider === "Bing News RSS" ? -1 : 0));
    providerFeedDiagnostics = providerResults.map(result => ({
        provider: result.provider,
        accepted: !!result.xml,
        itemCount: result.xml ? [...result.xml.matchAll(/<(?:[A-Za-z0-9_.-]+:)?item(?:\s[^>]*)?>[\s\S]*?<\/(?:[A-Za-z0-9_.-]+:)?item>/gi)].length : 0,
        error: result.error ? result.error.error || result.error.status || "provider_error" : null
    }));
    if (successfulProviders.length) {
        const feedItems = successfulProviders.flatMap(result => {
            const matches = [...result.xml.matchAll(/<(?:[A-Za-z0-9_.-]+:)?item(?:\s[^>]*)?>([\s\S]*?)<\/(?:[A-Za-z0-9_.-]+:)?item>/gi)]
                .slice(0, result.provider.startsWith("Bing News RSS") ? 10 : 12);
            return matches.map(match => {
                const source = result.provider.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
                const searchTeamTag = result.searchTeam
                    ? "<searchteam>" + String(result.searchTeam).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") + "</searchteam>"
                    : "";
                const searchProviderTag = "<searchprovider>" + result.provider.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") + "</searchprovider>";
                return "<item>" + match[1] + "<source>" + source + "</source>" + searchTeamTag + searchProviderTag + "</item>";
            });
        });
        if (feedItems.length) {
            xml = "<rss><channel>" + feedItems.join("") + "</channel></rss>";
            providerUsed = successfulProviders.map(result => result.provider).join(" + ");
        } else {
            const selectedProvider = successfulProviders[0];
            xml = selectedProvider.xml;
            providerUsed = selectedProvider.provider;
        }
    }

    // If every live provider is down or rate-limited, serve the last successful
    // result when available, clearly marked stale instead of pretending it is fresh.
    if (!xml) {
        if (cached && cached.data) {
            return res.json({
                ...cached.data,
                status: "stale_news_fallback",
                providersAttempted,
                providerErrors,
                importantNotice: "",
                cache: {
                    status: "stale_fallback",
                    fetchedAt: cached.fetchedAt,
                    ageSeconds: Math.max(0, Math.floor((Date.now() - cached.fetchedAtMs) / 1000)),
                    forceRefreshAvailable: true
                }
            });
        }
        return res.status(502).json({
            status: "news_provider_error",
            error: "Football news search providers are temporarily unavailable or rate-limited. Please try again later.",
            providersAttempted,
            providerErrors,
            providerFeedDiagnostics,
            fallbackAttempted: providersAttempted.length > 1
        });
    }

    const now = Date.now();
    const maxAgeMs = FOOTBALL_NEWS_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
    const feedEntries = [...xml.matchAll(/<(?:[A-Za-z0-9_.-]+:)?item(?:\s[^>]*)?>([\s\S]*?)<\/(?:[A-Za-z0-9_.-]+:)?item>/gi)];
    const atomEntries = feedEntries.length ? [] : [...xml.matchAll(/<(?:[A-Za-z0-9_.-]+:)?entry(?:\s[^>]*)?>([\s\S]*?)<\/(?:[A-Za-z0-9_.-]+:)?entry>/gi)];
    const parsedCandidates = [...(feedEntries.length ? feedEntries : atomEntries)].slice(0, 150).map(match => {
        const block = match[1];
        const title = newsXmlTag(block, "title");
        const atomLink = (block.match(/<link\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*\/?\s*>/i) || [])[1] || "";
        const link = newsXmlTag(block, "link") || decodeNewsXml(atomLink);
        const publishedAt = newsXmlTag(block, "pubDate") || newsXmlTag(block, "published") || newsXmlTag(block, "updated");
        // RSS providers sometimes put the useful excerpt in content:encoded while
        // description contains only the headline and publisher. Choose the richest
        // available feed excerpt instead of always taking the first short field.
        const descriptionCandidates = [
            newsXmlTag(block, "description"),
            newsXmlTag(block, "summary"),
            newsXmlTag(block, "encoded"),
            newsXmlTag(block, "content")
        ].map(value => String(value || "")
            .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
            .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
            .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
            .replace(/<[^>]*>/g, " ")
            .replace(/&nbsp;|&#160;/gi, " ")
            .replace(/&amp;/gi, "&").replace(/&quot;/gi, '"')
            .replace(/&#39;|&apos;/gi, "'").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
            .replace(/\s+/g, " ").trim())
            .filter(Boolean)
            .sort((a, b) => b.length - a.length);
        const description = String(descriptionCandidates[0] || "").slice(0, 1800);
        const searchTeam = newsXmlTag(block, "searchteam");
        const searchProvider = newsXmlTag(block, "searchprovider");
        const sourceTagMatch = block.match(/<(?:[A-Za-z0-9_.-]+:)?source\b([^>]*)>([\s\S]*?)<\/(?:[A-Za-z0-9_.-]+:)?source>/i);
        const publisherSourceUrlMatch = sourceTagMatch && sourceTagMatch[1]
            ? sourceTagMatch[1].match(/\burl\s*=\s*["']([^"']+)["']/i)
            : null;
        const publisherSourceUrl = publisherSourceUrlMatch ? decodeNewsXml(publisherSourceUrlMatch[1]) : null;
        const source = newsXmlTag(block, "source") ||
            newsXmlTag(block, "name") ||
            ((block.match(/<(?:[A-Za-z0-9_-]+:)?Source(?:\s[^>]*)?>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?Source>/i) || [])[1]
                ? decodeNewsXml((block.match(/<(?:[A-Za-z0-9_-]+:)?Source(?:\s[^>]*)?>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?Source>/i) || [])[1])
                : "");
        const parsedDate = publishedAt ? new Date(publishedAt) : null;
        const validDate = parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate : null;
        const ageMs = validDate ? now - validDate.getTime() : null;
        const lowerTitle = title.toLowerCase();
        const contextMarker = /\b(?:vs?\.?|versus|against|ahead of|before|after|following|trip to|clash with|meeting with|showdown with|tie with|game against|match against|game with|match with)\b/i;
        const contextIndex = title.search(contextMarker);
        const headlineSubjectText = (contextIndex >= 0 ? title.slice(0, contextIndex) : title).toLowerCase();
        // Publications often use short club names (e.g. "Man City") or identify
        // the club in the publisher/source field rather than repeating it in the headline.
        const titleMentionsHome = textMentionsFootballTeam(title + " " + source + " " + description, homeTeam);
        const titleMentionsAway = textMentionsFootballTeam(title + " " + source + " " + description, awayTeam);
        const mentionsHome = textMentionsFootballTeam(headlineSubjectText + " " + source, homeTeam);
        const mentionsAway = textMentionsFootballTeam(headlineSubjectText + " " + source, awayTeam);
        const mentionsBothTeams = titleMentionsHome && titleMentionsAway;
        const searchContextMatchesTarget = !!searchTeam && [homeTeam, awayTeam].some(name =>
            normalizeTeamName(name) === normalizeTeamName(searchTeam));
        const hasTargetTeamAsSubject = mentionsHome || mentionsAway || mentionsBothTeams || searchContextMatchesTarget;
        const opponentPattern = /\b(?:vs?\.?|versus|against|ahead of|before|after|following|trip to|clash with|meeting with|showdown with|tie with|game against|match against|game with|match with)\s+([A-Z][A-Za-z.'’&-]*(?:\s+[A-Z][A-Za-z.'’&-]*){0,2})/g;
        const namedOpponents = [...title.matchAll(opponentPattern)].map(match => match[1].trim());
        const targetNames = [homeTeam, awayTeam].map(name => name.toLowerCase());
        const isTargetTeamName = name => targetNames.some(target => target === name.toLowerCase() ||
            target.startsWith(name.toLowerCase()) || name.toLowerCase().startsWith(target));
        const conflictingFixtureOpponent = namedOpponents.some(name => !isTargetTeamName(name));
        const mentionsFixtureOpponent = namedOpponents.length > 0;
        const fixtureRelevance = mentionsBothTeams
            ? "direct_fixture"
            : (conflictingFixtureOpponent ? "other_fixture_excluded_from_analysis"
                : (mentionsFixtureOpponent ? "team_news_other_fixture_or_opponent_context" : "team_background_news"));
        const textForChecks = (title + " " + description + " " + source).toLowerCase();
        const isWomensStory = /\b(women|women's|wsl|ladies|female team|women's super league|women's champions league)\b/i.test(textForChecks);
        const hasSpamSignals = /\b(cathie wood|stock market|share price|cryptocurrency|crypto token|bitcoin|forex|casino|betting tips|odds boost|promo code|affiliate marketing|sponsored content)\b/i.test(textForChecks);
        const hasHeadlineNoise = /\b(click here|read more|live blog|live updates)\b/i.test(lowerTitle) ||
            title.split(/\s+/).length < 4 || /(?:\|\s*){2,}|\.{4,}/.test(title);
        const classification = classifyFootballNews(title, description);
        // Separate the strength of an availability claim from the broad news category.
        // This is a wording-based triage signal, not independent confirmation.
        const reportedDoubtful = /\b(could (?:be )?(?:out|sidelined|miss)|may (?:be )?(?:out|sidelined|miss)|might (?:be )?(?:out|sidelined|miss)|could miss|may miss|might miss|fear .*could|doubtful|a doubt|fitness test|late test|question mark over|being assessed|assess(?:ed|ment)?|hopes to be fit|race to be fit|not certain to play|uncertain to play|questionable|expected to miss|potentially unavailable)\b/i.test(textForChecks);
        const reportedUnavailable = /\b(ruled out|will miss|will not play|won't play|unavailable for|(?:is|has been|will be) sidelined for|out for (?:the )?(?:match|game|fixture|\d+|one|two|three|four|five|six|seven|eight|nine|ten|several)(?:\s+(?:days?|weeks?|months?))?|suspended for|banned for|serving a suspension)\b/i.test(textForChecks);
        // Uncertainty takes precedence: "could be out" is not a confirmed absence.
        const availabilityAssessment = reportedDoubtful
            ? "reported_doubtful_or_test_pending"
            : reportedUnavailable
                ? "reported_unavailable_check_original_source"
                : "availability_not_established";
        const availabilityScope = mentionsBothTeams
            ? "both_teams_named_in_headline_not_fixture_verified"
            : "single_team_background_not_fixture_verified";
        const availabilityGuidance = (reportedDoubtful
            ? "The article suggests doubt or a pending fitness assessment; do not treat the player as confirmed absent."
            : reportedUnavailable
                ? "The article uses wording that reports unavailability; verify the player, match, date, and original source."
                : "This article does not establish whether a player is available or absent.") +
            (mentionsBothTeams
                ? " Both teams appear in the headline, but the exact fixture and player status still need verification."
                : " This is team-background news, not confirmation of availability for the requested fixture.");
        // A manager quote is useful only when it discusses player availability,
        // fitness, selection, or suspension. Generic post-match comments must not
        // be presented as absentee evidence just because a team name appears.
        const managerAvailabilityContext = /\b(available|unavailable|fit|fitness|miss|missing|return|returning|doubt|doubtful|assess|assessment|train|training|squad|selection|ruled out|late test|match fitness|ban|suspend|suspension)\b/i.test(textForChecks);
        const hasRelevantAvailabilitySignal =
            classification.categories.some(category => ["injury", "suspension", "lineup", "manager_comment", "training", "transfer", "form", "match_preview", "squad_update"].includes(category));
        let relevanceScore = (mentionsHome ? 2 : 0) + (mentionsAway ? 2 : 0);
        if (searchContextMatchesTarget) relevanceScore += 2;
        if (mentionsBothTeams) relevanceScore += 4;
        if (mentionsFixtureOpponent && !mentionsBothTeams) relevanceScore -= 2;
        if (conflictingFixtureOpponent && !mentionsBothTeams) relevanceScore -= 8;
        if (classification.categories.some(category => ["injury", "suspension", "lineup", "manager_comment"].includes(category))) relevanceScore += 2;
        if (classification.categories.includes("unconfirmed_report")) relevanceScore += 1;
        if (/official|confirmed|press conference|team news|club news|injury update|suspended|training|match preview|squad|manager|coach|transfer|club statement/.test(lowerTitle)) relevanceScore += 1;
        if (isWomensStory) relevanceScore -= 5;
        return {
            title: title.slice(0, 300),
            source: source.slice(0, 120) || "Source not identified",
            searchTeam: searchTeam || null,
            searchProvider: searchProvider || null,
            publishedAt: validDate ? validDate.toISOString() : null,
            ageDays: ageMs === null ? null : Math.floor(ageMs / (24 * 60 * 60 * 1000)),
            freshness: ageMs === null ? "date_unknown" : ageMs < 0 ? "future_date_check" : ageMs <= maxAgeMs ? "fresh_7d" : "stale",
            snippet: description,
            url: /^https?:\/\//i.test(link) ? link : null,
            publisherSourceUrl: /^https?:\/\//i.test(publisherSourceUrl || "") ? publisherSourceUrl : null,
            categories: classification.categories,
            certainty: classification.certainty,
            availabilityAssessment,
            availabilityGuidance,
            availabilityScope,
            hasRelevantAvailabilitySignal,
            hasTargetTeamAsSubject,
            fixtureRelevance,
            relevanceScore,
            isWomensStory,
            hasSpamSignals,
            hasHeadlineNoise
        };
    });
    const filterDiagnostics = {
        parsedCandidates: parsedCandidates.length,
        missingTitleOrUrl: 0,
        womenStories: 0,
        spamSignals: 0,
        headlineNoise: 0,
        missingOrInvalidDate: 0,
        futureDates: 0,
        staleDates: 0,
        lowRelevance: 0,
        conflictingOpponent: 0,
        noTargetTeamInTitle: 0,
        noRelevantNewsCategory: 0
    };
    const isDirectOfficialClubUrlForDiscovery = value => {
        try {
            const host = new URL(value || "").hostname.toLowerCase();
            return ["arsenal.com", "evertonfc.com", "mancity.com", "avfc.co.uk", "rbleipzig.com", "borussia.com", "liverpoolfc.com", "chelseafc.com", "manutd.com", "tottenhamhotspur.com", "newcastleunited.com", "realmadrid.com", "fcbarcelona.com", "atleticodemadrid.com", "fcbayern.com", "bvb.de", "psg.fr", "juventus.com", "inter.it", "acmilan.com", "sscnapoli.it", "bayer04.de", "eintracht.de", "athletic-club.eus", "realsociedad.eus", "sevillafc.es", "villarrealcf.es", "gironafc.cat", "sslazio.it", "asroma.com", "om.fr", "ol.fr", "asmonaco.com", "slbenfica.pt", "fcporto.pt", "sporting.pt"]
                .some(domain => host === domain || host.endsWith("." + domain));
        } catch (_) { return false; }
    };
    let parsedItems = parsedCandidates.filter(item => {
        if (!item.title || !item.url) { filterDiagnostics.missingTitleOrUrl++; return false; }
        if (item.isWomensStory) { filterDiagnostics.womenStories++; return false; }
        if (item.hasSpamSignals) { filterDiagnostics.spamSignals++; return false; }
        if (item.hasHeadlineNoise) { filterDiagnostics.headlineNoise++; return false; }
        if (item.publishedAt === null || item.ageDays === null) { filterDiagnostics.missingOrInvalidDate++; return false; }
        const publishedTimestamp = Date.parse(item.publishedAt);
        if (!Number.isFinite(publishedTimestamp) || publishedTimestamp > now) {
            filterDiagnostics.futureDates++;
            return false;
        }
        if (now - publishedTimestamp > maxAgeMs) { filterDiagnostics.staleDates++; return false; }
        if (item.fixtureRelevance === "other_fixture_excluded_from_analysis") { filterDiagnostics.conflictingOpponent++; return false; }
        // A lineup report for a different match must never leak into this fixture's
        // Team News just because one selected club is mentioned in the headline.
        if (item.categories.includes("lineup") && item.fixtureRelevance !== "direct_fixture") {
            filterDiagnostics.conflictingOpponent++;
            return false;
        }
        // Direct official-club results from a team-specific official-site search are
        // valuable even when the headline says only "injury update" and does not
        // repeat the club name or an explicit OUT/DOUBTFUL label. Keep them so the
        // absentee route can open the original page and inspect its actual text.
        const officialAvailabilityLanguage = /\b(injury|injured|injuries|fitness|team news|club news|availability|unavailable|suspension|suspended|ruled out|doubtful|returns? to training|back in training|manager|coach|training|match preview|squad|transfer|club statement|press conference|form|match reaction)\b/i
            .test(item.title);
        const directOfficialTeamResult = isDirectOfficialClubUrlForDiscovery(item.url) &&
            item.searchTeam && [homeTeam, awayTeam].some(name =>
                normalizeTeamName(name) === normalizeTeamName(item.searchTeam)) &&
            (item.hasRelevantAvailabilitySignal || officialAvailabilityLanguage);
        if (directOfficialTeamResult) return true;
        if (item.relevanceScore < 3) { filterDiagnostics.lowRelevance++; return false; }
        if (!item.hasTargetTeamAsSubject) { filterDiagnostics.noTargetTeamInTitle++; return false; }
        if (!item.hasRelevantAvailabilitySignal) { filterDiagnostics.noRelevantNewsCategory++; return false; }
        return true;
    });
    filterDiagnostics.accepted = parsedItems.length;

    // Bing often supplies original publisher URLs for headlines Google News returns
    // as opaque aggregator links. Match only close title pairs; resolving a URL does
    // not independently verify the article's availability claim.
    const normalizeHeadlineForLinkMatch = value => String(value || "").toLowerCase()
        .replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/).filter(token => token.length > 2);
    const bingPublisherCandidates = parsedItems.filter(item => {
        if (!item.searchProvider || !item.searchProvider.startsWith("Bing News RSS") || !item.url) return false;
        try {
            const host = new URL(item.url).hostname.toLowerCase();
            return host !== "bing.com" && !host.endsWith(".bing.com") &&
                host !== "news.google.com" && !host.endsWith(".news.google.com");
        } catch (_) { return false; }
    });
    let bingPublisherLinksMatched = 0;
    parsedItems = parsedItems.map(item => {
        if (!item.url || !/^(?:https?:\/\/)?(?:www\.)?news\.google\.com\//i.test(item.url)) return item;
        const itemTokens = new Set(normalizeHeadlineForLinkMatch(item.title));
        if (!itemTokens.size) return item;
        let best = null, bestScore = 0;
        for (const candidate of bingPublisherCandidates) {
            const candidateTokens = new Set(normalizeHeadlineForLinkMatch(candidate.title));
            if (!candidateTokens.size) continue;
            let overlap = 0;
            for (const token of itemTokens) if (candidateTokens.has(token)) overlap++;
            const score = overlap / Math.max(itemTokens.size, candidateTokens.size);
            if (score > bestScore) { bestScore = score; best = candidate; }
        }
        if (!best || bestScore < 0.72) return item;
        bingPublisherLinksMatched++;
        return { ...item, url: best.url, originalPublisherUrlResolved: true,
            publisherUrlResolutionMethod: "matched_bing_news_headline",
            publisherUrlResolutionScore: Number(bestScore.toFixed(2)) };
    });
    // Official club domains are primary; this is publisher priority, not proof of player status.
    const isOfficialClubUrl = value => {
        try {
            const host = new URL(value || "").hostname.toLowerCase();
            const officialDomains = [
                "arsenal.com", "evertonfc.com", "mancity.com", "avfc.co.uk",
                "rbleipzig.com", "borussia.com", "liverpoolfc.com", "chelseafc.com",
                "manutd.com", "tottenhamhotspur.com", "newcastleunited.com",
                "realmadrid.com", "fcbarcelona.com", "atleticodemadrid.com",
                "fcbayern.com", "bvb.de", "psg.fr", "juventus.com", "inter.it",
                "acmilan.com", "sscnapoli.it", "bayer04.de", "eintracht.de",
                "athletic-club.eus", "realsociedad.eus", "sevillafc.es",
                "villarrealcf.es", "gironafc.cat", "sslazio.it", "asroma.com",
                "om.fr", "ol.fr", "asmonaco.com", "slbenfica.pt", "fcporto.pt",
                "sporting.pt", "sufc.co.uk", "dcfc.co.uk", "fc-koeln.de",
                "schalke04.de"
            ];
            return officialDomains.some(domain => host === domain || host.endsWith("." + domain));
        } catch (_) { return false; }
    };
    const isReputableFallbackPublisherUrl = value => {
        try {
            const host = new URL(value).hostname.toLowerCase().replace(/^www\./, "");
            return ["bbc.co.uk", "bbc.com", "skysports.com", "theathletic.com"]
                .some(domain => host === domain || host.endsWith("." + domain));
        } catch (_) { return false; }
    };
    parsedItems = parsedItems.map(item => {
        const officialClubSource = isOfficialClubUrl(item.url) || isOfficialClubUrl(item.publisherSourceUrl);
        const reputableFallbackSource = !officialClubSource &&
            (isReputableFallbackPublisherUrl(item.url) || isReputableFallbackPublisherUrl(item.publisherSourceUrl));
        return {
            ...item,
            // Official clubs remain the primary source. Only a small allowlist of
            // established football publishers can be used as provisional fallback.
            officialClubSource,
            sourceTrustTier: officialClubSource ? "official_club_website"
                : reputableFallbackSource ? "reputable_secondary_publication" : "unverified_publication"
        };
    });
    // Official club websites are ranked first. Reputable secondary publishers remain
    // fallback context, not official confirmation; relevance and freshness break ties.
    parsedItems.sort((a, b) =>
        Number(b.officialClubSource) - Number(a.officialClubSource) ||
        b.relevanceScore - a.relevanceScore ||
        ((a.ageDays === null ? 9999 : a.ageDays) - (b.ageDays === null ? 9999 : a.ageDays)));
    // Combine the two club-specific searches but remove duplicate headlines.
    // Keep a wider evidence pool so a single-team injury report is not crowded
    // out by repeated fixture previews before absentee extraction runs.
    const uniqueParsedItems = [];
    const seenNewsItems = new Set();
    const seenHeadlineTokens = [];
    const normalizeNewsHeadline = value => String(value || "").toLowerCase()
        .replace(/&amp;/g, "and").replace(/[^a-z0-9]+/g, " ")
        .replace(/\b(sheffield united|derby county|football club|fc|afc|preview|latest|update|news)\b/g, " ")
        .trim().split(/\s+/).filter(token => token.length > 2);
    for (const item of parsedItems) {
        const dedupeKey = String(item.url || "").toLowerCase().replace(/[?#].*$/, "");
        const tokens = [...new Set(normalizeNewsHeadline(item.title))];
        const nearDuplicate = tokens.length > 0 && seenHeadlineTokens.some(previous => {
            const overlap = tokens.filter(token => previous.includes(token)).length;
            // Syndicated injury stories often add/remove a few words or append
            // a publisher name. Use a slightly more tolerant overlap threshold.
            return overlap / Math.max(tokens.length, previous.length) >= 0.70;
        });
        if ((dedupeKey && seenNewsItems.has(dedupeKey)) || nearDuplicate) continue;
        if (dedupeKey) seenNewsItems.add(dedupeKey);
        if (tokens.length) seenHeadlineTokens.push(tokens);
        uniqueParsedItems.push(item);
    }
    let items = uniqueParsedItems.slice(0, 30).map(({ relevanceScore, isWomensStory, hasSpamSignals, hasHeadlineNoise, hasRelevantAvailabilitySignal, hasTargetTeamAsSubject, ...item }) => item);
    // Fetch full text from a small number of publicly accessible publisher pages.
    // If a site blocks extraction or only exposes a snippet, preserve that snippet.
    let fullStoryFetches = 0;
    items = await Promise.all(items.map(async article => {
        if (fullStoryFetches >= FOOTBALL_NEWS_MAX_ARTICLE_FETCHES || !article.url) return article;
        fullStoryFetches++;
        const story = await extractFullNewsStory(article.url, article.publisherSourceUrl, article.title);
        return story ? { ...article, snippet: story, fullStoryExtracted: true } :
            { ...article, fullStoryExtracted: false };
    }));
    const fetchedAtMs = Date.now();
    const fixtureSpecificCount = items.filter(item => item.fixtureRelevance === "direct_fixture").length;
    const teamBackgroundCount = items.filter(item => item.fixtureRelevance !== "direct_fixture").length;
    const result = {
        status: items.length ? "news_found" : "no_recent_relevant_articles",
        fixtureSpecificCount,
        teamBackgroundCount,
        hasFixtureSpecificEvidence: fixtureSpecificCount > 0,
        matchImpactWarning: fixtureSpecificCount > 0
            ? "At least one headline names both teams, but verify the original report and player status before changing a prediction."
            : "No fixture-specific availability evidence was found. Returned articles are team-background leads only and must not be treated as confirmed absentees for this match.",
        source: providerUsed,
        providersAttempted,
        providerErrors,
        providerFeedDiagnostics,
        teams: { home: homeTeam, away: awayTeam },
        searchedAt: new Date(fetchedAtMs).toISOString(),
        cache: {
            status: "fresh",
            fetchedAt: new Date(fetchedAtMs).toISOString(),
            ttlSeconds: Math.floor(FOOTBALL_NEWS_CACHE_TTL_MS / 1000),
            forceRefreshAvailable: true
        },
        maxArticleAgeDays: FOOTBALL_NEWS_MAX_AGE_DAYS,
        filterDiagnostics,
        publisherLinkResolutionDiagnostics: {
            bingPublisherCandidateCount: bingPublisherCandidates.length,
            googleNewsLinksMatchedToBingPublisher: bingPublisherLinksMatched
        },
        count: items.length,
        articles: items.map(article => {
            const detailText = String(article.snippet || "").trim()
                .replace(/&nbsp;|&#160;/gi, " ").replace(/&amp;/gi, "&")
                .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
                .replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
            const normalizedTitle = String(article.title || "")
                .replace(/&nbsp;|&#160;/gi, " ").replace(/&amp;/gi, "&")
                .replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
            const detailBeyondHeadline = detailText.toLowerCase()
                .replace(normalizedTitle.toLowerCase(), " ")
                .replace(String(article.source || "").toLowerCase(), " ")
                .replace(/^(?:[-–—|:;,.\s])+/, "")
                .replace(/\s+/g, " ").trim();
            const headlineOnly = !detailText || detailBeyondHeadline.length < 35;
            return {
                ...article,
                fullInformation: [article.title, detailText].filter(Boolean).join("\n\n"),
                articleDetails: headlineOnly
                    ? "The news feed did not provide enough article text for a reliable detailed summary. Football Genie will not invent missing details."
                    : detailText,
                detailAvailability: article.fullStoryExtracted ? "article_text_extracted"
                    : headlineOnly ? "headline_or_short_excerpt_only" : "publisher_excerpt_available",
                brandSignature: "FOOTBALLGENIE",
                sourceLabel: "FOOTBALL GENIE",
                informationOnly: true
            };
        }),
        brandSignature: "FOOTBALLGENIE",
        importantNotice: ""
    };
    footballNewsCache.set(cacheKey, {
        expiresAt: fetchedAtMs + FOOTBALL_NEWS_CACHE_TTL_MS,
        fetchedAtMs,
        fetchedAt: result.cache.fetchedAt,
        data: result
    });
    if (/^(1|true|yes)$/i.test(String(req.query.internal || ""))) return res.json(result);
    // Football Genie is the user-facing source; publisher URLs stay server-side.
    return res.json({
        ...result,
        articles: result.articles.map(article => {
            let publisherLabel = "Publisher not verified";
            const feedPublisher = String(article.source || "").trim();
            // Prefer the publisher name supplied by the news feed; aggregator URLs
            // (such as MSN) are not necessarily the original publisher.
            if (feedPublisher && !/^(Google News RSS|Bing News RSS|GDELT News Search|BBC Sport Football RSS|Sky Sports Football RSS|The Athletic Football RSS)/i.test(feedPublisher)) {
                publisherLabel = feedPublisher.replace(/\s+on MSN$/i, "").trim();
            } else {
                try {
                    const host = new URL(article.url || article.publisherSourceUrl || "").hostname.toLowerCase().replace(/^www\\./, "");
                    if (host && host !== "news.google.com" && !host.endsWith(".news.google.com") &&
                        host !== "bing.com" && !host.endsWith(".bing.com") && host !== "msn.com" && !host.endsWith(".msn.com")) {
                        const publisherNames = {
                            "bbc.co.uk": "BBC Sport", "bbc.com": "BBC Sport",
                            "skysports.com": "Sky Sports", "theathletic.com": "The Athletic",
                            "derbyshirelive.co.uk": "Derbyshire Live", "thestar.co.uk": "The Star",
                            "thestaceywest.com": "The Stacey West", "dcfc.co.uk": "Derby County (official)",
                            "sufc.co.uk": "Sheffield United (official)"
                        };
                        const knownDomain = Object.keys(publisherNames).find(domain => host === domain || host.endsWith("." + domain));
                        if (knownDomain) publisherLabel = publisherNames[knownDomain];
                    }
                } catch (_) {}
            }
            return {
                ...article,
                url: null,
                brandSignature: "FOOTBALLGENIE",
                sourceLabel: "FOOTBALL GENIE",
                publisherLabel,
                sourceLinkHidden: true
            };
        }),
        importantNotice: ""
    });
});

// Use the configured primary AI provider with the same OpenAI fallback as the main AI chat.
async function requestAbsenteeAIAnswer(systemInstruction, userContent) {
    // If Gemini is configured, use it exclusively for absentee extraction.
    // A Gemini failure must not silently switch this task to Groq or OpenAI.
    if (process.env.GEMINI_API_KEY) {
        const model = process.env.GEMINI_MODEL || "gemini-3.8-flash";
        const endpoint = "https://generativelanguage.googleapis.com/v1beta/models/" +
            encodeURIComponent(model) + ":generateContent?key=" +
            encodeURIComponent(process.env.GEMINI_API_KEY);
        const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                systemInstruction: { parts: [{ text: systemInstruction }] },
                contents: [{ role: "user", parts: [{ text: userContent }] }],
                generationConfig: { temperature: 0.1, maxOutputTokens: 1400,
                    responseMimeType: "application/json" }
            }),
            signal: AbortSignal.timeout(25000)
        });
        const bodyText = await response.text();
        let data;
        try { data = JSON.parse(bodyText); }
        catch (_) { throw new Error("Gemini absentee extraction returned unreadable data."); }
        if (!response.ok) {
            const providerMessage = data && data.error && data.error.message
                ? String(data.error.message) : "";
            const error = new Error("Gemini absentee extraction HTTP " + response.status +
                (providerMessage ? ": " + providerMessage.slice(0, 180) : "."));
            error.status = response.status;
            // Keep only non-secret quota diagnostics; never expose request URLs or API keys.
            const retryHeader = response.headers && response.headers.get
                ? response.headers.get("retry-after") : null;
            const retryAfterSeconds = retryHeader && Number.isFinite(Number(retryHeader))
                ? Number(retryHeader) : null;
            error.providerDetails = {
                message: providerMessage.slice(0, 240),
                retryAfterSeconds
            };
            throw error;
        }
        const answer = data.candidates && data.candidates[0] &&
            data.candidates[0].content && Array.isArray(data.candidates[0].content.parts)
            ? data.candidates[0].content.parts.map(part => String(part.text || "")).join("").trim()
            : "";
        if (!answer) throw new Error("Gemini returned an empty absentee extraction.");
        return { answer, model, provider: "gemini" };
    }
    let groqFailure = null;
    if (process.env.GROQ_API_KEY) {
        try {
            const result = await requestGroqAnswer(systemInstruction, userContent, {
                maxTokens: 1400, timeoutMs: 25000, maxAttempts: 1
            });
            return { ...result, provider: "groq" };
        } catch (error) {
            groqFailure = error;
            console.warn("Absentee extraction Groq attempt failed; checking OpenAI fallback:",
                String(error.message || error).slice(0, 160));
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
                temperature: 0.1,
                max_tokens: 1400,
                messages: [
                    { role: "system", content: systemInstruction },
                    { role: "user", content: userContent }
                ]
            }),
            signal: AbortSignal.timeout(22000)
        });
        const bodyText = await response.text();
        let data;
        try { data = JSON.parse(bodyText); }
        catch (_) { throw new Error("OpenAI absentee extraction returned unreadable data."); }
        if (!response.ok) {
            throw new Error("OpenAI absentee extraction HTTP " + response.status + ".");
        }
        const answer = data.choices && data.choices[0] && data.choices[0].message
            ? String(data.choices[0].message.content || "").trim() : "";
        if (!answer) throw new Error("OpenAI returned an empty absentee extraction.");
        return { answer, model, provider: "openai" };
    }
    if (groqFailure) throw groqFailure;
    throw new Error("No AI provider is configured for absentee extraction.");
}

// Publication age is a freshness hint, never proof of current availability.
function assessAbsenteePublicationFreshness(publishedAt) {
    if (!publishedAt) return {
        freshnessStatus: "publication_date_unknown",
        freshnessInterpretation: "date_unknown_do_not_assume_current",
        ageHours: null,
        currentAvailabilityVerified: false
    };
    const timestamp = new Date(publishedAt).getTime();
    if (!Number.isFinite(timestamp)) return {
        freshnessStatus: "publication_date_unknown",
        freshnessInterpretation: "date_unknown_do_not_assume_current",
        ageHours: null,
        currentAvailabilityVerified: false
    };
    const ageHours = Math.max(0, Math.round((Date.now() - timestamp) / 3600000));
    const freshnessStatus = ageHours <= 24 ? "published_within_24h"
        : ageHours <= 72 ? "published_within_72h" : "older_than_72h";
    return {
        freshnessStatus,
        freshnessInterpretation: ageHours <= 24
            ? "recent_publication_still_unverified"
            : ageHours <= 72
                ? "check_original_source_before_treating_as_current"
                : "historical_report_check_current_source",
        ageHours,
        currentAvailabilityVerified: false
    };
}

// BIG BALLS Data is the primary structured source for football absences.
const BIGBALLS_FOOTBALL_LEAGUES = {
    epl: "epl", "premier league": "epl", premierleague: "epl", england: "epl",
    laliga: "laliga", "la liga": "laliga", spain: "laliga",
    seriea: "seriea", "serie a": "seriea", italy: "seriea",
    bundesliga: "bundesliga", germany: "bundesliga",
    ligue1: "ligue1", "ligue 1": "ligue1", france: "ligue1",
    ucl: "ucl", "champions league": "ucl", "uefa champions league": "ucl",
    mls: "mls", "major league soccer": "mls"
};
const BIGBALLS_TEAM_LEAGUES = [
    { league: "epl", teams: ["arsenal","aston villa","bournemouth","brentford","brighton","burnley","chelsea","crystal palace","everton","fulham","leeds united","liverpool","manchester city","man city","manchester united","man united","newcastle united","nottingham forest","sunderland","tottenham","west ham","wolverhampton wanderers","wolves"] },
    { league: "laliga", teams: ["real madrid","barcelona","atletico madrid","atlético madrid","athletic club","real sociedad","villarreal","valencia","sevilla","real betis","girona","getafe","osasuna","mallorca","celta vigo","espanyol","elche","levante","alaves","deportivo alaves","rayo vallecano"] },
    { league: "seriea", teams: ["inter","inter milan","ac milan","milan","juventus","napoli","roma","lazio","atalanta","fiorentina","bologna","torino","udinese","genoa","parma","cagliari","lecce","sassuolo","como","pisa","cremonese"] },
    { league: "bundesliga", teams: ["bayern munich","borussia dortmund","rb leipzig","bayer leverkusen","eintracht frankfurt","stuttgart","freiburg","werder bremen","mainz","hoffenheim","wolfsburg","augsburg","union berlin","borussia monchengladbach","hamburger sv","koln","heidenheim","st pauli"] },
    { league: "ligue1", teams: ["paris saint-germain","paris saint germain","psg","marseille","monaco","lyon","lille","nice","lens","rennes","strasbourg","toulouse","nantes","montpellier","reims","auxerre","angers","le havre","lorient","metz","brest"] },
    { league: "mls", teams: ["inter miami","la galaxy","los angeles fc","lafc","new york city","new york red bulls","atlanta united","seattle sounders","portland timbers","columbus crew","fc cincinnati","orlando city","austin fc","dallas","houston dynamo","san diego fc"] }
];
function inferBigBallsLeague(homeTeam, awayTeam, competition) {
    const supplied = String(competition || "").toLowerCase().trim();
    const compact = supplied.replace(/[^a-z0-9]/g, "");
    if (BIGBALLS_FOOTBALL_LEAGUES[supplied]) return BIGBALLS_FOOTBALL_LEAGUES[supplied];
    if (BIGBALLS_FOOTBALL_LEAGUES[compact]) return BIGBALLS_FOOTBALL_LEAGUES[compact];

    // Fixture APIs often include season labels or prefixes such as "League:
    // Premier League 2026/27". Match the actual competition name in that text.
    const competitionAliases = [
        { league: "epl", keys: ["premierleague", "englishpremierleague", "epl"] },
        { league: "laliga", keys: ["laliga", "spanishprimera", "primera division"] },
        { league: "seriea", keys: ["seriea", "italianseriea"] },
        { league: "bundesliga", keys: ["bundesliga", "germanbundesliga"] },
        { league: "ligue1", keys: ["ligue1", "frenchligue1"] },
        { league: "ucl", keys: ["uefachampionsleague", "championsleague", "ucl"] },
        { league: "mls", keys: ["majorleaguesoccer", "mls"] }
    ];
    for (const alias of competitionAliases) {
        if (alias.keys.some(key => compact.includes(key.replace(/[^a-z0-9]/g, "")))) return alias.league;
    }

    // Last resort: identify the league from known club names only when the
    // supplied competition is blank or not recognised.
    for (const group of BIGBALLS_TEAM_LEAGUES) {
        if ([homeTeam, awayTeam].some(team => group.teams.some(name => {
            const normalizedTeam = normalizeTeamName(team);
            const normalizedKnown = normalizeTeamName(name);
            return normalizedTeam === normalizedKnown ||
                normalizedTeam.includes(normalizedKnown) ||
                normalizedKnown.includes(normalizedTeam);
        }))) return group.league;
    }
    return null;
}
function extractBigBallsRows(payload) {
    if (Array.isArray(payload)) return payload;
    if (!payload || typeof payload !== "object") return [];
    for (const key of ["data", "injuries", "absences", "results", "items", "records"]) {
        const value = payload[key];
        if (Array.isArray(value)) return value;
        if (value && typeof value === "object") {
            for (const nestedKey of ["data", "injuries", "absences", "results", "items", "records"]) {
                if (Array.isArray(value[nestedKey])) return value[nestedKey];
            }
        }
    }
    return [];
}
function bigBallsText(...values) {
    for (const value of values) {
        if (typeof value === "string" && value.trim()) return value.trim();
        if (value && typeof value === "object" && typeof value.name === "string" && value.name.trim()) return value.name.trim();
    }
    return "";
}
async function fetchBigBallsFootballAbsences(homeTeam, awayTeam, competition) {
    const apiKey = process.env.BIGBALLSDATA_API_KEY || process.env.BIG_BALLS_DATA_API_KEY;
    if (!apiKey) {
        const error = new Error("BIGBALLSDATA_API_KEY is not configured.");
        error.code = "bigballs_key_missing";
        throw error;
    }
    const league = inferBigBallsLeague(homeTeam, awayTeam, competition);
    if (!league) {
        const error = new Error("The fixture league could not be determined. Supply the competition parameter.");
        error.code = "bigballs_league_unknown";
        throw error;
    }

    // BIG BALLS soccer absence data is league-scoped. Its official league
    // examples use /v1/injuries?league=<slug>; requesting only sport=football
    // can return an empty dataset. Fetch the selected league explicitly, then
    // filter by the two selected team names locally to handle canonical aliases.
    const url = new URL("https://api.bigballsdata.com/v1/injuries");
    // The provider's OpenAPI contract requires the sport selector; league pages
    // document the league selector. Send both so we scope the soccer feed to the
    // requested competition rather than relying on provider defaults.
    url.searchParams.set("sport", "football");
    url.searchParams.set("league", league);
    const response = await fetch(url.href, {
        headers: { "Authorization": "Bearer " + apiKey, "Accept": "application/json" },
        signal: AbortSignal.timeout(12000)
    });
    const textBody = await response.text();
    let payload;
    try { payload = JSON.parse(textBody); }
    catch (_) {
        const error = new Error("BIG BALLS Data returned an unreadable response.");
        error.code = "bigballs_invalid_json";
        error.status = response.status;
        throw error;
    }
    if (!response.ok || (payload && payload.error)) {
        const providerMessage = payload && payload.error &&
            (payload.error.message || payload.error) || payload && payload.message || "Provider request failed.";
        const error = new Error("BIG BALLS Data HTTP " + response.status + ": " + String(providerMessage).slice(0, 180));
        error.status = response.status;
        error.code = "bigballs_provider_error";
        throw error;
    }

    const allRows = extractBigBallsRows(payload);
    const wantedTeams = [homeTeam, awayTeam].map(normalizeTeamName);
    const reports = allRows.map(row => {
        const player = row.player || row.athlete || {};
        const team = row.team || player.team || row.club || {};
        const teamName = bigBallsText(row.team_name, row.teamName,
            typeof team === "string" ? team : team.name, row.club_name, row.squad_name);
        const playerName = bigBallsText(row.player_name, row.playerName, row.name, player.name, row.full_name);
        const reason = bigBallsText(row.reason, row.injury, row.injury_type, row.absence_reason, row.description, row.comment);
        const fixture = row.fixture || row.match || row.game || {};
        const fixtureDate = bigBallsText(row.fixture_date, row.match_date, row.date, fixture.date, fixture.kickoff_utc, fixture.kickoff);
        const fixtureName = bigBallsText(row.fixture_name, row.match_name, fixture.name, fixture.label);
        const status = bigBallsText(row.status, row.availability, row.designation);
        return {
            row, playerName, teamName, reason, fixtureDate, fixtureName, status,
            playerId: row.player_id || row.playerId || player.id || null
        };
    }).filter(item => {
        if (!item.teamName) return false;
        const normalized = normalizeTeamName(item.teamName);
        return wantedTeams.some(wanted =>
            normalized === wanted || normalized.includes(wanted) || wanted.includes(normalized));
    });

    const meta = payload.meta || payload.metadata || {};
    const dataEnvelope = payload.data && typeof payload.data === "object" && !Array.isArray(payload.data)
        ? payload.data : {};
    // Safe provider diagnostics: expose response shape and coverage metadata, never
    // credentials or raw player records. This helps distinguish empty provider data
    // from an extraction/schema problem while keeping Team News provider-only.
    const diagnostics = {
        httpStatus: response.status,
        topLevelKeys: Object.keys(payload),
        dataType: Array.isArray(payload.data) ? "array" : typeof payload.data,
        dataKeys: Object.keys(dataEnvelope),
        dataCount: Number.isFinite(dataEnvelope.count) ? dataEnvelope.count : null,
        injuriesArrayLength: Array.isArray(dataEnvelope.injuries) ? dataEnvelope.injuries.length : null,
        metaKeys: Object.keys(meta),
        metaNote: bigBallsText(meta.note, meta.message, meta.coverage && meta.coverage.note),
        ignoredParams: Array.isArray(meta.ignored_params) ? meta.ignored_params : null
    };
    return {
        league,
        rows: reports,
        meta,
        diagnostics,
        fetchedAt: new Date().toISOString(),
        totalProviderRows: allRows.length
    };
}

// Structured absentee-report endpoint. Publication headlines are leads, not official confirmation.
const absenteeReportCache = new Map();
const ABSENTEE_REPORT_CACHE_TTL_MS = 10 * 60 * 1000;

app.get("/api/match-intelligence/absentees", async (req, res) => {
    const homeTeam = String(req.query && req.query.homeTeam || "").trim().slice(0, 100);
    const awayTeam = String(req.query && req.query.awayTeam || "").trim().slice(0, 100);
    if (!homeTeam || !awayTeam || homeTeam.length < 2 || awayTeam.length < 2 ||
        homeTeam.toLowerCase() === awayTeam.toLowerCase()) {
        return res.status(400).json({ error: "Provide two different teams using homeTeam and awayTeam." });
    }

    const cacheKey = homeTeam.toLowerCase() + "::" + awayTeam.toLowerCase() + "::" + String(req.query.competition || "").toLowerCase().trim();
    const forceRefresh = /^(1|true|yes)$/i.test(String(req.query.forceRefresh || ""));
    const cached = absenteeReportCache.get(cacheKey);
    if (!forceRefresh && cached && Date.now() < cached.expiresAt) {
        res.set("X-Football-Genie-Cache", "HIT");
        return res.json(cached.data);
    }

    try {
        // Big Balls is the selected primary structured provider. Do not silently fall back
        // to news-search or another AI provider when this integration is unavailable.
        const bigBalls = await fetchBigBallsFootballAbsences(homeTeam, awayTeam, req.query.competition);
        const reports = bigBalls.rows.map(item => ({
            player: item.playerName,
            team: item.teamName,
            reason: item.reason || null,
            providerStatus: item.status || null,
            reportedStatus: "availability_not_established",
            providerRecordType: "absence_record",
            fixtureDate: item.fixtureDate || null,
            fixture: item.fixtureName || null,
            playerId: item.playerId,
            sourceLabel: "Football Genie • BIG BALLS Data",
            sourceLinkHidden: true,
            currentAvailabilityVerified: false,
            evidenceNote: "Provider absence record; this record alone does not confirm the player is unavailable for the requested upcoming fixture."
        }));
        const result = {
            status: reports.length ? "provider_absence_records_found" : "no_provider_absence_records_for_teams",
            fixture: { home: homeTeam, away: awayTeam },
            generatedAt: new Date().toISOString(),
            provider: "BIG BALLS Data",
            providerLeague: bigBalls.league,
            providerAsOf: bigBalls.meta.as_of || bigBalls.meta.asOf || bigBalls.meta.updated_at || null,
            providerStale: typeof bigBalls.meta.stale === "boolean" ? bigBalls.meta.stale : null,
            providerRecordCount: reports.length,
            providerTotalLeagueRecords: bigBalls.totalProviderRows,
            providerDiagnostics: bigBalls.diagnostics || null,
            reports,
            evidence: reports.map((report, index) => ({
                evidenceId: "BB" + (index + 1),
                player: report.player,
                team: report.team,
                reason: report.reason,
                fixtureDate: report.fixtureDate,
                fixture: report.fixture,
                providerStatus: report.providerStatus,
                currentAvailabilityVerified: false
            })),
            sourcePolicy: {
                primaryProvider: "BIG BALLS Data",
                officialClubConfirmationStillPreferred: true,
                historicalAbsenceIsNotCurrentUnavailability: true,
                outboundPublisherLinksShown: false
            },
            importantNotice: "BIG BALLS Data is the structured absentee-data provider. Records are shown as provider-reported absence records; they do not automatically confirm current unavailability for the requested fixture. No prediction probabilities are changed by this endpoint."
        };
        absenteeReportCache.set(cacheKey, { expiresAt: Date.now() + ABSENTEE_REPORT_CACHE_TTL_MS, data: result });
        return res.json(result);
    } catch (error) {
        const code = error.code || "bigballs_provider_error";
        const statusCode = code === "bigballs_key_missing" || code === "bigballs_league_unknown" ? 503
            : error.status === 429 ? 429 : 502;
        console.error("BIG BALLS absentee provider unavailable:", String(error.message || error).slice(0, 220));
        return res.status(statusCode).json({
            status: code === "bigballs_key_missing" ? "provider_not_configured"
                : code === "bigballs_league_unknown" ? "competition_required" : "provider_unavailable",
            provider: "BIG BALLS Data",
            error: code === "bigballs_key_missing"
                ? "Add BIGBALLSDATA_API_KEY to the Render environment variables."
                : code === "bigballs_league_unknown"
                    ? "Supply the fixture competition so Football Genie can select the correct BIG BALLS league."
                    : "BIG BALLS Data could not return the absentee dataset. No alternative provider was silently substituted."
        });
    }

});

// Groq is the primary AI provider for Football Genie.
// Retry only transient provider/network failures once; never retry authentication or input errors.
async function requestGroqAnswer(systemInstruction, userContent, options = {}) {
    if (!process.env.GROQ_API_KEY) return null;
    const model = process.env.GROQ_MODEL || "openai/gpt-oss-120b";
    const maxTokens = Number.isFinite(options.maxTokens) ? options.maxTokens : 3000;
    const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 45000;
    const maxAttempts = Number.isFinite(options.maxAttempts)
        ? Math.max(1, Math.min(2, Math.floor(options.maxAttempts))) : 2;
    let lastError;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + process.env.GROQ_API_KEY,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    model,
                    temperature: 0.2,
                    max_tokens: maxTokens,
                    messages: [
                        { role: "system", content: systemInstruction },
                        { role: "user", content: userContent }
                    ]
                }),
                signal: AbortSignal.timeout(timeoutMs)
            });
            const textBody = await response.text();
            let data;
            try { data = JSON.parse(textBody); }
            catch (_) {
                const error = new Error("Groq returned an unreadable response.");
                error.retryable = response.status >= 500 || response.status === 429;
                throw error;
            }

            if (!response.ok) {
                const error = new Error("Groq HTTP " + response.status + ": " +
                    String(data.error && data.error.message || "provider request failed").slice(0, 220));
                // Groq daily token/request quotas will not recover after a short retry.
                // Avoid spending another request when the provider explicitly reports a daily limit.
                error.quotaExhausted = response.status === 429 &&
                    /tokens per day|requests per day|\bTPD\b|\bRPD\b|per-day limit|daily limit/i.test(error.message);
                error.retryable = !error.quotaExhausted &&
                    (response.status === 429 || [500, 502, 503, 504].includes(response.status));
                const retryAfter = Number(response.headers.get("retry-after"));
                error.retryAfterMs = Number.isFinite(retryAfter) && retryAfter > 0
                    ? Math.min(1500, retryAfter * 1000) : 500;
                throw error;
            }

            const answer = data.choices && data.choices[0] && data.choices[0].message
                ? String(data.choices[0].message.content || "").trim() : "";
            if (!answer) throw new Error("Groq returned an empty answer.");
            if (attempt > 1) console.warn("Groq request succeeded after retry", { attempt, model });
            return { answer, model };
        } catch (error) {
            lastError = error;
            const networkOrTimeout = !error.status &&
                (error.name === "AbortError" || error.name === "TimeoutError" ||
                 error.name === "TypeError" || error.cause);
            const retryable = error.retryable === true || networkOrTimeout;
            if (attempt >= maxAttempts || !retryable) break;
            const delayMs = error.retryAfterMs || 500;
            console.warn("Transient Groq failure; retrying once", {
                attempt, delayMs, error: String(error.message || error).slice(0, 180)
            });
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
    throw lastError || new Error("Groq request failed.");
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

// Safe in-memory diagnostics for the most recent cloud-analysis failures.
// These records deliberately exclude credentials, prompts, and match details.
let lastMatchAnalysisFailure = null;
let lastAiAnalysisFailure = null;
app.get("/api/match-intelligence/diagnostics", (req, res) => {
    if (!lastMatchAnalysisFailure) {
        return res.json({ status: "no_recent_failure", checkedAt: new Date().toISOString() });
    }
    return res.json({ ...lastMatchAnalysisFailure, checkedAt: new Date().toISOString() });
});
app.get("/api/ai/diagnostics", (req, res) => {
    if (!lastAiAnalysisFailure) {
        return res.json({ status: "no_recent_failure", checkedAt: new Date().toISOString() });
    }
    return res.json({ ...lastAiAnalysisFailure, checkedAt: new Date().toISOString() });
});

// Evidence-grounded conversational analysis. Provider keys stay on the server.
// Groq is primary; OpenAI is an optional fallback if Groq is unavailable.
// Coalesce simultaneous requests for the same fixture to prevent repeated taps
// from launching duplicate news searches and AI requests.
const inFlightMatchAnalyses = new Map();

app.get("/api/match-intelligence/analyze", async (req, res) => {
    const homeTeam = String(req.query && req.query.homeTeam || "").trim().slice(0, 100);
    const awayTeam = String(req.query && req.query.awayTeam || "").trim().slice(0, 100);
    if (!homeTeam || !awayTeam || homeTeam.length < 2 || awayTeam.length < 2 ||
        homeTeam.toLowerCase() === awayTeam.toLowerCase()) {
        return res.status(400).json({ error: "Provide two different team names using homeTeam and awayTeam." });
    }
    if (!process.env.GROQ_API_KEY) {
        return res.status(503).json({ status: "ai_not_configured", error: "Groq AI is not configured on the server." });
    }

    const analysisKey = homeTeam.toLowerCase() + "|" + awayTeam.toLowerCase();
    const existingAnalysis = inFlightMatchAnalyses.get(analysisKey);
    if (existingAnalysis) {
        try {
            const sharedResult = await existingAnalysis;
            res.set("X-Football-Genie-Request", "coalesced");
            if (sharedResult && sharedResult.__httpStatus) {
                return res.status(sharedResult.__httpStatus).json({
                    ...sharedResult.payload,
                    requestCoalesced: true
                });
            }
            return res.json({ ...sharedResult, requestCoalesced: true });
        } catch (_) {
            return res.status(503).json({
                status: "analysis_in_progress_failed",
                retryable: true,
                error: "The first analysis request did not complete. Please try again shortly."
            });
        }
    }

    let resolveAnalysis;
    let rejectAnalysis;
    const sharedAnalysisPromise = new Promise((resolve, reject) => {
        resolveAnalysis = resolve;
        rejectAnalysis = reject;
    });
    inFlightMatchAnalyses.set(analysisKey, sharedAnalysisPromise);

    let failureStage = "news_fetch";
    try {
        const newsUrl = new URL("/api/match-intelligence/news", req.protocol + "://" + req.get("host"));
        newsUrl.searchParams.set("homeTeam", homeTeam);
        newsUrl.searchParams.set("awayTeam", awayTeam);
        // Match analysis should use a fresh news lookup by default; callers may explicitly opt out with forceRefresh=false.
        const forceRefreshNews = !/^(0|false|no)$/i.test(String(req.query.forceRefresh || "true"));
        if (forceRefreshNews) newsUrl.searchParams.set("forceRefresh", "true");
        const newsResponse = await fetch(newsUrl, {
            headers: { "Accept": "application/json" },
            signal: AbortSignal.timeout(9000)
        });
        const newsData = await newsResponse.json().catch(() => ({}));
        if (!newsResponse.ok) {
            const failurePayload = {
                status: "news_unavailable",
                error: "The news search could not be completed, so no evidence-based report was generated."
            };
            // Resolve the shared result as an HTTP failure too, so simultaneous
            // callers receive the same outcome instead of waiting forever.
            resolveAnalysis({ __httpStatus: 502, payload: failurePayload });
            return res.status(502).json(failurePayload);
        }
        // Prefer direct-fixture evidence. Background reports are secondary and
        // must remain explicitly labelled; do not let a large pile of weak leads
        // dominate the AI context.
        const rawArticles = Array.isArray(newsData.articles) ? newsData.articles : [];
        const directArticles = rawArticles.filter(article => article.fixtureRelevance === "direct_fixture");
        const backgroundArticles = rawArticles.filter(article =>
            article.fixtureRelevance === "team_background_news" ||
            article.fixtureRelevance === "team_news_other_fixture_or_opponent_context");
        const selectedArticles = [
            ...directArticles.slice(0, 6),
            ...backgroundArticles.slice(0, directArticles.length >= 4 ? 2 : 4)
        ].slice(0, 8);
        const articles = selectedArticles.map((article, index) => {
            const source = String(article.source || "").slice(0, 120);
            const sourceText = (source + " " + String(article.url || "")).toLowerCase();
            const officialSource = /(^|[.\s])chelsea fc|arsenal\.com|chelseafc\.com|mancity\.com|manutd\.com|liverpoolfc\.com|tottenhamhotspur\.com|avfc\.co\.uk|evertonfc\.com|premierleague\.com|thefa\.com|uefa\.com|fifa\.com/.test(sourceText);
            return {
                evidenceId: "E" + (index + 1),
                title: String(article.title || "").slice(0, 300),
                source,
                sourceAuthority: officialSource ? "official_or_league_source_check_original_url" : "third_party_or_unverified_source",
                publishedAt: article.publishedAt || null,
                freshness: article.freshness || "date_unknown",
                categories: Array.isArray(article.categories) ? article.categories : [],
                certainty: article.certainty || "not_established",
                fixtureRelevance: article.fixtureRelevance || "not_classified",
                snippet: String(article.snippet || "").slice(0, 500),
                url: article.url || null
            };
        });
        const systemInstruction = "You are Football Genie Match Intelligence, an evidence-grounded football news analyst. Use ONLY the supplied articles and do not use outside knowledge to fill gaps. Each article has evidenceId E1, E2, etc., and sourceAuthority metadata. CRITICAL RULE: a search headline, search snippet, or third-party article title is not proof that a named player belongs to the club named in that headline. Do not write sentences such as 'Chelsea player X' or place a player in a team table unless the supplied text explicitly establishes BOTH the player's identity and that club affiliation; if it does not, write 'the headline mentions X and [club], but the affiliation is unverified' or omit the affiliation. Never infer a player's club from the requested fixture, a headline, old knowledge, or a URL redirect. For every player-specific claim, cite the evidenceId, quote exact supporting words from title/snippet, and link the article. A headline may support only that a source published those words; it does NOT automatically prove the player's current club, medical diagnosis, current availability, or return date. Do not combine facts about different players or fixtures. Treat a source as officially confirmed ONLY when sourceAuthority marks it official_or_league_source_check_original_url AND the linked original page is clearly an official club/league/federation source; otherwise label it as a media report, not an official confirmation. The sourceAuthority label is a heuristic, not proof that the original page was opened or verified. Even when the title says official or confirmed, do not imply Football Genie independently verified the original page. Distinguish confirmed club statements, third-party reports, predictions, and estimates. Return date estimates must remain estimates and be attributed to the source. Before calling an article relevant to this fixture, check whether it actually names either requested team and whether it concerns this specific fixture or only another fixture/background. Never turn a list of historical injury updates into a claim that a player is currently unavailable. If evidence is insufficient, ambiguous, stale, or conflicting, explicitly say what is unknown and do not guess. Missing reports do NOT mean the squad is fully fit. Explain possible relevance conditionally without changing numerical probabilities. Do not give betting guarantees. Keep the report clear and mobile-friendly. Prefer a short 'What the evidence supports / What remains unverified / What to check before kickoff' structure. Do NOT create a player-by-player team table from headlines alone. Only discuss a named player when the supplied title/snippet clearly connects that player's name to a specific claim; if current club affiliation or availability is not explicitly established, say so and do not assign the player to either team. Put direct_fixture evidence first. Treat team_background_news and team_news_other_fixture_or_opponent_context as background only, explicitly state that they do not establish availability for the requested fixture, and omit them if they add no clear value. If there are no direct-fixture articles, say that no direct-fixture evidence was found and keep any background section short. Final check: no unsupported club affiliations, medical claims, return dates, player names, sources, or fixture links.";
        const userContent = "Requested fixture: " + homeTeam + " vs " + awayTeam +
            "\nSearch status: " + String(newsData.status || "unknown") +
            "\nSearch time: " + String(newsData.searchedAt || "unknown") +
            "\nEvidence articles (unverified search leads; use article indexes and quote exact titles/snippets when naming players):\n" + JSON.stringify(articles);
        failureStage = "groq_analysis";
        const result = await requestGroqAnswer(systemInstruction, userContent, {
            // Evidence-grounded reports need more time than a short chat response.
            maxTokens: 900, timeoutMs: 25000, maxAttempts: 2
        });
        void logSystemEvent("match_intelligence_report_created", "success", "News intelligence report generated.", {
            homeTeam, awayTeam, articleCount: articles.length, provider: "groq", model: result.model
        });
        const reportPayload = {
            status: "analysis_complete",
            fixture: { home: homeTeam, away: awayTeam },
            provider: "groq",
            model: result.model,
            searchedAt: newsData.searchedAt || null,
            articleCount: articles.length,
            evidence: articles,
            report: result.answer,
            importantNotice: "AI-generated summaries can still make mistakes. Official confirmation is only established by checking the original official club/league/federation page; source labels and headlines alone are not enough. Verify player affiliation, medical status, return estimates, and relevance to this fixture against linked sources. No articles found does not mean there are no injuries. Numerical prediction probabilities are not changed by this report."
        };
        resolveAnalysis(reportPayload);
        return res.json(reportPayload);
    } catch (error) {
        rejectAnalysis(error);
        const diagnostic = String(error && error.message || "unknown");
        const providerQuotaExhausted = /Groq HTTP 429/i.test(diagnostic) &&
            /tokens per day|requests per day|\bTPD\b|\bRPD\b|per-day limit|daily limit/i.test(diagnostic);
        const providerRateLimited = !providerQuotaExhausted &&
            /Groq HTTP 429|rate.?limit|too many requests/i.test(diagnostic);
        const providerUnavailable = /Groq HTTP 5\d\d|timeout|timed out|abort/i.test(diagnostic);
        console.error("Match intelligence analysis failed at " + failureStage + ":", diagnostic);
        const groqStatusMatch = diagnostic.match(/Groq HTTP (\d{3})/);
        lastMatchAnalysisFailure = {
            status: providerQuotaExhausted ? "provider_quota_exhausted" :
                providerRateLimited ? "provider_rate_limited" :
                providerUnavailable ? "provider_unavailable" : "analysis_failed",
            stage: failureStage,
            providerHttpStatus: groqStatusMatch ? Number(groqStatusMatch[1]) : null,
            errorType: /timeout|timed out|abort/i.test(diagnostic) ? "timeout" :
                /Groq HTTP 401|Groq HTTP 403/i.test(diagnostic) ? "provider_authentication" :
                providerQuotaExhausted ? "provider_daily_quota" :
                /Groq HTTP 429|rate.?limit|too many requests/i.test(diagnostic) ? "provider_rate_limit" :
                /Groq HTTP 5\d\d/i.test(diagnostic) ? "provider_server_error" :
                failureStage === "news_fetch" ? "news_fetch_failure" : "other"
        };
        void logSystemEvent("match_intelligence_report_failed", "warning", "News intelligence analysis failed.", {
            stage: failureStage,
            providerRateLimited,
            providerQuotaExhausted,
            error: diagnostic.slice(0, 180)
        });
        if (providerQuotaExhausted) {
            // Daily quota resets are provider-controlled; a 60-second retry would be misleading.
            return res.status(503).json({
                status: "ai_daily_quota_exhausted",
                stage: failureStage,
                retryable: false,
                error: "Football Genie AI has reached its provider's daily usage limit. Match news and other app features may still work; AI analysis will resume when the provider quota resets."
            });
        }
        if (providerRateLimited) {
            res.set("Retry-After", "60");
            return res.status(503).json({
                status: "ai_rate_limited",
                stage: failureStage,
                retryable: true,
                retryAfterSeconds: 60,
                error: "Football Genie AI is temporarily rate-limited. Please wait about one minute before trying again."
            });
        }
        if (providerUnavailable) {
            res.set("Retry-After", "30");
            return res.status(503).json({
                status: "ai_temporarily_unavailable",
                stage: failureStage,
                retryable: true,
                retryAfterSeconds: 30,
                error: "Football Genie AI is temporarily unavailable or taking too long. Please try again shortly."
            });
        }
        return res.status(502).json({
            status: "analysis_failed",
            stage: failureStage,
            retryable: true,
            error: failureStage === "news_fetch"
                ? "Football Genie could not retrieve the news evidence. Please try again later."
                : "Football Genie could not complete the AI analysis. Please try again later."
        });
    } finally {
        if (inFlightMatchAnalyses.get(analysisKey) === sharedAnalysisPromise) {
            inFlightMatchAnalyses.delete(analysisKey);
        }
    }
});


/*
 * News-aware prediction review. This deliberately preserves baseline probabilities:
 * news search leads are not verified enough to justify automatic numerical changes.
 * The response explains evidence and potential relevance for later validation.
 */
app.get("/api/match-intelligence/prediction-review", async (req, res) => {
    const homeTeam = String(req.query && req.query.homeTeam || "").trim().slice(0, 100);
    const awayTeam = String(req.query && req.query.awayTeam || "").trim().slice(0, 100);
    if (!homeTeam || !awayTeam || homeTeam.length < 2 || awayTeam.length < 2 ||
        homeTeam.toLowerCase() === awayTeam.toLowerCase()) {
        return res.status(400).json({ error: "Provide two different teams using homeTeam and awayTeam." });
    }
    if (!process.env.GROQ_API_KEY) {
        return res.status(503).json({ status: "ai_not_configured", error: "Groq AI is not configured on the server." });
    }
    const probabilityFields = ["homeWin", "draw", "awayWin", "over25", "under25", "btts"];
    const baseline = {};
    for (const field of probabilityFields) {
        const raw = req.query[field];
        if (raw === undefined || raw === "") {
            baseline[field] = null;
            continue;
        }
        const number = Number(raw);
        if (!Number.isFinite(number) || number < 0 || number > 100) {
            return res.status(400).json({ error: field + " must be a number between 0 and 100." });
        }
        baseline[field] = number;
    }
    try {
        const newsUrl = new URL("/api/match-intelligence/news", req.protocol + "://" + req.get("host"));
        newsUrl.searchParams.set("homeTeam", homeTeam);
        newsUrl.searchParams.set("awayTeam", awayTeam);
        // Match analysis should use a fresh news lookup by default; callers may explicitly opt out with forceRefresh=false.
        const forceRefreshNews = !/^(0|false|no)$/i.test(String(req.query.forceRefresh || "true"));
        if (forceRefreshNews) newsUrl.searchParams.set("forceRefresh", "true");
        const newsResponse = await fetch(newsUrl, {
            headers: { "Accept": "application/json" },
            signal: AbortSignal.timeout(15000)
        });
        const newsData = await newsResponse.json().catch(() => ({}));
        if (!newsResponse.ok) {
            return res.status(502).json({ status: "news_unavailable", error: "News search failed; the baseline prediction has not been changed." });
        }
        const articles = (Array.isArray(newsData.articles) ? newsData.articles : []).slice(0, 12).map((article, index) => ({
            evidenceId: index + 1,
            title: String(article.title || "").slice(0, 300),
            source: String(article.source || "").slice(0, 120),
            publishedAt: article.publishedAt || null,
            freshness: article.freshness || "date_unknown",
            categories: Array.isArray(article.categories) ? article.categories : [],
            certainty: article.certainty || "not_established",
            fixtureRelevance: article.fixtureRelevance || "not_classified",
            snippet: String(article.snippet || "").slice(0, 500),
            url: article.url || null
        }));
        const systemInstruction = "You are Football Genie’s evidence-limited team-news analyst. Return a concise mobile-friendly review. Use only the supplied article titles and snippets. Identify named players only when their names literally appear in the supplied evidence; never invent or complete names. For every player mention, give evidenceId, exact article title, source, date if available, and URL. State the reported status carefully and do not present a search headline as verified medical information. Separate home-team and away-team reports; flag articles about other fixtures or general background. Explain plausible football relevance conditionally, not as a certainty. Do not change, recalculate, or suggest numerical changes to the baseline probabilities. If evidence is weak or irrelevant, say so. If no players can be named from evidence, explicitly say that. Finish with what to verify before kickoff.";
        const userContent = "Fixture: " + homeTeam + " vs " + awayTeam +
            "\nBaseline probabilities (percent; preserve unchanged): " + JSON.stringify(baseline) +
            "\nSearch status: " + String(newsData.status || "unknown") +
            "\nSearch time: " + String(newsData.searchedAt || "unknown") +
            "\nEvidence articles:\n" + JSON.stringify(articles);
        const result = await requestGroqAnswer(systemInstruction, userContent);
        void logSystemEvent("prediction_news_review_created", "success", "News context reviewed alongside unchanged baseline probabilities.", {
            homeTeam, awayTeam, articleCount: articles.length, provider: "groq", model: result.model
        });
        return res.json({
            status: "review_complete",
            fixture: { home: homeTeam, away: awayTeam },
            provider: "groq",
            model: result.model,
            searchedAt: newsData.searchedAt || null,
            baselineProbabilities: baseline,
            adjustedProbabilities: null,
            adjustmentStatus: "not_applied_pending_validation",
            articleCount: articles.length,
            evidence: articles,
            newsReview: result.answer,
            importantNotice: "Baseline probabilities are preserved. News articles are search leads, not independent verification. No numerical adjustment is applied until its effect can be validated against completed matches."
        });
    } catch (error) {
        console.error("Prediction news review failed:", error.message);
        void logSystemEvent("prediction_news_review_failed", "warning", "Prediction news review failed.", {
            error: String(error.message || "unknown").slice(0, 180)
        });
        return res.status(502).json({ status: "review_failed", error: "Football Genie could not complete the news review. Baseline probabilities remain unchanged." });
    }
});

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
    let userContent = "Question: " + prompt +
        "\nSaved validation report summary (user-provided app metrics):\n" + validationSummary +
        "\nMatch evidence (percentages are model probabilities, not live facts):\n" +
        JSON.stringify({ home, away, ...evidence }) +
        "\nCompleted saved predictions with actual scores (historical evidence only; newest first):\n" +
        JSON.stringify(completedHistory);

    // Connect the existing Android AI chat to the agreed free online-publication
    // injury/news sources only when the user asks about availability or team news.
    // These are reported leads, not verified injury records; never change probabilities.
    const asksAboutAbsentees = /injur|absen|unavailab|suspend|suspension|team news|line.?up|missing player|fitness|who is out|who will miss|player availability/i.test(prompt);
    let teamNewsEvidenceStatus = "not_requested";
    if (asksAboutAbsentees && home !== "Home team" && away !== "Away team" &&
        home.toLowerCase() !== away.toLowerCase()) {
        teamNewsEvidenceStatus = "unavailable";
        try {
            const newsUrl = new URL("/api/match-intelligence/news", req.protocol + "://" + req.get("host"));
            newsUrl.searchParams.set("homeTeam", home);
            newsUrl.searchParams.set("awayTeam", away);
            // The RSS route itself can take up to 12 seconds. Give it enough time to
            // finish; the old 9-second outer timeout could abort before evidence arrived.
            // Respect the news endpoint cache during AI follow-up questions. Forcing a fresh
            // RSS search on every absentee question can trigger provider rate limits.
            // A manual request may still use forceRefresh=true when a fresh fetch is genuinely needed.
            const newsResponse = await fetch(newsUrl, {
                headers: { "Accept": "application/json" },
                signal: AbortSignal.timeout(15000)
            });
            const newsData = await newsResponse.json().catch(() => ({}));
            if (newsResponse.ok) {
                const allNewsArticles = Array.isArray(newsData.articles) ? newsData.articles : [];
                // Injury/availability analysis accepts official club website evidence only.
                // Third-party publications are deliberately ignored for absentee claims.
                const rawArticles = allNewsArticles.filter(article =>
                    article.officialClubSource === true || article.sourceTrustTier === "official_club_website"
                );
                const nonOfficialArticlesIgnored = allNewsArticles.length - rawArticles.length;
                const directArticles = rawArticles.filter(article => article.fixtureRelevance === "direct_fixture");
                const backgroundArticles = rawArticles.filter(article =>
                    article.fixtureRelevance === "team_background_news" ||
                    article.fixtureRelevance === "team_news_other_fixture_or_opponent_context");
                const selectedArticles = [
                    ...directArticles.slice(0, 5),
                    ...backgroundArticles.slice(0, directArticles.length >= 3 ? 2 : 3)
                ].slice(0, 8);
                const articles = selectedArticles.map((article, index) => {
                    const source = String(article.source || "").slice(0, 100);
                    const sourceText = (source + " " + String(article.url || "")).toLowerCase();
                    const officialSource = /(^|[.\s])chelsea fc|arsenal\\.com|chelseafc\\.com|mancity\\.com|manutd\\.com|liverpoolfc\\.com|tottenhamhotspur\\.com|avfc\\.co\\.uk|evertonfc\\.com|premierleague\\.com|thefa\\.com|uefa\\.com|fifa\\.com/.test(sourceText);
                    return {
                        evidenceId: "N" + (index + 1),
                        title: String(article.title || "").slice(0, 250),
                        source,
                        sourceAuthority: officialSource ? "possible_official_source_check_original_url" : "third_party_or_unverified_source",
                        publishedAt: article.publishedAt || null,
                        freshness: article.freshness || "date_unknown",
                        categories: Array.isArray(article.categories) ? article.categories : [],
                        certainty: article.certainty || "not_established",
                        fixtureRelevance: article.fixtureRelevance || "not_classified",
                        snippet: String(article.snippet || "").slice(0, 350),
                        url: article.url || null
                    };
                });
                teamNewsEvidenceStatus = articles.length ? "articles_found" : "no_articles_found";
                userContent += "\nOFFICIAL-CLUB TEAM-NEWS EVIDENCE ONLY (third-party publications ignored: " + nonOfficialArticlesIgnored + "):\n" +
                    JSON.stringify({
                        status: newsData.status || "unknown",
                        searchedAt: newsData.searchedAt || null,
                        maxArticleAgeDays: newsData.maxArticleAgeDays || 30,
                        importantNotice: newsData.importantNotice || "News articles are leads, not verified player-availability records.",
                        articles
                    });
            } else {
                userContent += "\nONLINE-PUBLICATION TEAM-NEWS EVIDENCE: search failed; no live availability evidence is available for this request.";
            }
        } catch (newsError) {
            userContent += "\nONLINE-PUBLICATION TEAM-NEWS EVIDENCE: search timed out or failed; do not guess current absentees.";
        }
        userContent += "\nTEAM-NEWS SAFETY RULE: Use only supplied official club website article titles/snippets. Third-party publications are not evidence for absentee claims. For every player-specific report cite the evidenceId, exact title, source, and date if available. Prefer direct_fixture evidence; background or other-fixture stories must not be used to claim a player will miss THIS fixture. Freshness does not prove the report is current. Do not infer a diagnosis or availability from a vague headline. If no relevant official evidence exists, explicitly say Football Genie found no relevant official club update; do not fill the gap with other publications or guesses. Absence of a report does not mean the squad is fully fit. Never invent names or change numerical probabilities.";
    }

    void logSystemEvent("ai_analysis_requested", "info", "AI analysis request received.", { questionLength: prompt.length, teamNewsEvidenceStatus });
    const recordAiFailure = (status, stage, providerHttpStatus, errorType, retryable) => {
        lastAiAnalysisFailure = {
            status, stage, providerHttpStatus: providerHttpStatus || null,
            errorType, retryable: Boolean(retryable)
        };
    };
    try {
        // Groq is the primary AI provider. OpenAI is an optional independent fallback.
        let groqFailureMessage = "";
        if (process.env.GROQ_API_KEY) {
            try {
                const result = await requestGroqAnswer(systemInstruction, userContent);
                lastAiAnalysisFailure = null;
                void logSystemEvent("ai_analysis_succeeded", "success", "AI analysis completed successfully.", { provider: "groq", model: result.model });
                return res.json({
                    answer: result.answer,
                    provider: "groq",
                    model: result.model,
                    evidenceUsed: evidence
                });
            } catch (groqError) {
                groqFailureMessage = String(groqError && groqError.message || "Unknown Groq error");
                const statusMatch = groqFailureMessage.match(/Groq HTTP (\\d{3})/);
                const httpStatus = statusMatch ? Number(statusMatch[1]) : null;
                const dailyQuota = httpStatus === 429 &&
                    /tokens per day|requests per day|\\bTPD\\b|\\bRPD\\b|per-day limit|daily limit/i.test(groqFailureMessage);
                const rateLimited = httpStatus === 429 || /rate.?limit|too many requests/i.test(groqFailureMessage);
                recordAiFailure(
                    dailyQuota ? "provider_quota_exhausted" : rateLimited ? "provider_rate_limited" : "provider_failed",
                    "groq",
                    httpStatus,
                    dailyQuota ? "provider_daily_quota" : rateLimited ? "provider_rate_limit" :
                        /timeout|timed out|abort/i.test(groqFailureMessage) ? "timeout" :
                        /Groq HTTP 401|Groq HTTP 403/i.test(groqFailureMessage) ? "provider_authentication" : "provider_error",
                    !dailyQuota
                );
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
                const providerMessage = String(data.error && data.error.message || "OpenAI provider error");
                recordAiFailure("provider_failed", "openai", response.status,
                    response.status === 429 ? "provider_rate_or_quota_limit" :
                    response.status === 401 || response.status === 403 ? "provider_authentication" : "provider_error",
                    response.status !== 401 && response.status !== 403);
                console.error("OpenAI provider error:", response.status, providerMessage.slice(0, 180));
                return res.status(502).json({ code: "AI_PROVIDER_FAILED", error: "The AI analyst could not complete this request. Please try again." });
            }
            const answer = data.choices && data.choices[0] && data.choices[0].message
                ? String(data.choices[0].message.content || "").trim() : "";
            if (!answer) {
                recordAiFailure("provider_failed", "openai", response.status, "empty_provider_response", true);
                return res.status(502).json({ error: "The AI analyst returned an empty answer." });
            }
            lastAiAnalysisFailure = null;
            return res.json({ answer, provider: "openai", model, evidenceUsed: evidence });
        }

        if (process.env.GROQ_API_KEY && groqFailureMessage) {
            return res.status(502).json({
                code: "AI_PROVIDER_FAILED",
                error: "Groq could not complete this analysis: " + groqFailureMessage.slice(0, 180) + ". Please try again."
            });
        }

        recordAiFailure("ai_not_configured", "configuration", null, "missing_provider_key", false);
        return res.status(503).json({
            code: "AI_NOT_CONFIGURED",
            error: "Cloud AI is not configured. Add GROQ_API_KEY for Groq, or OPENAI_API_KEY for the optional OpenAI fallback."
        });
    } catch (error) {
        const message = String(error && error.message || "unknown");
        const statusMatch = message.match(/(?:Groq|OpenAI) HTTP (\\d{3})/);
        const httpStatus = statusMatch ? Number(statusMatch[1]) : null;
        const dailyQuota = httpStatus === 429 &&
            /tokens per day|requests per day|\\bTPD\\b|\\bRPD\\b|per-day limit|daily limit/i.test(message);
        recordAiFailure(
            dailyQuota ? "provider_quota_exhausted" : "analysis_failed",
            "request",
            httpStatus,
            dailyQuota ? "provider_daily_quota" :
                /timeout|timed out|abort/i.test(message) ? "timeout" :
                httpStatus === 429 ? "provider_rate_limit" :
                httpStatus === 401 || httpStatus === 403 ? "provider_authentication" : "request_error",
            !dailyQuota && httpStatus !== 401 && httpStatus !== 403
        );
        console.error("AI analysis request failed:", error.name, message.slice(0, 180));
        void logSystemEvent("ai_analysis_failed", "error", "AI analysis request failed.", {
            errorName: error.name, errorType: lastAiAnalysisFailure.errorType,
            providerHttpStatus: httpStatus
        });
        return res.status(dailyQuota ? 503 : 502).json({
            code: dailyQuota ? "AI_DAILY_QUOTA_EXHAUSTED" : "AI_PROVIDER_FAILED",
            retryable: !dailyQuota,
            error: dailyQuota
                ? "Football Genie AI has reached its provider's daily usage limit. AI analysis will resume when the provider quota resets."
                : "Football Genie AI could not complete this request. Please try again later."
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
