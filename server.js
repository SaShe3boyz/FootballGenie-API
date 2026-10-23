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
const FOOTBALL_NEWS_MAX_AGE_DAYS = 30;

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
    if (/line.?up|starting xi|starting eleven|team news|confirmed xi|confirmed line.?up|squad named/.test(text)) categories.push("lineup");
    if (/manager|coach|press conference|reveals|speaks ahead|comments/.test(text)) categories.push("manager_comment");
    if (/predicted|prediction|preview|could miss|doubt|questionable|expected to/.test(text)) categories.push("unconfirmed_report");
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

    // Search either team's availability news, not only articles mentioning both clubs.
    // Most injury reports discuss one club and do not name its next opponent.
    const homeSearchNames = footballTeamAliases(homeTeam).map(name => '"' + name + '"').join(" OR ");
    const awaySearchNames = footballTeamAliases(awayTeam).map(name => '"' + name + '"').join(" OR ");
    const query = '((' + homeSearchNames + ') OR (' + awaySearchNames +
        ')) (injury OR injured OR unavailable OR suspension OR suspended OR lineup OR "team news" OR "ruled out" OR "out for" OR "fitness update" OR "press conference") -women -"women\'s" -WSL -ladies';
    const googleUrl = "https://news.google.com/rss/search?" + new URLSearchParams({
        q: query + " when:30d", hl: "en", gl: "GB", ceid: "GB:en"
    }).toString();
    // Use only the selected news sources: Google News search plus established
    // football coverage from BBC Sport, Sky Sports and The Athletic. Providers
    // that repeatedly fail or return unsuitable results are intentionally excluded.
    const homeTeamQuery = '(' + homeSearchNames + ') (injury OR injured OR unavailable OR suspension OR suspended OR "team news" OR "ruled out" OR "out for" OR "fitness update") -women -"women\'s" -WSL -ladies';
    const awayTeamQuery = '(' + awaySearchNames + ') (injury OR injured OR unavailable OR suspension OR suspended OR "team news" OR "ruled out" OR "out for" OR "fitness update") -women -"women\'s" -WSL -ladies';
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
        }
    ];
    const requestedTeams = [homeTeam, awayTeam];
    const officialProviders = officialClubDomains.flatMap(entry => {
        const team = requestedTeams.find(name =>
            entry.aliases.some(alias => normalizeTeamName(alias) === normalizeTeamName(name)));
        if (!team) return [];
        const query = 'site:' + entry.domain + ' "' + team + '" (injury OR injured OR unavailable OR "team news" OR "fitness update" OR "ruled out" OR doubtful OR suspension)';
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
        const query = 'site:' + entry.domain + ' "' + team + '" (injury OR injured OR unavailable OR "team news" OR "fitness update" OR "ruled out" OR doubtful OR suspension)';
        return [{
            name: "Bing News RSS - " + entry.name,
            url: bingUrl(query),
            timeoutMs: 6500,
            searchTeam: team,
            officialPublisherDomain: entry.domain
        }];
    });
    const providers = [
        { name: "Google News RSS - fixture", url: googleUrl, timeoutMs: 6500 },
        { name: "Google News RSS - home team", url: teamGoogleUrl(homeTeamQuery), timeoutMs: 6500, searchTeam: homeTeam },
        { name: "Google News RSS - away team", url: teamGoogleUrl(awayTeamQuery), timeoutMs: 6500, searchTeam: awayTeam },
        // Bing News RSS provides original publisher URLs via an encoded apiclick link.
        { name: "Bing News RSS", url: bingUrl(bingQuery), timeoutMs: 6500 },
        { name: "Bing News RSS - home team", url: bingUrl(bingHomeQuery), timeoutMs: 6500, searchTeam: homeTeam },
        { name: "Bing News RSS - away team", url: bingUrl(bingAwayQuery), timeoutMs: 6500, searchTeam: awayTeam },
        ...officialBingProviders,
        // GDELT returns original publisher URLs, avoiding Google News wrapper resolution
        // and providing an independent fallback when Google News pages are rate-limited.
        { name: "GDELT News Search", url: gdeltUrl, timeoutMs: 4500, format: "json" },
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
                importantNotice: "Live news providers are currently unavailable or rate-limited. These are cached search leads, not verified player-availability records. Check the original sources before kickoff.",
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
        const description = (newsXmlTag(block, "description") || newsXmlTag(block, "summary") || newsXmlTag(block, "content"))
            .replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").slice(0, 500);
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
            classification.categories.some(category => ["injury", "suspension", "lineup"].includes(category)) ||
            (classification.categories.includes("manager_comment") && managerAvailabilityContext);
        let relevanceScore = (mentionsHome ? 2 : 0) + (mentionsAway ? 2 : 0);
        if (searchContextMatchesTarget) relevanceScore += 2;
        if (mentionsBothTeams) relevanceScore += 4;
        if (mentionsFixtureOpponent && !mentionsBothTeams) relevanceScore -= 2;
        if (conflictingFixtureOpponent && !mentionsBothTeams) relevanceScore -= 8;
        if (classification.categories.some(category => ["injury", "suspension", "lineup", "manager_comment"].includes(category))) relevanceScore += 2;
        if (classification.categories.includes("unconfirmed_report")) relevanceScore += 1;
        if (/official|confirmed|press conference|team news|injury update|suspended/.test(lowerTitle)) relevanceScore += 1;
        if (isWomensStory) relevanceScore -= 5;
        return {
            title: title.slice(0, 300),
            source: source.slice(0, 120) || "Source not identified",
            searchTeam: searchTeam || null,
            searchProvider: searchProvider || null,
            publishedAt: validDate ? validDate.toISOString() : null,
            ageDays: ageMs === null ? null : Math.floor(ageMs / (24 * 60 * 60 * 1000)),
            freshness: ageMs === null ? "date_unknown" : ageMs < 0 ? "future_date_check" : ageMs <= 7 * 24 * 60 * 60 * 1000 ? "fresh_7d" : ageMs <= maxAgeMs ? "recent_30d" : "stale",
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
    let parsedItems = parsedCandidates.filter(item => {
        if (!item.title || !item.url) { filterDiagnostics.missingTitleOrUrl++; return false; }
        if (item.isWomensStory) { filterDiagnostics.womenStories++; return false; }
        if (item.hasSpamSignals) { filterDiagnostics.spamSignals++; return false; }
        if (item.hasHeadlineNoise) { filterDiagnostics.headlineNoise++; return false; }
        if (item.publishedAt === null || item.ageDays === null) { filterDiagnostics.missingOrInvalidDate++; return false; }
        if (item.ageDays < 0) { filterDiagnostics.futureDates++; return false; }
        if (item.ageDays > FOOTBALL_NEWS_MAX_AGE_DAYS) { filterDiagnostics.staleDates++; return false; }
        if (item.relevanceScore < 3) { filterDiagnostics.lowRelevance++; return false; }
        if (item.fixtureRelevance === "other_fixture_excluded_from_analysis") { filterDiagnostics.conflictingOpponent++; return false; }
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
            return host === "avfc.co.uk" || host.endsWith(".avfc.co.uk") ||
                host === "mancity.com" || host.endsWith(".mancity.com") ||
                host === "rbleipzig.com" || host.endsWith(".rbleipzig.com") ||
                host === "borussia.com" || host.endsWith(".borussia.com") ||
                host === "arsenal.com" || host.endsWith(".arsenal.com") ||
                host === "evertonfc.com" || host.endsWith(".evertonfc.com");
        } catch (_) { return false; }
    };
    parsedItems = parsedItems.map(item => ({
        ...item,
        // Google News RSS wraps article links, but its <source url> attribute
        // identifies the publisher domain. Trust it only when it matches a supported
        // official club domain; keep the wrapped article URL as an unverified lead.
        officialClubSource: isOfficialClubUrl(item.url) || isOfficialClubUrl(item.publisherSourceUrl),
        sourceTrustTier: (isOfficialClubUrl(item.url) || isOfficialClubUrl(item.publisherSourceUrl))
            ? "official_club_website" : "secondary_publication"
    }));
    parsedItems.sort((a, b) => Number(b.officialClubSource) - Number(a.officialClubSource) ||
        b.relevanceScore - a.relevanceScore ||
        ((a.ageDays === null ? 9999 : a.ageDays) - (b.ageDays === null ? 9999 : b.ageDays)));
    // Combine the two club-specific searches but remove duplicate headlines.
    // Keep a wider evidence pool so a single-team injury report is not crowded
    // out by repeated fixture previews before absentee extraction runs.
    const uniqueParsedItems = [];
    const seenNewsItems = new Set();
    for (const item of parsedItems) {
        const dedupeKey = String(item.url || (item.title + "|" + item.source)).toLowerCase();
        if (seenNewsItems.has(dedupeKey)) continue;
        seenNewsItems.add(dedupeKey);
        uniqueParsedItems.push(item);
    }
    const items = uniqueParsedItems.slice(0, 30).map(({ relevanceScore, isWomensStory, hasSpamSignals, hasHeadlineNoise, hasRelevantAvailabilitySignal, hasTargetTeamAsSubject, ...item }) => item);
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
        articles: items,
        importantNotice: "News items are search leads, not verified player-availability records. Headlines that clearly name a different opponent are excluded to reduce cross-fixture contamination. Articles with missing or future publication dates are excluded. Open the original source and verify the exact fixture, player, team, and availability before changing a prediction. 'Confirmed' is a wording signal, not independent verification. No results does not mean there are no injuries."
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
        articles: result.articles.map(article => ({
            ...article,
            url: null,
            sourceLabel: article.officialClubSource
                ? "Football Genie • Official club source"
                : "Football Genie • Football publication",
            sourceLinkHidden: true
        })),
        importantNotice: "Football Genie prioritises official club websites and uses reputable football publications as supporting evidence. Publisher priority does not independently confirm current player availability."
    });
});

// Use the configured primary AI provider with the same OpenAI fallback as the main AI chat.
async function requestAbsenteeAIAnswer(systemInstruction, userContent) {
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

    const cacheKey = homeTeam.toLowerCase() + "::" + awayTeam.toLowerCase();
    const forceRefresh = /^(1|true|yes)$/i.test(String(req.query.forceRefresh || ""));
    const cached = absenteeReportCache.get(cacheKey);
    if (!forceRefresh && cached && Date.now() < cached.expiresAt) {
        res.set("X-Football-Genie-Cache", "HIT");
        return res.json(cached.data);
    }

    try {
        const newsUrl = new URL("/api/match-intelligence/news", req.protocol + "://" + req.get("host"));
        newsUrl.searchParams.set("homeTeam", homeTeam);
        newsUrl.searchParams.set("awayTeam", awayTeam);
        // Allow a deliberate diagnostic refresh to bypass both cache layers.
        newsUrl.searchParams.set("forceRefresh", forceRefresh ? "true" : "false");
        newsUrl.searchParams.set("internal", "true");
        const newsResponse = await fetch(newsUrl, {
            headers: { "Accept": "application/json" },
            signal: AbortSignal.timeout(15000)
        });
        const newsData = await newsResponse.json().catch(() => ({}));
        if (!newsResponse.ok) {
            return res.status(502).json({
                status: "news_unavailable",
                error: "Publication evidence could not be retrieved; no absentee claims were generated.",
                providersAttempted: newsData.providersAttempted || [],
                providerErrors: newsData.providerErrors || []
            });
        }

        // Absentee intelligence is official-club-source-only. Secondary publications may
        // still be useful for general news discovery, but must never support player-availability
        // claims or appear as absentee evidence in Football Genie.
        const rawNewsArticles = Array.isArray(newsData.articles) ? newsData.articles : [];
        const nonOfficialArticlesIgnored = rawNewsArticles.filter(article =>
            article.officialClubSource !== true && article.sourceTrustTier !== "official_club_website"
        ).length;
        const articles = rawNewsArticles
            .filter(article => article.officialClubSource === true || article.sourceTrustTier === "official_club_website")
            .slice(0, 30).map((article, index) => ({
            evidenceId: "E" + (index + 1),
            title: String(article.title || "").slice(0, 300),
            source: String(article.source || "").slice(0, 120),
            searchTeam: String(article.searchTeam || "").slice(0, 100) || null,
            searchProvider: String(article.searchProvider || "").slice(0, 100) || null,
            originalPublisherUrlResolved: article.originalPublisherUrlResolved === true,
            publisherUrlResolutionMethod: article.publisherUrlResolutionMethod || null,
            officialClubSource: article.officialClubSource === true,
            sourceTrustTier: article.sourceTrustTier || (article.officialClubSource === true ? "official_club_website" : "secondary_publication"),
            publishedAt: article.publishedAt || null,
            snippet: String(article.snippet || "").slice(0, 500),
            url: article.url || null,
            categories: Array.isArray(article.categories) ? article.categories : [],
            availabilityAssessment: article.availabilityAssessment || "availability_not_established",
            fixtureRelevance: article.fixtureRelevance || "team_background_news"
        }));

        let candidateReports = [];
        let extractionStatus = "evidence_only";
        let aiModel = null;
        let aiProvider = null;

        // Deterministic fallback: find literal player names next to availability wording
        // anywhere in a headline (not only at character zero). Many publishers prepend
        // the fixture/team, e.g. "Man City Injury News: Semenyo Out, O'Reilly Doubt".
        // Status is derived per named phrase so one doubtful player does not downgrade
        // a separate player explicitly reported out in the same headline.
        const namedAvailabilityPattern = /((?:[A-Z][A-Za-z'’.-]{2,}(?:\s+[A-Z][A-Za-z'’.-]{1,}){0,2})(?:\s+(?:and|&)\s+[A-Z][A-Za-z'’.-]{2,}(?:\s+[A-Z][A-Za-z'’.-]{1,}){0,1})?)\s+(?:(?:is|has been|will be)\s+)?(ruled out|out\b|injured\b|sidelined\b|set to miss|will miss|to miss|a doubt\b|doubts?\b|doubtful\b|faces? .*? injury|suffers? .*? injury|suffers? .*? knock|fit\b|available\b|back in training|returns? to training|returns? to the squad|available for selection)/gi;
        candidateReports = articles.flatMap(evidence => {
            const title = String(evidence.title || "");
            const subjectMarker = /\b(?:vs?\.?|versus|against|ahead of|before|after|following|trip to|clash with|meeting with|showdown with|tie with|game against|match against|game with|match with)\b/i;
            const subjectEnd = title.search(subjectMarker);
            const articleSubject = (subjectEnd >= 0 ? title.slice(0, subjectEnd) : title).trim();
            const subjectTeams = [homeTeam, awayTeam].filter(name => textMentionsFootballTeam(articleSubject, name));
            const teamFromSubject = subjectTeams.length === 1 ? subjectTeams[0] : null;
            const matches = [...title.matchAll(namedAvailabilityPattern)];
            return matches.flatMap(match => {
                const namesText = String(match[1] || "").trim();
                const phrase = String(match[2] || "").toLowerCase();
                const reportedStatus = /\b(?:a doubt|doubts?|doubtful)\b/.test(phrase)
                    ? "doubtful_or_test_pending"
                    : /\b(?:fit|available|back in training|returns? to training|returns? to the squad|available for selection)\b/.test(phrase)
                        ? "reported_available_check_source"
                        : "reported_unavailable";
                const players = namesText.split(/\s+(?:and|&)\s+/i).map(name => name.trim()).filter(Boolean);
                // Avoid treating team labels or generic editorial phrases as players.
                return players.flatMap(player => {
                    // Headlines also use capitalized medical terms immediately before "doubt"
                    // (e.g. "Back Doubt", "Calf Doubt", "injury doubts"). These are not player names.
                    if (!player || /^(?:man city|manchester city|aston villa|team news|injury news|injury|injuries|back|calf|hamstring|knee|ankle|muscle|fitness|latest|confirmed|predicted|lineup|line-up|return|doubt|doubts|update|updates|status|test|training|available|unavailable)$/i.test(player)) return [];
                    const team = teamFromSubject || (evidence.searchTeam &&
                        [homeTeam, awayTeam].find(name => normalizeTeamName(name) === normalizeTeamName(evidence.searchTeam)));
                    if (!team) return [];
                    const freshness = assessAbsenteePublicationFreshness(evidence.publishedAt);
                    return [{
                        player, team, reportedStatus,
                        reason: title.slice(0, 220),
                        evidenceId: evidence.evidenceId, title, source: evidence.source,
                        evidenceQuote: String(match[0] || "").trim(),
                        publishedAt: evidence.publishedAt, url: evidence.url,
                        sourceLinkType: (() => {
                            try {
                                const host = new URL(evidence.url).hostname.toLowerCase();
                                if (host === "news.google.com" || host.endsWith(".news.google.com")) {
                                    return "news_aggregator_link_original_publisher_not_resolved";
                                }
                                if (host === "mancity.com" || host.endsWith(".mancity.com") ||
                                    host === "avfc.co.uk" || host.endsWith(".avfc.co.uk") ||
                                    host === "rbleipzig.com" || host.endsWith(".rbleipzig.com") ||
                                    host === "borussia.com" || host.endsWith(".borussia.com") ||
                                    host === "arsenal.com" || host.endsWith(".arsenal.com") ||
                                    host === "evertonfc.com" || host.endsWith(".evertonfc.com")) {
                                    return "official_club_domain_direct_link_content_not_verified";
                                }
                                return "publisher_link_candidate_not_independently_verified";
                            } catch (_) {
                                return "source_link_missing_or_invalid";
                            }
                        })(),
                        officialPublisherDomainMatch: evidence.officialClubSource === true || (() => {
                            try {
                                const host = new URL(evidence.url).hostname.toLowerCase();
                                return host === "mancity.com" || host.endsWith(".mancity.com") ||
                                    host === "avfc.co.uk" || host.endsWith(".avfc.co.uk") ||
                                    host === "rbleipzig.com" || host.endsWith(".rbleipzig.com") ||
                                    host === "borussia.com" || host.endsWith(".borussia.com") ||
                                    host === "arsenal.com" || host.endsWith(".arsenal.com") ||
                                    host === "evertonfc.com" || host.endsWith(".evertonfc.com");
                            } catch (_) { return false; }
                        })(),
                        sourceTrustTier: evidence.sourceTrustTier || (evidence.officialClubSource === true ? "official_club_website" : "secondary_publication"),
                        publisherUrlResolutionMethod: evidence.publisherUrlResolutionMethod ||
                            (String(evidence.searchProvider || "").startsWith("Bing News RSS - official")
                                ? "direct_official_club_domain_search_result" : null),
                        originalSourceUrlVerified: false,
                        sourceVerificationGuidance: reportedStatus === "reported_available_check_source"
                            ? "This headline suggests availability, not an absence. Open the original publisher or official club statement and confirm the named player, date, and exact fixture before marking available."
                            : "Open the original publisher page and confirm the named player, club, publication date, and exact fixture before treating this as current availability.",
                        ...freshness,
                        fixtureRelevance: evidence.fixtureRelevance,
                        evidenceAssessment: reportedStatus === "reported_unavailable"
                            ? "reported_unavailable_check_original_source"
                            : reportedStatus === "reported_available_check_source"
                                ? "reported_available_check_original_source"
                                : "reported_doubtful_or_test_pending",
                        extractionMethod: "literal_headline_phrase"
                    }];
                });
            });
        });
        // Deduplicate syndicated mentions, including surname-only vs full-name versions.
        // Keep the strongest evidence record: direct-fixture context first, then newest dated publication.
        const uniqueCandidateReports = [];
        const samePlayerMention = (left, right) => {
            const a = normalizeTeamName(left);
            const b = normalizeTeamName(right);
            return a === b || a.endsWith(" " + b) || b.endsWith(" " + a);
        };
        const evidenceStrength = report => {
            const relevance = report.fixtureRelevance === "direct_fixture" ? 100
                : report.fixtureRelevance === "team_news_other_fixture_or_opponent_context" ? 10 : 0;
            const timestamp = report.publishedAt ? new Date(report.publishedAt).getTime() : 0;
            return relevance + (Number.isFinite(timestamp) ? timestamp / 1e13 : 0);
        };
        for (const report of candidateReports) {
            const duplicateIndex = uniqueCandidateReports.findIndex(existing =>
                normalizeTeamName(existing.team) === normalizeTeamName(report.team) &&
                existing.reportedStatus === report.reportedStatus &&
                samePlayerMention(existing.player, report.player));
            if (duplicateIndex < 0) {
                uniqueCandidateReports.push(report);
                continue;
            }
            const existing = uniqueCandidateReports[duplicateIndex];
            const existingIsFullerName = normalizeTeamName(existing.player).split(" ").length >
                normalizeTeamName(report.player).split(" ").length;
            const reportIsFullerName = normalizeTeamName(report.player).split(" ").length >
                normalizeTeamName(existing.player).split(" ").length;
            const preferred = evidenceStrength(report) > evidenceStrength(existing) ? report : existing;
            const name = reportIsFullerName ? report.player : existingIsFullerName ? existing.player : preferred.player;
            uniqueCandidateReports[duplicateIndex] = {
                ...preferred,
                player: name,
                duplicateEvidenceCount: Number(existing.duplicateEvidenceCount || 1) + 1,
                evidenceVerification: {
                    status: "unverified_publication_lead",
                    originalSourceOpened: false,
                    playerClubIndependentlyVerified: false,
                    exactFixtureAvailabilityVerified: false,
                    headlineOnly: true
                }
            };
        }
        candidateReports = uniqueCandidateReports.map(report => ({
            ...report,
            evidenceVerification: report.evidenceVerification || {
                status: "unverified_publication_lead",
                originalSourceOpened: false,
                playerClubIndependentlyVerified: false,
                exactFixtureAvailabilityVerified: false,
                headlineOnly: true
            },
            fixtureRelevanceGuidance: report.fixtureRelevance === "direct_fixture"
                ? "Both requested teams appear in the headline; still verify the original source and player status."
                : report.fixtureRelevance === "team_news_other_fixture_or_opponent_context"
                    ? "Background or other-fixture context only; does not establish availability for this fixture."
                    : "Team-background headline only; does not establish availability for this fixture."
        }));
        if (candidateReports.length) extractionStatus = "literal_headline_candidates";
        if (articles.length && (process.env.GROQ_API_KEY || process.env.OPENAI_API_KEY)) {
            const systemInstruction = "You extract possible player-absence reports from supplied football publication evidence. Return only valid JSON with a top-level reports array. Each report must contain playerNameAsWritten, team, reportedStatus, reasonAsWritten, and evidenceId. reportedStatus must be one of reported_unavailable, doubtful_or_test_pending, or availability_not_established. Never invent players, expand a surname into a full name, infer an injury, or use outside knowledge. playerNameAsWritten must be a literal player name or surname appearing in that article title/snippet. Only report a player if the evidence text names them. Do not treat a generic team injury headline as proof that every named player is absent. Team must be exactly one of the two supplied teams. If no player is named, return an empty reports array.";
            const userContent = "Fixture: " + homeTeam + " vs " + awayTeam +
                "\nTeams allowed: " + JSON.stringify([homeTeam, awayTeam]) +
                "\nPublication evidence (search leads, not official confirmation):\n" + JSON.stringify(articles);
            try {
                const aiResult = await requestAbsenteeAIAnswer(systemInstruction, userContent);
                aiModel = aiResult.model;
                aiProvider = aiResult.provider;
                const answerText = aiResult.answer.trim();
                const firstBrace = answerText.indexOf("{");
                const lastBrace = answerText.lastIndexOf("}");
                if (firstBrace < 0 || lastBrace < firstBrace) throw new Error("AI response did not contain a JSON object.");
                const parsed = JSON.parse(answerText.slice(firstBrace, lastBrace + 1));
                const allowedTeams = [homeTeam, awayTeam];
                const aiCandidateReports = (Array.isArray(parsed.reports) ? parsed.reports : []).slice(0, 30).flatMap(report => {
                    const evidence = articles.find(item => item.evidenceId === String(report.evidenceId || ""));
                    const player = String(report.playerNameAsWritten || "").trim().slice(0, 100);
                    const team = allowedTeams.find(name => name.toLowerCase() === String(report.team || "").trim().toLowerCase());
                    if (!evidence || !player || !team) return [];
                    const evidenceText = evidence.title + " " + evidence.snippet;
                    const subjectMarker = /\b(?:vs?\.?|versus|against|ahead of|before|after|following|trip to|clash with|meeting with|showdown with|tie with|game against|match against|game with|match with)\b/i;
                    const subjectEnd = evidence.title.search(subjectMarker);
                    const articleSubject = (subjectEnd >= 0 ? evidence.title.slice(0, subjectEnd) : evidence.title).toLowerCase();
                    // Do not assign a player to a team mentioned only as the opponent or in a different fixture.
                    if (!evidenceText.toLowerCase().includes(player.toLowerCase()) ||
                        !articleSubject.includes(team.toLowerCase())) return [];
                    // Status comes from deterministic wording checks, not AI inference.
                    const reportedStatus = evidence.availabilityAssessment === "reported_unavailable_check_original_source"
                        ? "reported_unavailable"
                        : evidence.availabilityAssessment === "reported_doubtful_or_test_pending"
                            ? "doubtful_or_test_pending"
                            : "availability_not_established";
                    return [{
                        player,
                        team,
                        reportedStatus,
                        reason: String(report.reasonAsWritten || "").slice(0, 220),
                        evidenceId: evidence.evidenceId,
                        title: evidence.title,
                        source: evidence.source,
                        publishedAt: evidence.publishedAt,
                        url: evidence.url,
                        fixtureRelevance: evidence.fixtureRelevance,
                        evidenceAssessment: evidence.availabilityAssessment
                    }];
                });
                // Prefer validated AI candidates when present; otherwise retain
                // the deterministic literal-headline candidates created above.
                if (aiCandidateReports.length) candidateReports = aiCandidateReports;
                extractionStatus = aiCandidateReports.length ? "ai_extracted_candidates" : "literal_fallback_no_ai_candidates";
            } catch (error) {
                // Do not fail the whole absentee endpoint if AI is rate-limited; return publication evidence only.
                console.warn("Absentee extraction fell back to evidence-only mode:", String(error.message || error).slice(0, 180));
            }
        }

        // Official club websites are the only accepted evidence for absentee reports.
        // If a club has not published a relevant update, do not fill the gap with
        // secondary publications or unverified AI inference.
        const isOfficialEvidenceReport = report => {
            if (report.officialPublisherDomainMatch === true || report.sourceTrustTier === "official_club_website") return true;
            const evidence = articles.find(item => item.evidenceId === report.evidenceId);
            return !!(evidence && (evidence.officialClubSource === true || evidence.sourceTrustTier === "official_club_website"));
        };
        const normalizedPlayerText = value => normalizeTeamName(String(value || "").replace(/[^A-Za-z0-9'’ -]/g, " "));
        const hasIndependentCorroboration = report => {
            const playerKey = normalizedPlayerText(report.player);
            const teamKey = normalizeTeamName(report.team);
            if (!playerKey || !teamKey) return false;
            const reportSource = String(report.source || "").toLowerCase();
            const reportHost = (() => { try { return new URL(report.url).hostname.toLowerCase(); } catch (_) { return ""; } })();
            return articles.some(other => {
                if (other.evidenceId === report.evidenceId) return false;
                const otherText = String(other.title || "") + " " + String(other.snippet || "");
                if (!normalizedPlayerText(otherText).includes(playerKey)) return false;
                if (!normalizeTeamName(otherText).includes(teamKey)) return false;
                const otherSource = String(other.source || "").toLowerCase();
                if (!otherSource || otherSource === reportSource) return false;
                const otherHost = (() => { try { return new URL(other.url).hostname.toLowerCase(); } catch (_) { return ""; } })();
                if (reportHost && otherHost && reportHost === otherHost) return false;
                if (/news\.google\.com/i.test(String(other.url || ""))) return false;
                const assessment = other.availabilityAssessment || "availability_not_established";
                return report.reportedStatus === "reported_unavailable"
                    ? assessment === "reported_unavailable_check_original_source"
                    : report.reportedStatus === "doubtful_or_test_pending"
                        ? assessment === "reported_doubtful_or_test_pending"
                        : false;
            });
        };
        const reportCountBeforeSourcePolicy = candidateReports.length;
        candidateReports = candidateReports.filter(isOfficialEvidenceReport);
        const nonOfficialReportsSuppressed = reportCountBeforeSourcePolicy - candidateReports.length;

        // Resolve Google News wrapper URLs to their publisher destination when possible.
        // A resolved destination is NOT proof that the article confirms player availability.
        const googleNewsUrls = [...new Set(candidateReports
            .map(report => report.url)
            .filter(url => {
                try {
                    const host = new URL(url).hostname.toLowerCase();
                    return (host === "news.google.com" || host.endsWith(".news.google.com"));
                } catch (_) {
                    return false;
                }
            }))].slice(0, 8);
        const resolvedPublisherUrls = new Map();
        const resolverDiagnostics = { googleNewsUrlCount: googleNewsUrls.length, pageFetchSuccessCount: 0, pageFetchNonOkStatuses: [], pageFetchMissingUrlCount: 0, directRedirectCount: 0, signatureExtractedCount: 0, signatureMissingCount: 0, pageFetchErrorCount: 0, pageFetchErrorKinds: [], rpcAttempted: false, rpcHttpStatus: null, rpcErrorKind: null, rpcResponseLength: 0, rpcRowsParsed: 0, rpcAcceptedRows: 0, publisherDestinationsExtracted: 0, resolvedPublisherUrlCount: 0 };

        // Google News no longer reliably redirects RSS article links to publishers.
        // Its current flow requires a per-article signature followed by one batched
        // garturlreq RPC. Keep this bounded and optional: unresolved links remain intact.
        const signatureResults = await Promise.all(googleNewsUrls.map(async originalUrl => {
            try {
                // RSS article links can return feed-style responses without the
                // signed article-page metadata. Use the normal article page for
                // signature extraction, retaining originalUrl as the report key.
                const lookupUrl = new URL(originalUrl);
                if (lookupUrl.pathname.startsWith("/rss/articles/")) {
                    lookupUrl.pathname = lookupUrl.pathname.replace("/rss/articles/", "/articles/");
                }
                lookupUrl.search = "";
                const response = await fetch(lookupUrl.href, {
                    method: "GET",
                    redirect: "follow",
                    headers: {
                        "Accept": "text/html,application/xhtml+xml",
                        "Accept-Language": "en-US,en;q=0.9",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
                        "Cookie": "SOCS=CAISNQgQEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNjE4LjA2X3AwGgJlbiADGgYIgOCvswY"
                    },
                    signal: AbortSignal.timeout(4500)
                });
                const html = await response.text();
                if (!response.ok) {
                    resolverDiagnostics.pageFetchNonOkStatuses.push(response.status);
                    return null;
                }
                if (!response.url) {
                    resolverDiagnostics.pageFetchMissingUrlCount += 1;
                    return null;
                }
                resolverDiagnostics.pageFetchSuccessCount += 1;
                // Some Google News article links still redirect directly to the publisher.
                // Capture that final URL instead of discarding it before signature parsing.
                const finalHost = new URL(response.url).hostname.toLowerCase();
                if (finalHost !== "news.google.com" && !finalHost.endsWith(".news.google.com")) {
                    resolverDiagnostics.directRedirectCount += 1;
                    return { originalUrl, directDestination: response.url };
                }
                const signature = (html.match(/data-n-a-sg="([^"]+)"/) || [])[1];
                const timestamp = (html.match(/data-n-a-ts="([^"]+)"/) || [])[1];
                const pathname = lookupUrl.pathname;
                const marker = "/articles/";
                const markerIndex = pathname.indexOf(marker);
                const articleId = markerIndex >= 0 ? pathname.slice(markerIndex + marker.length) : "";
                if (!signature || !timestamp || !articleId || !/^\d+$/.test(timestamp)) {
                    resolverDiagnostics.signatureMissingCount += 1;
                    return null;
                }
                resolverDiagnostics.signatureExtractedCount += 1;
                return { originalUrl, articleId, signature, timestamp: Number(timestamp) };
            } catch (error) {
                resolverDiagnostics.pageFetchErrorCount += 1;
                const kind = String(error && (error.cause && error.cause.code || error.name || error.message) || "unknown").slice(0, 100);
                if (!resolverDiagnostics.pageFetchErrorKinds.includes(kind)) resolverDiagnostics.pageFetchErrorKinds.push(kind);
                return null;
            }
        }));

        for (const item of signatureResults.filter(item => item && item.directDestination)) {
            try {
                const destinationHost = new URL(item.directDestination).hostname.toLowerCase();
                if (destinationHost !== "news.google.com" && !destinationHost.endsWith(".news.google.com")) {
                    resolvedPublisherUrls.set(item.originalUrl, item.directDestination);
                    resolverDiagnostics.publisherDestinationsExtracted += 1;
                }
            } catch (_) {}
        }
        const validSignatures = signatureResults.filter(item => item && item.articleId && item.signature && Number.isFinite(item.timestamp));
        if (validSignatures.length) {
            try {
                resolverDiagnostics.rpcAttempted = true;
                const rpcEntries = validSignatures.map((item, index) => {
                    const inner = [
                        "garturlreq",
                        [
                            ["X", "X", ["X", "X"], null, null, 1, 1, "GB:en", null, 1,
                                null, null, null, null, null, 0, 1],
                            "X", "X", 1, [1, 1, 1], 1, 1, null, 0, 0, null, 0
                        ],
                        item.articleId,
                        item.timestamp,
                        item.signature
                    ];
                    return ["Fbv4je", JSON.stringify(inner), null, "g" + index];
                });
                const rpcBody = "f.req=" + encodeURIComponent(JSON.stringify([rpcEntries]));
                const rpcResponse = await fetch("https://news.google.com/_/DotsSplashUi/data/batchexecute", {
                    method: "POST",
                    headers: {
                        "Accept": "*/*",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
                        "Cookie": "SOCS=CAISNQgQEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNjE4LjA2X3AwGgJlbiADGgYIgOCvswY"
                    },
                    body: rpcBody,
                    signal: AbortSignal.timeout(6000)
                });
                resolverDiagnostics.rpcHttpStatus = rpcResponse.status;
                if (rpcResponse.ok) {
                    let rpcText = (await rpcResponse.text()).replace(/^\)\]\}'\n?/, "").trim();
                    resolverDiagnostics.rpcResponseLength = rpcText.length;
                    const firstLine = rpcText.split("\n").find(line => line.trim().startsWith("["));
                    if (firstLine) rpcText = firstLine;
                    let rpcRows = [];
                    try { rpcRows = JSON.parse(rpcText); } catch (_) {}
                    resolverDiagnostics.rpcRowsParsed = Array.isArray(rpcRows) ? rpcRows.length : 0;
                    let fallbackResponseIndex = 0;
                    for (const row of rpcRows) {
                        if (!Array.isArray(row) || row[0] !== "wrb.fr" || row[1] !== "Fbv4je") continue;
                        resolverDiagnostics.rpcAcceptedRows += 1;
                        try {
                            const payload = JSON.parse(row[2]);
                            const destination = Array.isArray(payload) && payload[0] === "garturlres" ? payload[1] : null;
                            // Google may return a generic response label instead of the request
                            // tag (g0, g1...). In that case, batchexecute preserves entry order.
                            const sequence = row[6];
                            const taggedItem = validSignatures.find((candidate, index) => "g" + index === sequence);
                            const item = taggedItem || validSignatures[fallbackResponseIndex];
                            fallbackResponseIndex += 1;
                            if (item && typeof destination === "string" && /^https?:\/\//i.test(destination)) {
                                const destinationHost = new URL(destination).hostname.toLowerCase();
                                if (destinationHost !== "news.google.com" && !destinationHost.endsWith(".news.google.com")) {
                                    resolvedPublisherUrls.set(item.originalUrl, destination);
                                    resolverDiagnostics.publisherDestinationsExtracted += 1;
                                }
                            }
                        } catch (_) {}
                    }
                }
            } catch (error) {
                resolverDiagnostics.rpcErrorKind = String(error && (error.cause && error.cause.code || error.name || error.message) || "unknown").slice(0, 100);
                // Google may rate-limit or change the RPC; preserve the original RSS URL.
            }
        }
        resolverDiagnostics.resolvedPublisherUrlCount = resolvedPublisherUrls.size;
        candidateReports = candidateReports.map(report => {
            const publisherUrl = resolvedPublisherUrls.get(report.url);
            if (!publisherUrl) return report;
            return {
                ...report,
                url: publisherUrl,
                originalPublisherUrlResolved: true,
                originalSourceUrlVerified: false,
                sourceLinkType: "resolved_original_publisher_link_not_content_verified",
                sourceVerificationGuidance: "The original publisher URL was resolved automatically, but the article content and player availability are still unverified. Open the article and confirm the named player, club, publication date, and exact fixture.",
                evidenceVerification: {
                    ...(report.evidenceVerification || {}),
                    status: "unverified_publication_lead",
                    originalSourceOpened: false,
                    originalPublisherUrlResolved: true,
                    playerClubIndependentlyVerified: false,
                    exactFixtureAvailabilityVerified: false,
                    headlineOnly: true
                }
            };
        });
        const result = {
            status: candidateReports.length ? "candidate_reports_found" : (articles.length ? "no_named_absentees_established" : "no_relevant_publication_evidence"),
            fixture: { home: homeTeam, away: awayTeam },
            generatedAt: new Date().toISOString(),
            source: newsData.source || "selected football publication feeds",
            providersAttempted: newsData.providersAttempted || [],
            providerErrors: newsData.providerErrors || [],
            providerFeedDiagnostics: newsData.providerFeedDiagnostics || [],
            publisherLinkResolutionDiagnostics: newsData.publisherLinkResolutionDiagnostics || null,
            sourceAgreementDiagnostics: {
                policy: "official_club_websites_only",
                nonOfficialArticlesIgnored,
                nonOfficialReportsSuppressed
            },
            resolverDiagnostics,
            articleCount: articles.length,
            extractionStatus,
            aiModel,
            aiProvider,
            reports: candidateReports,
            evidence: articles,
            importantNotice: "These are publication-based candidate reports, not official team-sheet confirmation. Player names are returned only when literally present in the supplied article title/snippet. A report marked unavailable or doubtful must be checked against the original article, exact match date, and official club/league update. No prediction probabilities are changed by this endpoint."
        };
        absenteeReportCache.set(cacheKey, { expiresAt: Date.now() + ABSENTEE_REPORT_CACHE_TTL_MS, data: result });
        const publicResult = {
            ...result,
            reports: result.reports.map(report => ({
                ...report,
                url: null,
                sourceLabel: report.officialPublisherDomainMatch
                    ? "Football Genie • Official club source"
                    : "Football Genie • Football publication",
                sourceLinkHidden: true
            })),
            evidence: result.evidence.map(item => ({
                ...item,
                url: null,
                sourceLabel: item.officialClubSource
                    ? "Football Genie • Official club source"
                    : "Football Genie • Football publication",
                sourceLinkHidden: true
            })),
            sourcePolicy: {
                acceptedForAbsenteeClaims: "official_club_websites_only",
                secondaryPublicationsUsedForAbsenteeClaims: false,
                userFacingSource: "Football Genie",
                outboundPublisherLinksShown: false
            },
            importantNotice: "Football Genie uses official club website evidence only for player-availability reports. If no relevant official update is found, no absentee claim is made; secondary publications and unverified search leads are not used to fill the gap. Official articles still require relevance and date checks. No prediction probabilities are changed by this endpoint."
        };
        absenteeReportCache.set(cacheKey, { expiresAt: Date.now() + ABSENTEE_REPORT_CACHE_TTL_MS, data: publicResult });
        return res.json(publicResult);
    } catch (error) {
        console.error("Absentee intelligence request failed:", String(error.message || error).slice(0, 220));
        return res.status(502).json({
            status: "absentee_intelligence_unavailable",
            error: "Football Genie could not prepare the absentee report. No player availability has been guessed."
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
