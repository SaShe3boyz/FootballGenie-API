const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;
const API_TOKEN = process.env.FOOTBALL_DATA_API_TOKEN;

app.use(express.json());

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
error: "Football data API token is not configured on the server."
});
}

try {
const response = await fetch(
"https://api.football-data.org/v4/competitions",
{
headers: {
"X-Auth-Token": API_TOKEN
}
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
console.error("Football data request failed:", error.message);

res.status(502).json({
  error: "Unable to retrieve football competitions."
});

}
});

app.get("/api/matches", async (req, res) => {
if (!API_TOKEN) {
return res.status(500).json({
error: "Football data API token is not configured on the server."
});
}

const dateFrom = req.query.dateFrom;
const dateTo = req.query.dateTo;

if (
(dateFrom && !/^\d{4}-\d{2}-\d{2}$/.test(dateFrom)) ||
(dateTo && !/^\d{4}-\d{2}-\d{2}$/.test(dateTo))
) {
return res.status(400).json({
error: "Dates must use YYYY-MM-DD format."
});
}

const params = new URLSearchParams();

if (dateFrom) params.set("dateFrom", dateFrom);
if (dateTo) params.set("dateTo", dateTo);

const query = params.toString();
const url = "https://api.football-data.org/v4/matches" +
(query ? "?${query}" : "");

try {
const response = await fetch(url, {
headers: {
"X-Auth-Token": API_TOKEN
}
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
console.error("Football match request failed:", error.message);

res.status(502).json({
  error: "Unable to retrieve football matches."
});

}
});

app.listen(PORT, "0.0.0.0", () => {
console.log("Football Genie API listening on port ${PORT}");
});
