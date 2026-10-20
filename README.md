# Football Genie API

Secure backend for Football Genie Android.

## Runtime configuration

- `FOOTBALL_DATA_API_TOKEN`: required for football-data.org fixtures and team statistics.
- `OPENAI_API_KEY`: optional but required to enable the cloud conversational analyst at `POST /api/ai/analyze`. Add it as a private environment variable in the Render service dashboard. Never commit this key to GitHub or place it inside the Android APK.
- `OPENAI_MODEL`: optional model override; defaults to `gpt-4o-mini`.
- `PORT`: supplied by the hosting platform.

The cloud analyst receives the user's question and the app's current match names, expected-goal inputs, and displayed probabilities. It is instructed to distinguish model estimates from verified data and not invent live injuries, line-ups, shots, possession, or match events. If `OPENAI_API_KEY` is absent, the endpoint returns `503` with code `AI_NOT_CONFIGURED`; the Android app then uses its on-device fallback analyst.

## Endpoints

- `GET /`: service health.
- `GET /api/competitions`: available competitions.
- `GET /api/matches`: fixture/results feed.
- `GET /api/competition-strength?competitionId=<id>`: home/away competition and team strength baselines.
- `GET /api/team-stats?teamId=<id>&limit=10`: recent finished matches and team form.
- `POST /api/ai/analyze`: evidence-grounded conversational match analysis.

The service keeps provider credentials on the server. Model probabilities remain estimates and should not be treated as guarantees.
