# VLESS-WS on Zerops

Single fixed user, stateless: UUID and subscription key are derived from the `SECRET_KEY` env var,
so restarts/redeploys never change the connection info.

## Deploy
1. Push this folder to a new GitHub repo.
2. Edit `buildFromGit` in `import.yaml`, then Zerops dashboard → Import project → paste `import.yaml`.
3. Open `https://<your-subdomain>/panel/<USER_UUID>` (or `/panel/<SECRET_KEY>`) to see the VLESS link, copy button and QR code; `/link/<key>` returns plain text,
   or use `/sub/<SECRET_KEY>` as a subscription URL.

## Env
| Var | Meaning |
|---|---|
| `SECRET_KEY` | required, min 16 chars; keep it private |
| `USER_UUID` | fixed user UUID (set in import.yaml) |
| `PUBLIC_DOMAIN` | optional, custom domain instead of the zerops subdomain |
| `REMARK` | config name |
