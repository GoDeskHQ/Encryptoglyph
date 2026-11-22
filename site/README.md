# Encryptoglyph public marketing site

Static HTML, CSS, JavaScript, and an original SVG mark. No build step, external fonts,
analytics, credentials, or runtime API. The only stored value is the browser's theme
preference. System color scheme is honored until a visitor picks a theme; reduced
motion disables animation and smooth scrolling. Without JavaScript, the page and
repository links work and CSS follows the system theme.

## Preview and checks

From the repository root:

```sh
python -m http.server 8080 --bind 127.0.0.1 --directory site
node --test site/check.test.cjs
```

Open `http://127.0.0.1:8080`. Check light/dark themes and a narrow viewport.
The local preview is for this static folder only.

## Production path: Coolify with Traefik

The intended public hostname is **encryptoglyph.godesk.io**. This repository does
not assert that it is live. Deployment, DNS, and certificate provisioning are
separate operator actions and were not performed as part of adding this site.

Create a separate Dockerfile application in Coolify from the desired Git revision:

- Base/build directory: `/site`; Dockerfile: `/Dockerfile` relative to that directory.
- Container port: `80`. Set the domain to `https://encryptoglyph.godesk.io`.
- Let Coolify's Traefik proxy route the hostname and terminate TLS. The proxy must
  reach the application container on its managed Docker network. No additional
  published host port is required.
- No environment variables, secrets, volumes, backend services, or console routes
  are needed. Do not use the repository's API/console compose stack for this page.
- Verify the application settings use only `site/` as the Docker build context.

Equivalent image build (does not deploy or start a container):

```sh
docker build -t encryptoglyph-site:local site
```

The explicit image allowlist copies only the four public assets. Nginx serves
static files on port 80, rejects unknown paths with 404, and applies a restrictive
content security policy. The container healthcheck requests `/` internally.
After a separately authorized deployment, verify HTTPS, both repository links,
theme persistence, health, and 404 responses for `/console/` and `/v1/`.
