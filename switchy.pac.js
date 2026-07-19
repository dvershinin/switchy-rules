/*
https://apple.stackexchange.com/questions/396677/catalina-safari-proxy-automatic-configuration-pac-is-not-used
Safari can't be configured with file:// PAC files. You need to serve it from a web server.
https://raw.githubusercontent.com/dvershinin/switchy-rules/main/switchy.pac.js

Proxy routing strategy:
  - 127.0.0.1:1080  -> SSH tunnel to a Russia exit (for .ru / .рф / Russian-geofenced sites)
  - 127.0.0.1:2408  -> Cloudflare WARP via usque (default everywhere else, with DIRECT fallback)

"SOCKS5 ...; DIRECT" fallback means: when the local SOCKS5 isn't listening
(e.g. you stopped usque / closed the SSH tunnel), clients transparently go
DIRECT instead of erroring. So toggling a proxy on/off = start/stop the
corresponding local process. Russia rule intentionally omits the DIRECT
fallback to avoid leaking unproxied requests to Russian-geofenced sites.

CAVEAT — not every client honors "; DIRECT". Docker Desktop ships its own
Go-Chromium PAC handler which only attempts the first proxy in the chain;
when usque is down, it RSTs the TLS handshake instead of falling back to
DIRECT. That kills both Docker Desktop's own startup (Electron network
service fails TLS during launch and the backend loops on "unmarshaling
start request: unexpected EOF") and any container's HTTPS egress (OpenAI
embeddings → SSLEOFError: UNEXPECTED_EOF_WHILE_READING). To keep the
Docker stack and LLM-API egress resilient to a dead usque, there is an
explicit DIRECT bypass block below for Docker + OpenAI + Anthropic hosts.

Private hosts / own infra should be added to the system proxy bypass list
via `networksetup -setproxybypassdomains`, not this PAC — that keeps
personal hostnames out of this public repo.
 */
function FindProxyForURL(url, host) {
    // ГИС ЖКХ (dom.gosuslugi.ru) is on a geofenced Rostelecom range,
    // unreachable from some networks — force it through the Russian proxy.
    // Must come before the generic gosuslugi.ru DIRECT rule below.
    if (shExpMatch(host, "dom.gosuslugi.ru") ||
        shExpMatch(host, "*.dom.gosuslugi.ru")) {
        return 'SOCKS5 127.0.0.1:1080;SOCKS 127.0.0.1:1080';
    }
    // Gosuslugi works fine without a proxy, and it is defunct when using proxy
    if (shExpMatch(host, "gosuslugi.ru") ||
        shExpMatch(host, "*.gosuslugi.ru")) {
        return "DIRECT";
    }
    // VK video works from any location
    if (shExpMatch(host, "vkvideo.ru") ||
        shExpMatch(host, "*.vkvideo.ru")) {
        return "DIRECT";
    }
    // VK main works from any location
    if (shExpMatch(host, "vk.com") || shExpMatch(host, "vk.ru") ||
        shExpMatch(host, "*.vk.com") || shExpMatch(host, "*.vk.ru")) {
        return "DIRECT";
    }
    // Google also works fine without a proxy, and working for corporate US company, requires no Russian VPN
    if (shExpMatch(host, "google.ru") ||
        shExpMatch(host, "*.google.ru")) {
        return "DIRECT";
    }
    // Lenta.Ru does not require a Russian proxy
    if (shExpMatch(host, "lenta.ru") ||
        shExpMatch(host, "*.lenta.ru")) {
        return "DIRECT";
    }
    // ------------------------------------------------------------------
    // DIRECT bypass for clients with a broken PAC fallback.
    //
    // The default rule at the bottom returns 'SOCKS5 127.0.0.1:2408; DIRECT'.
    // macOS / Safari / Chrome / curl honor the '; DIRECT' tail when usque
    // (Cloudflare WARP SOCKS5 on 127.0.0.1:2408) is not listening. Docker
    // Desktop's bundled Go-Chromium PAC engine does NOT — it only tries
    // the first proxy in the chain, hits the dead 2408, and RSTs the TLS
    // handshake. Observed real-world breakage when usque is down:
    //   1. Docker Desktop itself fails to launch. Its Electron UI's network
    //      service evaluates this PAC at startup, the TLS handshake to
    //      hub.docker.com / api.docker.com fails, and the backend loops on
    //      "unmarshaling start request: unexpected EOF" in
    //      ~/Library/Containers/com.docker.docker/Data/log/host/com.docker.backend.log.
    //   2. Any running container's outbound HTTPS fails the same way —
    //      e.g. Brain's OpenAI embeddings call dies with
    //      SSLEOFError: UNEXPECTED_EOF_WHILE_READING.
    //
    // Why not just flip the default catch-all to DIRECT? Because we want
    // every other host to keep using WARP egress automatically as soon as
    // usque is healthy again, without needing to flip the PAC back. The
    // '; DIRECT' tail does the right thing for every client that respects
    // it; this block exists only for the clients that don't.
    //
    // Why not set HTTPS_PROXY / NO_PROXY inside containers? Docker
    // Desktop's egress is intercepted at the VPNKit layer on the host,
    // long before container env vars come into play. The host-side PAC is
    // the only lever.
    //
    // Keep this list minimal — only hosts that actually break under
    // dead-usque. Adding more hosts here silently removes them from WARP
    // when usque is up, which is usually not what we want.
    // ------------------------------------------------------------------
    if (shExpMatch(host, "api.docker.com") ||
        shExpMatch(host, "hub.docker.com") ||
        shExpMatch(host, "registry-1.docker.io") ||
        shExpMatch(host, "*.docker.io") ||
        shExpMatch(host, "production.cloudflare.docker.com") ||
        shExpMatch(host, "*.cloudflare.docker.com") ||
        shExpMatch(host, "api.openai.com") ||
        shExpMatch(host, "*.openai.com") ||
        shExpMatch(host, "api.anthropic.com")) {
        return "DIRECT";
    }
    // Apple Notarization / OCSP / CRL / CloudKit must bypass usque too.
    // When these endpoints are unreachable, trustd/syspolicyd's cached
    // Notarization tickets for Developer-ID-signed apps expire and aren't
    // refreshed. The kernel-level AMFI then applies a stricter sandbox to
    // affected bundles. Observed symptom (2026-05-16): Docker Desktop
    // 4.66.0 launched fine for days while usque was healthy, then began
    // crashing with the same "unmarshaling start request: unexpected EOF"
    // signature after a transient WARP outage poisoned the Notarization
    // cache. Bypass these so trustd can always reach Apple directly.
    if (shExpMatch(host, "ocsp.apple.com") ||
        shExpMatch(host, "ocsp2.apple.com") ||
        shExpMatch(host, "ocsp.digicert.com") ||
        shExpMatch(host, "crl.apple.com") ||
        shExpMatch(host, "crl3.digicert.com") ||
        shExpMatch(host, "crl4.digicert.com") ||
        shExpMatch(host, "api.apple-cloudkit.com") ||
        shExpMatch(host, "*.apple-cloudkit.com") ||
        shExpMatch(host, "ax.itunes.apple.com") ||
        shExpMatch(host, "gs.apple.com") ||
        shExpMatch(host, "valid.apple.com")) {
        return "DIRECT";
    }
    // Shopee Indonesia anti-bot flags the WARP/Singapore exit as a crawler
    // (endless "Verify to Continue" whose captcha API itself refuses to load,
    // scene=crawler_item). Serve it from the real local ISP IP like the
    // phone app does. shopeemobile.com hosts the JS/assets/captcha bundles.
    if (shExpMatch(host, "shopee.co.id") ||
        shExpMatch(host, "*.shopee.co.id") ||
        shExpMatch(host, "*.shopeemobile.com") ||
        shExpMatch(host, "*.shopee.io")) {
        return "DIRECT";
    }
    // All other .ru and .рф domains and some specific domains go through the Russian proxy
    if (shExpMatch(host, "*.ru") ||
        shExpMatch(host, "*.xn--p1ai") ||
        shExpMatch(host, "ipinfo.io") ||
        shExpMatch(host, "premier.one") ||
        shExpMatch(host, "*.yandex.net")) {
        return 'SOCKS5 127.0.0.1:1080;SOCKS 127.0.0.1:1080';
    }
    // Default: Cloudflare WARP via usque, fall back to DIRECT if usque is off
    return 'SOCKS5 127.0.0.1:2408; DIRECT';
}
