# switchy-rules

[Switchy](https://code.google.com/archive/p/switchy/wikis/RuleList.wiki) rule lists for Internet freedom.

Allow circumventing government censorship as well as sanctions imposed by external entities, without having to switch
a proxy manually.

Consumable by Chrome extensions like
[SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif?hl=en).

## How to use

### Install SwitchyOmega

Open Chrome browser, and proceed to install
[Switchy Omega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif?hl=en)
extension.

### Set up a proxy profile

First, you must have your own proxy. We do not provide a proxy, VPN.
We highly recommend a *SOCKS 5* proxy (see why in "Caveats" section).

In the extension settings for SwitchyOmega, set up a proxy profile (using a proxy server of your own or found
elsewhere).

### Configuration

Create a switch profile, or using the default auto switch profile.
In the switch profile, proceed to "Rule List Config" and enter URLs below depending on the country of residence.

### Countries

When located in the country listed, use its rule list in order to gain informative decision about using restricted
websites in that country.

Requests to restricted websites will be routed through your proxy.

#### Inside Russia

Switchy rules: `https://raw.githubusercontent.com/dvershinin/switchy-rules/main/russia.txt`.

#### Inside Indonesia

The censorship system in Indonesia is based mostly on DNS.
The ISPs hijack DNS system in a way that port 53 is taken over by the providers.
No matter what DNS nameservers you set (Google, Cloudflare, or whatever), all requests to port 53 to anywhere, will go by Indonesia DNS censorship system.

This is most easiest to bypass in Chrome:

1. Select the three-dot menu in your browser > Settings.
2. Select Privacy and security > Security.
3. Scroll down and enable Use secure DNS.
4. Select the With option, and from the drop-down menu choose Cloudflare (1.1.1.1).

In this way, DNS requests do not go via 53 port, and are anonymous to the Indonesian DNS censorship.

## macOS System-Level PAC Proxy

This PAC file can also be used as a system-level proxy on macOS via:

    System Settings → Network → Wi-Fi → Details → Proxies → Automatic Proxy Configuration

Set the URL to:

    https://raw.githubusercontent.com/dvershinin/switchy-rules/refs/heads/main/switchy.pac.js?v=1

### Required: Apple Domain Bypass

On macOS 26 (Tahoe), sandboxed system daemons (`remindd`, `itunescloudd`,
`amsengagementd`, etc.) cannot access the PAC resolver service
(`com.apple.cfnetwork.cfnetworkagent`) due to a sandbox restriction. This
causes iCloud sync failures, Reminders hanging, and repeated daemon crashes.

To work around this, add Apple domains to the proxy bypass list so they skip
PAC evaluation entirely:

```bash
networksetup -setproxybypassdomains Wi-Fi \
  "*.local" "169.254/16" \
  "*.apple.com" "*.icloud.com" "*.icloud-content.com" \
  "*.mzstatic.com" "*.cdn-apple.com" "*.push.apple.com"
```

This is safe because the PAC file already returns `DIRECT` for Apple domains
(they are not `.ru`). The bypass simply prevents macOS from attempting PAC
resolution for these hosts, avoiding the sandbox denial.

## Caveats

Making use of proxy profile in Chrome may not be sufficient. If your DNS servers are censoring (e.g. Yandex DNS), you
might be making your proxy connecting to the censor's IP addresses. For these reasons, do one of the following:

* reliable: make sure the proxy connections resolve DNS via proxy, instead of directly. This can be done by simply
using a SOCKS 5 proxy
* less reliable: configure your entire system to use independent DNS that is non-blocking, e.g.
Google DNS or Cloudflare. However, note that the latter will likely have point of presence in your country, so even
using `1.1.1.1` will use a server in your country, and thus enforce blocking set out by the government.
