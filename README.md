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

#### Countries

When located in the country listed, use its rule list in order to gain informative decision about using restricted 
websites in that country.

Requests to restricted websites will be routed through your proxy.

* Russia: `https://raw.githubusercontent.com/dvershinin/switchy-rules/main/russia.txt`. 

## Caveats

Making use of proxy profile in Chrome may not be sufficient. If your DNS servers are censoring (e.g. Yandex DNS), you 
might be making your proxy connecting to the censor's IP addresses. For these reasons, do one of the following:

* reliable: make sure the proxy connections resolve DNS via proxy, instead of directly. This can be done by simply 
using a SOCKS 5 proxy
* less reliable: configure your entire system to use independent DNS that is non-blocking, e.g. 
Google DNS or Cloudflare. However, note that the latter will likely have point of presence in your country, so even 
using `1.1.1.1` will use a server in your country, and thus enforce blocking set out by the government.

