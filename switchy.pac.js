/*
https://apple.stackexchange.com/questions/396677/catalina-safari-proxy-automatic-configuration-pac-is-not-used
Safari can't be configured with file:// PAC files. You need to serve it from a web server.
https://raw.githubusercontent.com/dvershinin/switchy-rules/main/switchy.pac.js
 */
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.gosuslugi.ru")) {
        // Gosuslugi works fine without proxy, and it is defunct when using proxy
        return "DIRECT";
    }
    if (shExpMatch(host, "*.ru") || shExpMatch(host, "ipinfo.io") || shExpMatch(host, "premier.one")) {
        return 'SOCKS5 127.0.0.1:1080;SOCKS 127.0.0.1:1080';
    }
    return "DIRECT";
}
