/*
https://apple.stackexchange.com/questions/396677/catalina-safari-proxy-automatic-configuration-pac-is-not-used
Safari can't be configured with file:// PAC files. You need to serve it from a web server.
https://raw.githubusercontent.com/dvershinin/switchy-rules/main/switchy.pac.js
 */
function FindProxyForURL(url, host) {
    // Gosuslugi works fine without a proxy, and it is defunct when using proxy
    if (shExpMatch(host, "gosuslugi.ru") ||
        shExpMatch(host, "*.gosuslugi.ru")) {
        return "DIRECT";
    }
    # VK video works from any location
    if (shExpMatch(host, "vkvideo.ru") ||
        shExpMatch(host, "*.vkvideo.ru")) {
        return "DIRECT";
    }
    # VK main works from any location
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
    // All other .ru domains and some specific domains go through the Russian proxy
    if (shExpMatch(host, "*.ru") ||
        shExpMatch(host, "ipinfo.io") ||
        shExpMatch(host, "premier.one") ||
        shExpMatch(host, "*.yandex.net")) {
        return 'SOCKS5 127.0.0.1:1080;SOCKS 127.0.0.1:1080';
    }
    return "DIRECT";
}
