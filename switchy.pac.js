function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.ru") || shExpMatch(host, "ipinfo.io")) {
        return "SOCKS5 127.0.0.1:1080";
    }
    return "DIRECT";
}
