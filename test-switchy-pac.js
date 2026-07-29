const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function shExpMatch(value, pattern) {
    const escaped = pattern
        .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*");
    return new RegExp(`^${escaped}$`).test(value);
}

const source = fs.readFileSync("switchy.pac.js", "utf8");
const sandbox = {shExpMatch};
vm.runInNewContext(source, sandbox);

const directHosts = [
    "wildberries.ru",
    "www.wildberries.ru",
    "wb.ru",
    "id.wb.ru",
    "wbbasket.ru",
    "static-basket-01.wbbasket.ru",
];

for (const host of directHosts) {
    assert.equal(
        sandbox.FindProxyForURL(`https://${host}/`, host),
        "DIRECT",
        `${host} must bypass the PAC proxy`,
    );
}

assert.equal(
    sandbox.FindProxyForURL("https://example.ru/", "example.ru"),
    "SOCKS5 127.0.0.1:1080;SOCKS 127.0.0.1:1080",
    "unrelated .ru traffic must retain the strict Russian SOCKS rule",
);
assert.equal(
    sandbox.FindProxyForURL("https://example.com/", "example.com"),
    "SOCKS5 127.0.0.1:2408; DIRECT",
    "unrelated non-.ru traffic must retain the WARP default",
);

console.log("switchy.pac.js routing tests passed");
