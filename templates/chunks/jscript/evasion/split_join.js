// chunk: evasion/split_join
// depends: (none)
// provides: _d
// format: jscript
// note: XOR-based string decode with key 0x55, producing different static
//       byte patterns than plain charcode decoding.

function _d(arr) {
    var s = "";
    for (var i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i] ^ 0x55);
    return s;
}
