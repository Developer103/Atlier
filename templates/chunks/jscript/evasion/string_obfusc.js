// chunk: evasion/string_obfusc
// depends: (none)
// provides: _d
// format: jscript

function _d(arr) {
    var s = "";
    for (var i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return s;
}
