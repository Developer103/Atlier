// chunk: evasion/math_charcode
// depends: (none)
// provides: _d
// format: jscript
// note: Arithmetic offset decode. First element is the key, remaining elements
//       are shifted char codes. Different key per string breaks static patterns.

function _d(arr) {
    var s = "";
    var key = arr[0];
    for (var i = 1; i < arr.length; i++) s += String.fromCharCode(arr[i] + key);
    return s;
}
