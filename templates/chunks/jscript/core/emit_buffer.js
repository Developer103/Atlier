// chunk: core/emit_buffer
// depends: (none)
// provides: emit, _buf
// format: jscript

var _buf = "";

function emit(s) {
    _buf += s;
}
