// chunk: commands/upload_file
// depends: core/file_ops
// provides: upload_file
// format: jscript

function upload_file(filePath, url) {
    try {
        var stream = new ActiveXObject("ADODB.Stream");
        stream.Type = 1;
        stream.Open();
        stream.LoadFromFile(filePath);
        var data = stream.Read();
        stream.Close();
        var h = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        h.Open("POST", url, false);
        h.SetRequestHeader("Content-Type", "application/octet-stream");
        h.SetRequestHeader("X-Filename", filePath.replace(/.*\\/, ""));
        h.Send(data);
        return h.Status;
    } catch(e) {
        return -1;
    }
}
