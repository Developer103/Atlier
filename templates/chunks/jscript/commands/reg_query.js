// chunk: commands/reg_query
// depends: core/run_cmd
// provides: reg_query, reg_set
// format: jscript

function reg_query(keyPath) {
    return _run("reg query \"" + keyPath + "\" 2>NUL");
}

function reg_set(keyPath, valueName, valueData, valueType) {
    var t = valueType || "REG_SZ";
    return _run("reg add \"" + keyPath + "\" /v \"" + valueName + "\" /d \"" + valueData + "\" /t " + t + " /f 2>NUL");
}
