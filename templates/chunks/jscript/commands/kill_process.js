// chunk: commands/kill_process
// depends: core/run_cmd
// provides: kill_process
// format: jscript

function kill_process(name) {
    return _run("taskkill /f /im \"" + name + "\" 2>NUL");
}
