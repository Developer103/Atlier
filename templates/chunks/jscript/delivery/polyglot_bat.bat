@if(0)==(0) echo off & cscript //nologo //E:jscript "%~f0" & exit /b
@end
// chunk: delivery/polyglot_bat
// provides: bat_jscript_polyglot
// format: polyglot (batch + jscript)
// description: Batch file that re-invokes itself as JScript via cscript. Double-clicking
//   runs the batch header which launches cscript with //E:jscript on this same file.
//   Everything below the @if/@end block is pure JScript.

{{PAYLOAD_BODY}}
