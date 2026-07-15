REM provides: collect_network
REM depends: core/output
REM description: Collect network configuration and connections

echo === IPCONFIG === >> "%OUTPUT_FILE%"
ipconfig /all >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === ARP TABLE === >> "%OUTPUT_FILE%"
arp -a >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === ROUTE TABLE === >> "%OUTPUT_FILE%"
route print >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === ACTIVE CONNECTIONS === >> "%OUTPUT_FILE%"
netstat -ano >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === DNS CACHE === >> "%OUTPUT_FILE%"
ipconfig /displaydns >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
echo === NET SHARES === >> "%OUTPUT_FILE%"
net share >> "%OUTPUT_FILE%" 2>nul
echo. >> "%OUTPUT_FILE%"
