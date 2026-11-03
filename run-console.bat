@echo off
REM ============================================================
REM  Chingtsi WAF - run console mode from the source tree
REM  Requires JDK 17+ on PATH, run build.bat first.
REM ============================================================
setlocal
cd /d "%~dp0"

if not exist "dist\chingtsi-waf.jar" (
    echo [ERR] chingtsi-waf.jar not found. Run build.bat first.
    pause
    exit /b 1
)

java -Dwaf.home="%~dp0" -Dfile.encoding=UTF-8 --add-modules jdk.httpserver -cp "dist\chingtsi-waf.jar;lib\flatlaf.jar" com.chingtsi.waf.WafMain %*
endlocal
