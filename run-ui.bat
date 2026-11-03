@echo off
REM ============================================================
REM  Chingtsi WAF - launch the graphical console from source tree
REM  Falls back to the system look-and-feel when lib\flatlaf.jar is absent.
REM ============================================================
setlocal
cd /d "%~dp0"

if not exist "dist\chingtsi-waf.jar" (
    echo [ERR] chingtsi-waf.jar not found. Run build.bat first.
    pause
    exit /b 1
)

if exist "lib\flatlaf.jar" (
    start "" javaw -Dwaf.home="%~dp0" -Dfile.encoding=UTF-8 -cp "dist\chingtsi-waf.jar;lib\flatlaf.jar" com.chingtsi.waf.ui.DashboardMain
) else (
    start "" javaw -Dwaf.home="%~dp0" -Dfile.encoding=UTF-8 -cp "dist\chingtsi-waf.jar" com.chingtsi.waf.ui.DashboardMain
)
endlocal
