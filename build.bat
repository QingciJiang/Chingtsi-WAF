@echo off
REM ============================================================
REM  Chingtsi WAF - build script (JDK 17+ only, zero dependency)
REM  1) compile all sources (core + graphical console)
REM  2) copy icon resources into classes
REM  3) package a single jar with version metadata
REM  Version string comes from the VERSION file at repo root.
REM ============================================================
setlocal
cd /d "%~dp0"

set "VERSION="
for /f "usebackq delims=" %%v in ("VERSION") do set "VERSION=%%v"
if not defined VERSION set "VERSION=1.0.0.0"

set "OUT=build\classes"
if not exist "build" mkdir "build"
if not exist "%OUT%" mkdir "%OUT%"
if not exist "dist" mkdir "dist"

where javac >nul 2>nul
if errorlevel 1 (
    echo [ERR] javac not found. Install JDK 17 or newer and put it on PATH.
    exit /b 1
)

echo [1/3] Compiling sources...
dir /s /b "src\*.java" > "build\sources.txt"
javac -encoding UTF-8 -d "%OUT%" @"build\sources.txt"
if errorlevel 1 (
    echo [ERR] Compile failed.
    exit /b 1
)

echo [2/3] Copying resources...
if exist "src\com\chingtsi\waf\ui\*.png" xcopy /y /q "src\com\chingtsi\waf\ui\*.png" "%OUT%\com\chingtsi\waf\ui\" >nul

echo [3/3] Packaging chingtsi-waf.jar...
> "build\manifest.mf" echo Manifest-Version: 1.0
>> "build\manifest.mf" echo Main-Class: com.chingtsi.waf.WafMain
>> "build\manifest.mf" echo Implementation-Title: Chingtsi WAF
>> "build\manifest.mf" echo Implementation-Version: %VERSION%
>> "build\manifest.mf" echo Implementation-Vendor: Chingtsi Studio
if exist "dist\chingtsi-waf.jar" del /q "dist\chingtsi-waf.jar"
jar --create --file "dist\chingtsi-waf.jar" --manifest "build\manifest.mf" -C "%OUT%" .
if errorlevel 1 (
    echo [ERR] Packaging failed.
    exit /b 1
)

echo.
echo Build OK  -^> %CD%\dist\chingtsi-waf.jar   (version %VERSION%)
echo Console   : java -cp "dist\chingtsi-waf.jar;lib\flatlaf.jar" com.chingtsi.waf.ui.DashboardMain
echo Headless  : java -cp "dist\chingtsi-waf.jar" com.chingtsi.waf.WafMain
echo Installer : installer\build-installer.bat
endlocal
