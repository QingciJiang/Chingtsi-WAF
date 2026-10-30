@echo off
rem ============================================================
rem  Chingtsi WAF - build Windows installer (jlink + WinSW + Inno Setup)
rem  Usage: double-click this file, or from cmd:
rem           cd installer
rem           build-installer.bat
rem  Requirements: JDK 17+ (jlink), Inno Setup 6 (ISCC.exe),
rem                tools\WinSW-x64.exe (see tools\README.md)
rem  Note: jlink refuses paths containing non-ASCII characters,
rem        so the runtime is generated in %TEMP% and copied in.
rem ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0.."
set "ROOT=%CD%"
set "STAGE=%ROOT%\dist\stage"
set "RT=%TEMP%\chingtsi-waf-runtime"

set "VER="
for /f "usebackq delims=" %%v in ("%ROOT%\VERSION") do set "VER=%%v"
if not defined VER set "VER=1.0.0.0"
echo [1/5] version: %VER%

rem ---------- locate JDK ----------
set "JDKDIR="
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\jlink.exe" set "JDKDIR=%JAVA_HOME%"
if not defined JDKDIR for /f "delims=" %%p in ('where jlink.exe 2^>nul') do if not defined JDKDIR call :derive_jdk "%%p"
if not defined JDKDIR (
  echo [ERROR] jlink.exe not found. Install JDK 17+ and set JAVA_HOME.
  exit /b 1
)
echo       jdk: %JDKDIR%

rem ---------- locate ISCC ----------
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not defined ISCC for /f "delims=" %%p in ('where ISCC.exe 2^>nul') do if not defined ISCC set "ISCC=%%p"
if not defined ISCC (
  echo [ERROR] ISCC.exe not found. Install Inno Setup 6: https://jrsoftware.org/isdl.php
  exit /b 1
)
echo       iscc: %ISCC%

rem ---------- locate WinSW ----------
set "WINSW="
if exist "%ROOT%\tools\WinSW-x64.exe" set "WINSW=%ROOT%\tools\WinSW-x64.exe"
if not defined WINSW if exist "%ProgramFiles%\WinSW\WinSW-x64.exe" set "WINSW=%ProgramFiles%\WinSW\WinSW-x64.exe"
if not defined WINSW for /f "delims=" %%p in ('where WinSW-x64.exe 2^>nul') do if not defined WINSW set "WINSW=%%p"
if not defined WINSW (
  echo [ERROR] WinSW-x64.exe not found. Put it in tools\ - see tools\README.md
  exit /b 1
)
echo       winsw: %WINSW%

rem ---------- compile jar ----------
echo [2/5] compiling jar
call "%ROOT%\build.bat"
if errorlevel 1 (
  echo [ERROR] build.bat failed
  exit /b 1
)
if not exist "%ROOT%\dist\chingtsi-waf.jar" (
  echo [ERROR] dist\chingtsi-waf.jar not produced
  exit /b 1
)

rem ---------- stage layout ----------
echo [3/5] staging files
if exist "%STAGE%" rd /s /q "%STAGE%"
mkdir "%STAGE%\app\lib" 2>nul
mkdir "%STAGE%\bin" 2>nul
mkdir "%STAGE%\conf" 2>nul
mkdir "%STAGE%\rules" 2>nul

copy /y "%ROOT%\dist\chingtsi-waf.jar" "%STAGE%\app\" >nul
if exist "%ROOT%\lib\flatlaf.jar" copy /y "%ROOT%\lib\flatlaf.jar" "%STAGE%\app\lib\" >nul
copy /y "%ROOT%\conf\*" "%STAGE%\conf\" >nul
copy /y "%ROOT%\rules\*.conf" "%STAGE%\rules\" >nul
if exist "%ROOT%\data\ip2region.db" (
  mkdir "%STAGE%\app\data" 2>nul
  copy /y "%ROOT%\data\ip2region.db" "%STAGE%\app\data\" >nul
) else (
  echo       note: data\ip2region.db missing, shipping without geo database
)
copy /y "%WINSW%" "%STAGE%\bin\chingtsi-waf-service.exe" >nul

rem ---------- jlink runtime ----------
echo [4/5] building runtime with jlink
if exist "%RT%" rd /s /q "%RT%"
"%JDKDIR%\bin\jlink.exe" --add-modules java.base,java.logging,java.net.http,jdk.httpserver,java.desktop --strip-debug --no-header-files --no-man-pages --compress=zip-6 --output "%RT%"
if errorlevel 1 (
  echo       retry with legacy --compress=2
  if exist "%RT%" rd /s /q "%RT%"
  "%JDKDIR%\bin\jlink.exe" --add-modules java.base,java.logging,java.net.http,jdk.httpserver,java.desktop --strip-debug --no-header-files --no-man-pages --compress=2 --output "%RT%"
)
if not exist "%RT%\bin\java.exe" (
  echo [ERROR] jlink failed
  exit /b 1
)
robocopy "%RT%" "%STAGE%\runtime" /E /NFL /NDL /NJH /NJS >nul
if exist "%RT%" rd /s /q "%RT%"
if not exist "%STAGE%\runtime\bin\java.exe" (
  echo [ERROR] runtime copy failed
  exit /b 1
)

rem ---------- compile installer ----------
echo [5/5] compiling installer with Inno Setup
"%ISCC%" "%ROOT%\installer\chingtsi-waf.iss"
if errorlevel 1 (
  echo [ERROR] ISCC failed
  exit /b 1
)

echo.
echo Done: %ROOT%\dist\Chingtsi-WAF-Setup-%VER%-x64.exe
endlocal
exit /b 0

:derive_jdk
set "JDKBIN=%~dp1"
set "JDKBIN=%JDKBIN:~0,-1%"
for %%i in ("%JDKBIN%") do set "JDKDIR=%%~dpi"
if "%JDKDIR:~-1%"=="\" set "JDKDIR=%JDKDIR:~0,-1%"
exit /b 0
