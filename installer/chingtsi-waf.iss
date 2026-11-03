; ============================================================
;  Chingtsi WAF 1.0.0.0 - Inno Setup 6 安装脚本
;
;  用法：先运行 installer\build-installer.bat 准备 dist\stage，
;        再右键本脚本 → Compile，或直接运行 build-installer.bat。
;  Source 相对路径均以本脚本所在目录为基准。
;
;  升级策略：固定 AppId + UsePreviousAppDir，覆盖程序文件；
;            conf / rules 一律 onlyifdoesntexist + uninsneveruninstall，
;            升级不丢配置与自定义规则。
; ============================================================

#define AppName "Chingtsi WAF"
#define AppVersion "1.0.0.0"
#define AppPublisher "Chingtsi Studio"
#define AppExe "chingtsi-waf-service.exe"
#define SrcDir "..\dist\stage"
#define IconFile "..\assets\chingtsi-waf.ico"
#define DefaultPort "8091"

[Setup]
AppId={{9C4E7A21-3F5B-4D8E-9A62-71C0B5D94E18}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Chingtsi WAF
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
UsePreviousGroup=yes
UsePreviousTasks=yes
OutputDir=..\dist
OutputBaseFilename=Chingtsi-WAF-Setup-{#AppVersion}-x64
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\bin\chingtsi-waf.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
UninstallDisplayName={#AppName} {#AppVersion}
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup (upgrade-safe)
VersionInfoCopyright=Copyright (c) 2026 Chingtsi Studio
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
AllowNoIcons=yes
CloseApplications=no
RestartApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
en.LaunchConsole=Launch the Chingtsi WAF console now
en.DesktopIcon=Create a desktop shortcut for the console

[Tasks]
Name: "service"; Description: "Install as a Windows service (auto-start on boot) - recommended"; GroupDescription: "Service:"; Flags: checkedonce
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "firewall"; Description: "Add Windows Firewall inbound rule for TCP {#DefaultPort}"; GroupDescription: "Service:"

[Files]
; 程序本体：升级时整体覆盖
Source: "{#SrcDir}\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SrcDir}\app\chingtsi-waf.jar"; DestDir: "{app}\app"; Flags: ignoreversion
Source: "{#SrcDir}\app\lib\*"; DestDir: "{app}\app\lib"; Flags: ignoreversion
Source: "{#SrcDir}\bin\{#AppExe}"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#IconFile}"; DestDir: "{app}\bin"; DestName: "chingtsi-waf.ico"; Flags: ignoreversion
; 用户数据：首装写入，升级/卸载均不动
Source: "{#SrcDir}\conf\*"; DestDir: "{app}\conf"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#SrcDir}\app\data\*"; DestDir: "{app}\data"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SrcDir}\rules\*"; DestDir: "{app}\rules"; Flags: onlyifdoesntexist uninsneveruninstall

[Dirs]
Name: "{app}\logs"; Permissions: users-modify

[Icons]
Name: "{group}\Chingtsi WAF 控制台"; Filename: "{app}\runtime\bin\javaw.exe"; Parameters: "-Dwaf.home=""{app}"" -Dfile.encoding=UTF-8 -cp ""{app}\app\chingtsi-waf.jar;{app}\app\lib\flatlaf.jar"" com.chingtsi.waf.ui.DashboardMain"; WorkingDir: "{app}"; IconFilename: "{app}\bin\chingtsi-waf.ico"
Name: "{group}\Edit configuration (waf.properties)"; Filename: "{sys}\notepad.exe"; Parameters: """{app}\conf\waf.properties"""
Name: "{group}\Edit rules folder"; Filename: "{sys}\explorer.exe"; Parameters: """{app}\rules"""
Name: "{group}\Open log folder"; Filename: "{sys}\explorer.exe"; Parameters: """{app}\logs"""
Name: "{group}\Run in console (debug)"; Filename: "{app}\bin\console.cmd"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Chingtsi WAF 控制台"; Filename: "{app}\runtime\bin\javaw.exe"; Parameters: "-Dwaf.home=""{app}"" -Dfile.encoding=UTF-8 -cp ""{app}\app\chingtsi-waf.jar;{app}\app\lib\flatlaf.jar"" com.chingtsi.waf.ui.DashboardMain"; WorkingDir: "{app}"; IconFilename: "{app}\bin\chingtsi-waf.ico"; Tasks: desktopicon

[Run]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Chingtsi WAF"" dir=in action=allow protocol=TCP localport={#DefaultPort}"; Flags: runhidden waituntilterminated; Tasks: firewall
Filename: "{app}\runtime\bin\javaw.exe"; Parameters: "-Dwaf.home=""{app}"" -Dfile.encoding=UTF-8 -cp ""{app}\app\chingtsi-waf.jar;{app}\app\lib\flatlaf.jar"" com.chingtsi.waf.ui.DashboardMain"; Description: "{cm:LaunchConsole}"; Flags: postinstall nowait skipifsilent; WorkingDir: "{app}"

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop ChingtsiWAF"; Flags: runhidden waituntilterminated; RunOnceId: "StopWaf"
Filename: "{sys}\sc.exe"; Parameters: "delete ChingtsiWAF"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteWaf"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Chingtsi WAF"""; Flags: runhidden waituntilterminated; RunOnceId: "DelFw"

[UninstallDelete]
Type: files; Name: "{app}\bin\chingtsi-waf-service.xml"
Type: files; Name: "{app}\bin\console.cmd"
Type: files; Name: "{app}\bin\console-ui.cmd"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\runtime"
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\bin"

[Code]
const
  ServiceId = 'ChingtsiWAF';
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{9C4E7A21-3F5B-4D8E-9A62-71C0B5D94E18}_is1';

var
  PreviousVersion: String;

function BuildServiceXml(AppDir: String): String;
begin
  Result :=
    '<!-- Chingtsi WAF service descriptor (WinSW) -->' + #13#10 +
    '<service>' + #13#10 +
    '  <id>' + ServiceId + '</id>' + #13#10 +
    '  <name>Chingtsi WAF</name>' + #13#10 +
    '  <description>Reverse-proxy Web Application Firewall (Chingtsi Studio)</description>' + #13#10 +
    '  <executable>' + AppDir + '\runtime\bin\java.exe</executable>' + #13#10 +
    '  <arguments>-Dwaf.home="' + AppDir + '" -Dfile.encoding=UTF-8 -cp "' + AppDir + '\app\chingtsi-waf.jar" com.chingtsi.waf.WafMain</arguments>' + #13#10 +
    '  <workingdirectory>' + AppDir + '</workingdirectory>' + #13#10 +
    '  <startmode>Automatic</startmode>' + #13#10 +
    '  <delayedAutoStart>true</delayedAutoStart>' + #13#10 +
    '  <onfailure action="restart" delay="10 sec"/>' + #13#10 +
    '  <resetfailure>1 hour</resetfailure>' + #13#10 +
    '  <stoptimeout>20 sec</stoptimeout>' + #13#10 +
    '  <stopparentprocessfirst>true</stopparentprocessfirst>' + #13#10 +
    '  <logpath>' + AppDir + '\logs</logpath>' + #13#10 +
    '  <log mode="roll-by-size">' + #13#10 +
    '    <sizeThreshold>10240</sizeThreshold>' + #13#10 +
    '    <keepFiles>8</keepFiles>' + #13#10 +
    '  </log>' + #13#10 +
    '</service>' + #13#10;
end;

function BuildConsoleCmd(): String;
begin
  Result :=
    '@echo off' + #13#10 +
    'chcp 65001 >nul' + #13#10 +
    'cd /d "%~dp0.."' + #13#10 +
    'echo Starting Chingtsi WAF in console mode (Ctrl+C to stop)...' + #13#10 +
    '"%~dp0..\runtime\bin\java.exe" -Dwaf.home="%~dp0.." -Dfile.encoding=UTF-8 -cp "%~dp0..\app\chingtsi-waf.jar" com.chingtsi.waf.WafMain' + #13#10 +
    'echo.' + #13#10 +
    'pause' + #13#10;
end;

function BuildConsoleUiCmd(): String;
begin
  Result :=
    '@echo off' + #13#10 +
    'cd /d "%~dp0.."' + #13#10 +
    '"%~dp0..\runtime\bin\javaw.exe" -Dwaf.home="%~dp0.." -Dfile.encoding=UTF-8 -cp "%~dp0..\app\chingtsi-waf.jar;%~dp0..\app\lib\flatlaf.jar" com.chingtsi.waf.ui.DashboardMain' + #13#10;
end;

{ 升级前停止旧服务，等待 java 进程释放 jar 文件锁（sc stop 幂等，已停止时返回 1062 无副作用） }
procedure StopWafService();
var
  I, Rc: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop ' + ServiceId, '', SW_HIDE, ewWaitUntilTerminated, Rc);
  for I := 1 to 10 do
  begin
    Sleep(1000);
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop ' + ServiceId, '', SW_HIDE, ewWaitUntilTerminated, Rc);
  end;
  Sleep(1500);
end;

{ 服务注册必须放在 ssPostInstall：WinSW install 首次可能返回非 0，需要退避重试 }
procedure RegisterWafService(AppDir: String);
var
  SvcExe: String;
  Rc, Attempt: Integer;
  Ok: Boolean;
begin
  SvcExe := AppDir + '\bin\{#AppExe}';
  Rc := -1;
  Exec(SvcExe, 'uninstall', AppDir, SW_HIDE, ewWaitUntilTerminated, Rc);
  Sleep(800);
  Ok := False;
  for Attempt := 1 to 3 do
  begin
    if Exec(SvcExe, 'install', AppDir, SW_HIDE, ewWaitUntilTerminated, Rc) and (Rc = 0) then
    begin
      Ok := True;
      Break;
    end;
    Sleep(1500);
  end;
  if Ok then
    Exec(SvcExe, 'start', AppDir, SW_HIDE, ewWaitUntilTerminated, Rc)
  else
    MsgBox('The Windows service could not be registered automatically (code ' + IntToStr(Rc) + ').' + #13#10 +
           'You can register it manually by running, as Administrator:' + #13#10 +
           SvcExe + ' install', mbError, MB_OK);
end;

function InitializeSetup(): Boolean;
var
  V: String;
begin
  Result := True;
  PreviousVersion := '';
  if RegQueryStringValue(HKLM64, UninstallKey, 'DisplayVersion', V) then
    PreviousVersion := V
  else if RegQueryStringValue(HKLM32, UninstallKey, 'DisplayVersion', V) then
    PreviousVersion := V;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpWelcome) and (PreviousVersion <> '') then
    WizardForm.WelcomeLabel2.Caption :=
      WizardForm.WelcomeLabel2.Caption + #13#10#13#10 +
      '升级模式：检测到已安装的 Chingtsi WAF ' + PreviousVersion + '。' + #13#10 +
      '将保留 conf（配置）、rules（规则）、logs（日志），仅替换程序文件并重启服务。';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  StopWafService();
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  AppDir: String;
begin
  if CurStep = ssPostInstall then
  begin
    AppDir := ExpandConstant('{app}');
    ForceDirectories(AppDir + '\logs');
    SaveStringToFile(AppDir + '\bin\chingtsi-waf-service.xml', BuildServiceXml(AppDir), False);
    SaveStringToFile(AppDir + '\bin\console.cmd', BuildConsoleCmd(), False);
    SaveStringToFile(AppDir + '\bin\console-ui.cmd', BuildConsoleUiCmd(), False);
    if WizardIsTaskSelected('service') then
      RegisterWafService(AppDir);
  end;
end;
