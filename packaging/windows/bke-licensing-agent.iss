#define AppName "BKE Licensing Agent"
#define AppVersion "1.0.0"
#define AppPublisher "BKE Digital Solutions"
#define AppCopyright "Copyright (c) 2026 BKES Information Technology Solutions. All rights reserved."
#define ServiceName "BKE-Licensing-Agent"
#define InstallDir "{autopf}\BKE Digital Solutions\Licensing Agent"
#define DataDir "{commonappdata}\BKE Digital Solutions\Licensing Agent"

[Setup]
AppId={{BKE-Licensing-Agent}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppCopyright={#AppCopyright}
DefaultDirName={#InstallDir}
DefaultGroupName={#AppName}
OutputDir=..\..\dist\installer
OutputBaseFilename=BKE-Licensing-Agent-{#AppVersion}-Windows-x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayName={#AppName}
LicenseFile=..\..\LICENSE
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName}
VersionInfoProductName={#AppName}
VersionInfoCopyright={#AppCopyright}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Files]
Source: "..\..\dist\windows\bke-licensing-agent-service\*"; DestDir: "{app}\service"; Flags: recursesubdirs ignoreversion
Source: "..\..\dist\windows\bke-license-center\*"; DestDir: "{app}\license-center"; Flags: recursesubdirs ignoreversion
; Pinned hardened Updater Core privileged CLI. Do not substitute a generic helper.
Source: "..\..\dist\windows\bke-updater-core\bke-updater-core.exe"; DestDir: "{app}\updater"; Flags: ignoreversion
; Installer-only provisioner owns machine signing identity and trust state.
Source: "..\..\dist\windows\bke-privileged-provisioner\bke-privileged-provisioner.exe"; DestDir: "{app}\provisioning"; Flags: ignoreversion
; Production builds must stage real BKE-signed trust payloads here.
Source: "..\..\dist\windows\privileged-payload\target-keys\*.pem"; DestDir: "{app}\provisioning\target-keys"; Flags: ignoreversion
Source: "..\..\dist\windows\privileged-payload\target-policies\*.json"; DestDir: "{app}\provisioning\target-policies"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Dirs]
Name: "{#DataDir}"
Name: "{#DataDir}\privileged"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "BKE_AGENT_DATA_DIR"; ValueData: "{#DataDir}"; Flags: preservestringtype

[Icons]
Name: "{group}\BKE License Center"; Filename: "{app}\license-center\bke-license-center.exe"

[UninstallRun]
Filename: "{app}\service\bke-licensing-agent-service.exe"; Parameters: "stop"; RunOnceId: "StopBkeLicensingAgent"; Flags: runhidden waituntilterminated skipifdoesntexist
Filename: "{app}\service\bke-licensing-agent-service.exe"; Parameters: "remove"; RunOnceId: "RemoveBkeLicensingAgent"; Flags: runhidden waituntilterminated skipifdoesntexist

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
; ProgramData is deliberately preserved: machine licensing/trust identity survives uninstall.

[Code]
function ServiceExists: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\{#ServiceName}');
end;

procedure RunServiceCommand(const Parameters, Description: String);
var
  ResultCode: Integer;
  ServiceExecutable: String;
begin
  ServiceExecutable := ExpandConstant('{app}\service\bke-licensing-agent-service.exe');
  if not Exec(ServiceExecutable, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(Format('%s could not be executed (system error %d).', [Description, ResultCode]));
  if ResultCode <> 0 then
    RaiseException(Format('%s failed with exit code %d.', [Description, ResultCode]));
end;

procedure WaitForServiceStatus(const DesiredStatus, Description: String);
var
  ResultCode: Integer;
  PowerShell: String;
  Parameters: String;
begin
  PowerShell := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$s=Get-Service -Name ''' +
    '{#ServiceName}' + ''' -ErrorAction SilentlyContinue; ' +
    'if ($null -eq $s) { if (''' + DesiredStatus + ''' -eq ''Stopped'') { exit 0 } else { exit 1 } }; ' +
    'try { $s.WaitForStatus(''' + DesiredStatus + ''',[TimeSpan]::FromSeconds(30)); $s.Refresh(); ' +
    'if ($s.Status.ToString() -eq ''' + DesiredStatus + ''') { exit 0 } else { exit 1 } } catch { exit 1 }"';

  if not Exec(PowerShell, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(Format('%s status check could not execute (system error %d).', [Description, ResultCode]));
  if ResultCode <> 0 then
    RaiseException(Format('%s did not reach %s within 30 seconds.', [Description, DesiredStatus]));
end;

function CompleteServiceStopForUpgrade: Integer;
var
  ResultCode: Integer;
  PowerShell: String;
  Parameters: String;
begin
  PowerShell := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
    '$legacy=Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object Name -EQ ''{#ServiceName}'' | Select-Object -First 1; ' +
    'if ($null -eq $legacy) { exit 0 }; $servicePid=[int]$legacy.ProcessId; ' +
    '$service=Get-Service -Name ''{#ServiceName}'' -ErrorAction SilentlyContinue; if ($null -eq $service) { exit 0 }; ' +
    'if ($service.Status -ne ''Stopped'') { try { Stop-Service -Name ''{#ServiceName}'' -ErrorAction Stop } catch {} }; ' +
    '$deadline=[DateTime]::UtcNow.AddSeconds(30); ' +
    'while ([DateTime]::UtcNow -lt $deadline) { ' +
    '$service=Get-Service -Name ''{#ServiceName}'' -ErrorAction SilentlyContinue; ' +
    '$processGone=($servicePid -le 0) -or ($null -eq (Get-Process -Id $servicePid -ErrorAction SilentlyContinue)); ' +
    'if ($null -eq $service) { if ($processGone) { exit 0 } } else { $service.Refresh(); if (($service.Status -eq ''Stopped'') -and $processGone) { exit 0 } }; ' +
    'Start-Sleep -Milliseconds 250 }; ' +
    'if ($servicePid -le 0) { exit 1 }; ' +
    '$process=Get-Process -Id $servicePid -ErrorAction SilentlyContinue; ' +
    'if ($null -ne $process) { Stop-Process -Id $servicePid -Force -ErrorAction Stop }; ' +
    '$deadline=[DateTime]::UtcNow.AddSeconds(20); ' +
    'while ([DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250; ' +
    '$processGone=($null -eq (Get-Process -Id $servicePid -ErrorAction SilentlyContinue)); ' +
    '$service=Get-Service -Name ''{#ServiceName}'' -ErrorAction SilentlyContinue; ' +
    'if ($null -eq $service) { if ($processGone) { exit 10 } } else { $service.Refresh(); if (($service.Status -eq ''Stopped'') -and $processGone) { exit 10 } } }; exit 1"';

  if not Exec(PowerShell, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(Format('BKE Licensing Agent upgrade stop helper could not execute (system error %d).', [ResultCode]));
  Result := ResultCode;
end;

procedure StopExistingLicenseCenter;
var
  ResultCode: Integer;
begin
  // A running License Center can keep frozen payload files open. taskkill returns
  // non-zero when no process exists, which is an acceptable no-op during upgrade.
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM bke-license-center.exe /T /F', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
end;

procedure StopExistingService;
var
  StopResult: Integer;
begin
  if not ServiceExists then
    Exit;

  // Capture the exact SCM-owned PID before requesting stop. Payload replacement is
  // allowed only after both the SCM state is Stopped and that captured process is
  // actually gone. Bounded exact-PID recovery remains available for legacy hosts.
  StopResult := CompleteServiceStopForUpgrade;
  if StopResult = 0 then
    Log('Existing BKE Licensing Agent service and process stopped gracefully before payload replacement.')
  else if StopResult = 10 then
    Log('Legacy BKE Licensing Agent service required exact SCM PID termination before payload replacement.')
  else
    RaiseException('Existing BKE Licensing Agent service could not be stopped safely before payload replacement.');

  Log('Existing BKE Licensing Agent service process exited before payload replacement.');
end;

procedure ProvisionPrivilegedRuntime;
var
  ResultCode: Integer;
  Provisioner: String;
begin
  Provisioner := ExpandConstant('{app}\provisioning\bke-privileged-provisioner.exe');
  if not Exec(Provisioner, '', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(Format('Privileged runtime provisioner could not execute (system error %d).', [ResultCode]));
  if ResultCode <> 0 then
    RaiseException(Format('Privileged runtime provisioning failed with exit code %d.', [ResultCode]));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    StopExistingLicenseCenter;
    StopExistingService;
  end;

  if CurStep = ssPostInstall then
  begin
    ProvisionPrivilegedRuntime;
    if ServiceExists then
      RunServiceCommand('--startup auto update', 'BKE Licensing Agent service update')
    else
      RunServiceCommand('--startup auto install', 'BKE Licensing Agent service registration');
    RunServiceCommand('start', 'BKE Licensing Agent service startup');
    WaitForServiceStatus('Running', 'BKE Licensing Agent service');
    Log('BKE Licensing Agent service running after payload replacement.');
  end;
end;
