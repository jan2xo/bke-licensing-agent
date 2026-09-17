#define AppName "BKE Licensing Agent"
#define AppVersion "2.0.0"
#define AppPublisher "BKE Digital Solutions"
#define ServiceName "BKE-Licensing-Agent"
#define InstallDir "{autopf}\BKE Digital Solutions\Licensing Agent"
#define DataDir "{commonappdata}\BKE Digital Solutions\Licensing Agent"

; Certification-only migration installer. The canonical production installer is
; intentionally unchanged until the Python -> .NET runtime bridge is proven.

[Setup]
AppId={{BKE-Licensing-Agent}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={#InstallDir}
DefaultGroupName={#AppName}
OutputDir=..\..\dist\installer
OutputBaseFilename=BKE-Licensing-Agent-{#AppVersion}-RuntimeBridge-Windows-x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayName={#AppName}
LicenseFile=..\..\LICENSE
Compression=lzma
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Files]
; Stable SCM host. Its filename/path is a permanent machine compatibility boundary.
Source: "..\..\dist\windows\bke-licensing-agent-service\*"; DestDir: "{app}\service"; Flags: recursesubdirs ignoreversion
; Replaceable implementation-language payload.
Source: "..\..\dist\windows\bke-licensing-agent-runtime\*"; DestDir: "{app}\runtime"; Flags: recursesubdirs ignoreversion
; Existing native user UI and hardened updater assets remain separate migration boundaries.
Source: "..\..\dist\windows\bke-license-center\*"; DestDir: "{app}\license-center"; Flags: recursesubdirs ignoreversion
Source: "..\..\dist\windows\bke-updater-core\bke-updater-core.exe"; DestDir: "{app}\updater"; Flags: ignoreversion
Source: "..\..\dist\windows\bke-privileged-provisioner\bke-privileged-provisioner.exe"; DestDir: "{app}\provisioning"; Flags: ignoreversion
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
Filename: "{sys}\sc.exe"; Parameters: "stop ""{#ServiceName}"""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete ""{#ServiceName}"""; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
; ProgramData deliberately survives runtime-language changes and uninstall.

[Code]
function ServiceExists: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\{#ServiceName}');
end;

procedure RunSc(const Parameters, Description: String);
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\sc.exe'), Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(Format('%s could not execute (system error %d).', [Description, ResultCode]));
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
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM bke-license-center.exe /T /F', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
end;

procedure StopExistingService;
var
  StopResult: Integer;
begin
  if not ServiceExists then
    Exit;
  StopResult := CompleteServiceStopForUpgrade;
  if (StopResult <> 0) and (StopResult <> 10) then
    RaiseException('Existing BKE Licensing Agent service could not be stopped safely before runtime replacement.');
  Log('Existing BKE Licensing Agent service process exited before runtime replacement.');
end;

procedure ClearReplaceablePayloads;
begin
  { The stable paths stay constant; their implementation contents are disposable. }
  DelTree(ExpandConstant('{app}\service'), True, True, True);
  DelTree(ExpandConstant('{app}\runtime'), True, True, True);
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

procedure ConfigureStableService;
var
  ServiceExecutable: String;
  Parameters: String;
begin
  ServiceExecutable := ExpandConstant('{app}\service\bke-licensing-agent-service.exe');
  if ServiceExists then
    Parameters := 'config "{#ServiceName}" binPath= "' + ServiceExecutable + '" start= auto DisplayName= "{#AppName}"'
  else
    Parameters := 'create "{#ServiceName}" binPath= "' + ServiceExecutable + '" start= auto DisplayName= "{#AppName}"';
  RunSc(Parameters, 'BKE Licensing Agent service registration');
  RunSc('description "{#ServiceName}" "Loopback-only BKE licensing authority and runtime supervisor."',
    'BKE Licensing Agent service description');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    StopExistingLicenseCenter;
    StopExistingService;
    ClearReplaceablePayloads;
  end;

  if CurStep = ssPostInstall then
  begin
    ProvisionPrivilegedRuntime;
    { Admin-only certification seam. Production packaging never emits this marker. }
    SaveStringToFile(ExpandConstant('{app}\bridge-cert.enable'), 'runtime bridge certification only' + #13#10, False);
    ConfigureStableService;
    RunSc('start "{#ServiceName}"', 'BKE Licensing Agent service startup');
    WaitForServiceStatus('Running', 'BKE Licensing Agent service');
    Log('Runtime-neutral BKE Licensing Agent service running after payload replacement.');
  end;
end;
