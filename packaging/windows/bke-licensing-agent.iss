#define AppName "BKE Licensing Agent"
#define AppVersion "1.0.0"
#define AppPublisher "BKE Digital Solutions"
#define InstallDir "{autopf}\BKE Digital Solutions\Licensing Agent"
#define DataDir "{commonappdata}\BKE Digital Solutions\Licensing Agent"

[Setup]
AppId={{BKE-Licensing-Agent}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={#InstallDir}
OutputDir=..\..\dist\installer
OutputBaseFilename=BKE-Licensing-Agent-{#AppVersion}-Windows-x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Files]
; Frozen Agent/License Center packaging is intentionally separate from trust authority.
Source: "..\..\dist\windows\bke-licensing-agent\*"; DestDir: "{app}\agent"; Flags: recursesubdirs ignoreversion
Source: "..\..\dist\windows\bke-license-center\*"; DestDir: "{app}\license-center"; Flags: recursesubdirs ignoreversion
; This is the pinned hardened Updater Core privileged CLI, not the retired generic helper.
Source: "..\..\dist\windows\bke-updater-core\bke-updater-core.exe"; DestDir: "{app}\updater"; Flags: ignoreversion
; Provisioner is installer-only. It owns machine signing identity and protected trust state.
Source: "..\..\dist\windows\bke-privileged-provisioner\bke-privileged-provisioner.exe"; DestDir: "{app}\provisioning"; Flags: ignoreversion
; Production builds must stage BKE-signed trust payloads here. CI uses disposable fixtures only.
Source: "..\..\dist\windows\privileged-payload\target-keys\*.pem"; DestDir: "{app}\provisioning\target-keys"; Flags: ignoreversion
Source: "..\..\dist\windows\privileged-payload\target-policies\*.json"; DestDir: "{app}\provisioning\target-policies"; Flags: ignoreversion

[Dirs]
Name: "{#DataDir}"
Name: "{#DataDir}\privileged"

[Icons]
Name: "{group}\BKE License Center"; Filename: "{app}\license-center\bke-license-center.exe"

[Code]
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
  if CurStep = ssPostInstall then
    ProvisionPrivilegedRuntime;
end;

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
; Machine signing identity and trust state under ProgramData are intentionally preserved.
; A reinstall/upgrade validates and reuses the existing Agent identity; malformed state fails closed.
