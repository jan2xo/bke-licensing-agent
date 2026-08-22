#define AppName "BKE Licensing Agent"
#define AppVersion "1.0.0"
#define AppPublisher "BKE Digital Solutions"
#define ServiceName "BKE-Licensing-Agent"
#define InstallDir "{autopf}\BKE Digital Solutions\Licensing Agent"
#define DataDir "{commonappdata}\BKE Digital Solutions\Licensing Agent"

[Setup]
AppId={{BKE-Licensing-Agent}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={#InstallDir}
DefaultGroupName={#AppName}
OutputDir=..\..\dist\installer
OutputBaseFilename=BKE-Licensing-Agent-{#AppVersion}-Windows-x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayName={#AppName}
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "..\..\dist\windows\bke-licensing-agent-service-wrapper\*"; DestDir: "{app}\service"; Flags: recursesubdirs ignoreversion
Source: "..\..\dist\windows\bke-license-center\*"; DestDir: "{app}\license-center"; Flags: recursesubdirs ignoreversion

[Dirs]
; Inno creates ProgramData with administrator/service ownership defaults.
; Do not grant ordinary users modification rights over licensing state or trusted keys.
Name: "{#DataDir}"
Name: "{#DataDir}\trusted-keys"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "BKE_AGENT_DATA_DIR"; ValueData: "{#DataDir}"; Flags: preservestringtype

[Icons]
Name: "{group}\BKE License Center"; Filename: "{app}\license-center\bke-license-center.exe"

[UninstallRun]
Filename: "{app}\service\bke-licensing-agent-service.exe"; Parameters: "stop"; RunOnceId: "StopBkeLicensingAgent"; Flags: runhidden waituntilterminated
Filename: "{app}\service\bke-licensing-agent-service.exe"; Parameters: "remove"; RunOnceId: "RemoveBkeLicensingAgent"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
; Durable {commonappdata} state is intentionally preserved.

[Code]
procedure RunServiceCommand(const Parameters, Description: String);
var
  ResultCode: Integer;
  ServiceExecutable: String;
begin
  ServiceExecutable := ExpandConstant('{app}\service\bke-licensing-agent-service.exe');
  if not Exec(ServiceExecutable, Parameters, '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
  begin
    RaiseException(Format('%s could not be executed (system error %d).', [Description, ResultCode]));
  end;
  if ResultCode <> 0 then
  begin
    RaiseException(Format('%s failed with exit code %d.', [Description, ResultCode]));
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RunServiceCommand('--startup auto install', 'BKE Licensing Agent service registration');
    RunServiceCommand('start', 'BKE Licensing Agent service startup');
  end;
end;
