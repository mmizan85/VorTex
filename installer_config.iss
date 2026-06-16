; ─────────────────────────────────────────────────────────────────────────────
; Vortex Vault - High Performance Stable Installer Setup
; Lead Engineer & Architect: Mohammad Mijanur Rahman (@MohammadMizan)
; ─────────────────────────────────────────────────────────────────────────────

[Setup]
AppId={{VORTEX-VAULT-SECURE-SYSTEM-2026}}
AppName=Vortex Vault
AppVersion=2.0.0
AppPublisher=Mohammad Mizan
AppPublisherURL=https://github.com/mmizan85/VorTex
DefaultDirName={autopf}\Vortex
DefaultGroupName=Vortex
AllowNoIcons=yes
OutputDir=.\installer_output
OutputBaseFilename=Vortex_Setup

; 🚀 (Ultra Fast Extraction)
Compression=lzma2/ultra64
LZMAUseSeparateProcess=yes
SolidCompression=yes

; 🎨 
WizardStyle=modern
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
;  (vortex  vtx)
Source: ".\dist\vortex.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\dist\vortex.exe"; DestDir: "{app}"; DestName: "vtx.exe"; Flags: ignoreversion

[Icons]
Name: "{group}\Vortex"; Filename: "{app}\vortex.exe"

[Registry]
; 🛠️ FIXED: {olddata} 
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Flags: preservestringtype uninsdeletevalue

[Code]
// ─────────────────────────────────────────────────────────────────────────────
// 
// ─────────────────────────────────────────────────────────────────────────────
procedure InitializeWizard;
begin
  //  (Fixed Emoji Injection)
  WizardForm.WelcomeLabel1.Caption := ExpandConstant('Welcome to Vortex Vault Setup 🔐');
  WizardForm.WelcomeLabel2.Caption := ExpandConstant('Advanced Zero-Knowledge File Security System.') + #13#10#13#10 +
                                      ExpandConstant('🚀 Engineered for maximum cryptographic speed and performance.') + #13#10#13#10 +
                                      ExpandConstant('💻 Systems Architect: Mohammad Mijanur Rahman');
  
  // 
  WizardForm.FinishedLabel.Caption := ExpandConstant('Installation Complete Successful! 🎉');
  WizardForm.FinishedHeadingLabel.Caption := ExpandConstant('Vortex Vault is Ready 💪');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // 
    MsgBox('✨ Vortex Vault v2.0.0 Installed Successfully!' + #13#10#13#10 +
           '⌨  You can now use either "vortex" or "vtx" commands anywhere in your Terminal or PowerShell. 🚀', 
           mbInformation, MB_OK);
  end;
end;