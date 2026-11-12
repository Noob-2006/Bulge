; SE Agent NSIS installer hooks (bundle.windows.nsis.installerHooks).
; A running seagent.exe (the background daemon) is locked by Windows, so an upgrade or uninstall
; stops it first. The app starts it again on its next launch. Errors are ignored: on a fresh
; install there is nothing to stop.
;
; The virtual display driver (resources vdd\, control/vdd.rs in seagent-browser) is an optional
; part of the install, on by default: after the files are in place the installer asks (silent
; installs: yes) and runs vdd\install-vdd.ps1 elevated — one UAC prompt, and Windows may ask to
; install device software published by "SignPath Foundation". Already installed (its VDDPATH
; points at our configuration): nothing to do, so updates do not prompt again. The settings page
; installs / repairs / removes it later; uninstalling the app removes it.

!macro NSIS_HOOK_PREINSTALL
  IfFileExists "$INSTDIR\seagent.exe" 0 +2
    nsExec::Exec '"$INSTDIR\seagent.exe" daemon stop'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  IfFileExists "$INSTDIR\vdd\install-vdd.ps1" 0 seagent_vdd_done
    SetRegView 64
    ReadRegStr $0 HKLM "SOFTWARE\MikeTheTech\VirtualDisplayDriver" "VDDPATH"
    SetRegView lastused
    StrCmp $0 "$PROGRAMFILES64\SEAgent\VirtualDisplay" seagent_vdd_done
    MessageBox MB_YESNO|MB_ICONQUESTION "Install the virtual display driver (recommended)?$\r$\n安裝虛擬顯示器驅動程式（建議）？$\r$\n$\r$\nApps on the agent's Bot Desktop then stream at 30-60 fps instead of about 10. It adds one virtual screen outside the corner of your screens; your own screens do not change. Needs administrator approval.$\r$\n代理的 Bot Desktop 上的 App 會以 30–60 fps 串流（否則約 10 fps）。只會在你螢幕的角落外側加一台虛擬螢幕，你的螢幕不變。需要系統管理員同意。" /SD IDYES IDNO seagent_vdd_done
    ExecShellWait "runas" "powershell.exe" '-NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\vdd\install-vdd.ps1" -Relaunched' SW_SHOWNORMAL
  seagent_vdd_done:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$INSTDIR\seagent.exe" 0 +2
    nsExec::Exec '"$INSTDIR\seagent.exe" daemon stop'
  IfFileExists "$INSTDIR\vdd\install-vdd.ps1" 0 seagent_vdd_gone
    SetRegView 64
    ReadRegStr $0 HKLM "SOFTWARE\MikeTheTech\VirtualDisplayDriver" "VDDPATH"
    SetRegView lastused
    StrCmp $0 "$PROGRAMFILES64\SEAgent\VirtualDisplay" 0 seagent_vdd_gone
    ExecShellWait "runas" "powershell.exe" '-NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\vdd\install-vdd.ps1" -Uninstall -Relaunched' SW_SHOWNORMAL
  seagent_vdd_gone:
!macroend
