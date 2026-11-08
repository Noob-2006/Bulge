; SE Agent NSIS installer hooks (bundle.windows.nsis.installerHooks).
; A running seagent.exe (the background daemon) is locked by Windows, so an upgrade or uninstall
; stops it first. The app starts it again on its next launch. Errors are ignored: on a fresh
; install there is nothing to stop.

!macro NSIS_HOOK_PREINSTALL
  IfFileExists "$INSTDIR\seagent.exe" 0 +2
    nsExec::Exec '"$INSTDIR\seagent.exe" daemon stop'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$INSTDIR\seagent.exe" 0 +2
    nsExec::Exec '"$INSTDIR\seagent.exe" daemon stop'
!macroend
