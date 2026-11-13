; RZP2 Windows 安装脚本
; 由 package.sh / package.ps1 通过 -D 传入 VERSION / VIVERSION / ARCH / OUTFILE / STAGEDIR 等参数。

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "StrFunc.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef VIVERSION
  !define VIVERSION "0.0.0.0"
!endif
!ifndef ARCH
  !define ARCH "x86_64"
!endif
!ifndef PUBLISHER
  !define PUBLISHER "张俊琦"
!endif
!ifndef OUTFILE
  !define OUTFILE "rzp2-setup.exe"
!endif
!ifndef STAGEDIR
  !define STAGEDIR "."
!endif

Name "RZP2 ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "D:\RZP2"
InstallDirRegKey HKLM "Software\RZP2" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
!cd "${STAGEDIR}"

VIProductVersion "${VIVERSION}"
VIAddVersionKey "ProductName" "RZP2"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "RZP2 压缩加密工具"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright (c) ${PUBLISHER}"

${StrStr}
${UnStrRep}
${UnStrStr}

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

Section "RZP2" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"
  File "rzp2.exe"
  File "README.md"
  File "FORMAT.md"
  File "API.md"
  File "LICENSE"
  File "LICENSE-MIT"
  File "LICENSE-APACHE"
  File "rzp2-completion.ps1"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP2" "DisplayName" "RZP2 压缩加密工具"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP2" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP2" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP2" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP2" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP2" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP2" "NoRepair" 1

  WriteRegStr HKLM "Software\RZP2" "InstallDir" "$INSTDIR"

  ; 关联 .rzp2 文件图标（默认图标取 rzp2.exe 内嵌图标，索引 0）
  WriteRegStr HKLM "Software\Classes\.rzp2" "" "RZP2.Archive"
  WriteRegStr HKLM "Software\Classes\RZP2.Archive" "" "RZP2 压缩档案"
  WriteRegStr HKLM "Software\Classes\RZP2.Archive\DefaultIcon" "" '$INSTDIR\rzp2.exe,0'
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'

  Call AddToPath

  CreateDirectory "$SMPROGRAMS\RZP2"
  CreateShortcut "$SMPROGRAMS\RZP2\卸载 RZP2.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\RZP2\README.lnk" "$INSTDIR\README.md"
SectionEnd

Section "注册 PowerShell Tab 补全" SecCompletion
  Call AddCompletionToProfiles
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "安装 RZP2 程序、文档与图标，并加入 PATH。"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCompletion} "把 rzp2 的 Tab 补全脚本写入 PowerShell 配置文件（$PROFILE），安装后需重开 PowerShell 生效。"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; 向 profile 文件追加一行（若已含 rzp2-completion.ps1 引用则跳过）。
; 入参：$0 = profile 文件路径；$1 = 待追加的行（含真实安装路径）。
Function AppendProfileLine
  Push $2
  Push $3
  Push $4
  Push $5

  ClearErrors
  FileOpen $2 "$0" r
  IfErrors append_create

  StrCpy $3 ""
  append_read_loop:
    FileRead $2 $4
    IfErrors append_read_done
    StrCpy $3 "$3$4"
    Goto append_read_loop
  append_read_done:
  FileClose $2

  ${StrStr} $5 "$3" "rzp2-completion.ps1"
  StrCmp $5 "" 0 append_done

  FileOpen $2 "$0" a
  FileSeek $2 0 END
  StrCmp $3 "" append_write
  FileWrite $2 "$\r$\n"
  append_write:
  FileWrite $2 "$1$\r$\n"
  FileClose $2
  Goto append_done

  append_create:
  ClearErrors
  FileOpen $2 "$0" a
  FileWrite $2 "$1$\r$\n"
  FileClose $2

  append_done:
  Pop $5
  Pop $4
  Pop $3
  Pop $2
FunctionEnd

; 向 Windows PowerShell 5.1 与 PowerShell 7 的 profile 写入补全引用。
Function AddCompletionToProfiles
  Push $0
  Push $1

  CreateDirectory "$DOCUMENTS\WindowsPowerShell"
  CreateDirectory "$DOCUMENTS\PowerShell"

  StrCpy $1 '. $\"$INSTDIR\rzp2-completion.ps1$\"'

  StrCpy $0 "$DOCUMENTS\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
  Call AppendProfileLine

  StrCpy $0 "$DOCUMENTS\PowerShell\Microsoft.PowerShell_profile.ps1"
  Call AppendProfileLine

  Pop $1
  Pop $0
FunctionEnd

Function AddToPath
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${StrStr} $1 "$0" "$INSTDIR"
  ${If} $1 != ""
    Return
  ${EndIf}
  ${If} $0 == ""
    StrCpy $0 "$INSTDIR"
  ${Else}
    StrCpy $0 "$0;$INSTDIR"
  ${EndIf}
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
FunctionEnd

Function un.RemoveFromPath
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${If} $0 == ""
    Return
  ${EndIf}
  ${UnStrRep} $1 "$0" "$INSTDIR;" ""
  ${UnStrRep} $2 "$1" ";$INSTDIR" ""
  ${UnStrRep} $3 "$2" "$INSTDIR" ""
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$3"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
FunctionEnd

; 从 profile 文件移除引用 rzp2-completion.ps1 的行。
; 入参：$0 = profile 文件路径。
Function un.RemoveProfileLine
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6

  ClearErrors
  FileOpen $2 "$0" r
  IfErrors un_remove_done

  StrCpy $3 ""
  StrCpy $6 ""
  un_remove_loop:
    FileRead $2 $4
    IfErrors un_remove_eof
    ${UnStrStr} $5 "$4" "rzp2-completion.ps1"
    StrCmp $5 "" 0 un_remove_skip
    StrCpy $3 "$3$4"
    Goto un_remove_loop
    un_remove_skip:
    StrCpy $6 "1"
    Goto un_remove_loop
  un_remove_eof:
  FileClose $2

  StrCmp $6 "" un_remove_done

  FileOpen $2 "$0" w
  FileWrite $2 "$3"
  FileClose $2

  un_remove_done:
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
FunctionEnd

; 清理两个 PowerShell 版本 profile 中的补全引用。
Function un.RemoveCompletionFromProfiles
  Push $0
  StrCpy $0 "$DOCUMENTS\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
  Call un.RemoveProfileLine
  StrCpy $0 "$DOCUMENTS\PowerShell\Microsoft.PowerShell_profile.ps1"
  Call un.RemoveProfileLine
  Pop $0
FunctionEnd

Section "Uninstall"
  Call un.RemoveFromPath
  Call un.RemoveCompletionFromProfiles
  Delete '$INSTDIR\rzp2.exe'
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\FORMAT.md"
  Delete "$INSTDIR\API.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\LICENSE-MIT"
  Delete "$INSTDIR\LICENSE-APACHE"
  Delete "$INSTDIR\rzp2-completion.ps1"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\RZP2\卸载 RZP2.lnk"
  Delete "$SMPROGRAMS\RZP2\README.lnk"
  RMDir "$SMPROGRAMS\RZP2"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP2"
  DeleteRegKey HKLM "Software\RZP2"

  ; 清理 .rzp2 文件关联（仅在仍指向本 ProgID 时删除 .rzp2 键）
  ReadRegStr $0 HKLM "Software\Classes\.rzp2" ""
  ${If} $0 == "RZP2.Archive"
    DeleteRegKey HKLM "Software\Classes\.rzp2"
  ${EndIf}
  DeleteRegKey HKLM "Software\Classes\RZP2.Archive"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'
SectionEnd
