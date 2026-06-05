@echo off
REM ============================================================================
REM  Build xways-<name>.dll (x64) with MSVC cl.exe.
REM
REM  Project naming convention (do not stray):
REM    - Source folder (in our repo):  x-tensions\xways-<name>\
REM    - Source files:                 xways-<name>.cpp / .def / (optional) .rc
REM    - DLL:                          xways-<name>.dll
REM    - Deploy bundle (build output): xtensions\xways-<name>\xways-<name>.dll
REM      (xtensions\ matches X-Ways' built-in auto-load folder; drop the
REM      per-X-Tension subfolder straight into <X-Ways install>\xtensions\.)
REM
REM  Auto-bootstraps the VS x64 toolchain if cl.exe isn't on PATH yet, so this
REM  works from a plain cmd.exe / PowerShell window.
REM ============================================================================

setlocal EnableDelayedExpansion

REM --- Bootstrap VS x64 toolchain if needed ----------------------------------
where cl >nul 2>nul && goto :have_toolchain

set "VCVARS="
for %%V in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) do if not defined VCVARS if exist %%V set "VCVARS=%%~V"
if not defined VCVARS (
    echo ERROR: Could not find vcvars64.bat. Install the MSVC C++ build tools, or
    echo run this script from a "x64 Native Tools Command Prompt for VS 2019/2022".
    exit /b 1
)
echo Bootstrapping MSVC x64 environment from:
echo     !VCVARS!
call "!VCVARS!" >nul 2>nul
if errorlevel 1 (
    echo ERROR: vcvars64.bat reported failure.
    exit /b 1
)

:have_toolchain

set NAME=xways-trufflehog
set OUT=%NAME%.dll
set CXXFLAGS=/nologo /std:c++17 /W3 /EHsc /O2 /utf-8 /DUNICODE /D_UNICODE
set LDFLAGS=/DLL /DEF:%NAME%.def /OUT:%OUT% /MACHINE:X64
REM version.lib is for GetFileVersionInfo* / VerQueryValueW (PE VERSIONINFO
REM identity check in PeIdentityContains).
set LIBS=user32.lib shell32.lib ole32.lib comdlg32.lib comctl32.lib gdi32.lib advapi32.lib version.lib

if exist *.obj del /q *.obj
if exist *.res del /q *.res

rc /nologo /fo %NAME%.res %NAME%.rc || goto :fail
cl %CXXFLAGS% /c %NAME%.cpp || goto :fail
link %LDFLAGS% %NAME%.obj %NAME%.res %LIBS% || goto :fail

echo.
echo Built: %OUT%

REM Project deployment convention: xtensions\<name>\<name>.dll
REM (Each X-Tension lives in its own subfolder under xtensions\.)
if not exist xtensions\%NAME% mkdir xtensions\%NAME%
copy /Y "%OUT%" "xtensions\%NAME%\%OUT%" >nul || goto :fail
echo Deployed: xtensions\%NAME%\%OUT%

REM Also deploy the .cfg.example reference. EnsureCfgExists() in the cpp
REM copies this to xways-trufflehog.cfg on first run if no cfg exists yet.
if exist "%NAME%.cfg.example" (
    copy /Y "%NAME%.cfg.example" "xtensions\%NAME%\%NAME%.cfg.example" >nul
    echo Deployed: xtensions\%NAME%\%NAME%.cfg.example
)

REM Title-bar icon -- loaded via LoadImageW (LR_LOADFROMFILE) from the DLL's
REM own directory at WM_INITDIALOG. Same pattern as xways-updater.
if exist "hog.ico" (
    copy /Y "hog.ico" "xtensions\%NAME%\hog.ico" >nul
    echo Deployed: xtensions\%NAME%\hog.ico
)

REM Remove the project-root DLL so the only loadable copy is in the deploy
REM bundle (cfg sidecars land next to the loaded DLL — keeps them out of
REM the project root if X-Tensions.txt still has a stale path).
if exist "%OUT%" del /Q "%OUT%" 2>nul

exit /b 0

:fail
echo.
echo BUILD FAILED
exit /b 1
