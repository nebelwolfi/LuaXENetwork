@echo off
rem TB-287: build the module and only then run its tests. The && of two
rem pipelines would report findstr's exit code, not cmake's, so the build's
rem %ERRORLEVEL% is checked on its own before the tests start.
setlocal
set MODULE=%~dp0

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo FAILED to load the VS2022 environment
    exit /b 1
)

rem /showIncludes makes the compiler print every header, so the build output
rem goes to a log and only its verdict is printed; on failure the log is shown.
set BUILD_LOG=%TEMP%\tb287-build.log
cmake --build "%MODULE%cmake-build-release" > "%BUILD_LOG%" 2>&1
if errorlevel 1 (
    type "%BUILD_LOG%"
    echo BUILD FAILED - tests not run
    exit /b 1
)
echo build ok

powershell -NoProfile -ExecutionPolicy Bypass -File "%MODULE%tests\run_all.ps1" ^
    -Dll "%MODULE%cmake-build-release\network.dll" %*
exit /b %ERRORLEVEL%