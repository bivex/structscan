@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
::  build.bat — StructScan v4.0  |  Ninja + CMake multi-arch build
::
::  Usage:
::    build.bat              — build both x64 and ARM64 (Release)
::    build.bat x64          — x64 only
::    build.bat arm64        — ARM64 only
::    build.bat clean        — delete build\ directories
::    build.bat /?           — help
:: ============================================================================

set "VS2026=%ProgramFiles%\Microsoft Visual Studio\18\Insiders"
set "VS2022E=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise"
set "VS2022P=%ProgramFiles%\Microsoft Visual Studio\2022\Professional"
set "VS2022=%ProgramFiles%\Microsoft Visual Studio\2022\Community"

:: Derive root from script location, strip trailing backslash
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "BIN_DIR=%ROOT%\bin"
set "BUILD_ROOT=%ROOT%\build"
set "HELPER=%ROOT%\_build_arch.bat"

:: ── Args ──────────────────────────────────────────────────────────────────────
set "BUILD_X64=1"
set "BUILD_ARM64=1"

if /i "%~1"=="x64"   ( set "BUILD_ARM64=0" & goto :locate_vs )
if /i "%~1"=="arm64" ( set "BUILD_X64=0"   & goto :locate_vs )
if /i "%~1"=="clean" goto :clean
if    "%~1"=="/?"    goto :usage
if /i "%~1"=="help"  goto :usage
goto :locate_vs

:usage
echo.
echo  build.bat              -- x64 + ARM64 Release
echo  build.bat x64          -- x64 only
echo  build.bat arm64        -- ARM64 only
echo  build.bat clean        -- remove build\x64 and build\arm64
echo  build.bat /?           -- help
echo.
exit /b 0

:: ── Locate Visual Studio ──────────────────────────────────────────────────────
:locate_vs
set "VCVARSALL="
if exist "%VS2026%\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%VS2026%\VC\Auxiliary\Build\vcvarsall.bat"
    set "VS_TAG=VS 2026 Insiders"
    goto :found_vs
)
if exist "%VS2022E%\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%VS2022E%\VC\Auxiliary\Build\vcvarsall.bat"
    set "VS_TAG=VS 2022 Enterprise"
    goto :found_vs
)
if exist "%VS2022P%\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%VS2022P%\VC\Auxiliary\Build\vcvarsall.bat"
    set "VS_TAG=VS 2022 Professional"
    goto :found_vs
)
if exist "%VS2022%\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%VS2022%\VC\Auxiliary\Build\vcvarsall.bat"
    set "VS_TAG=VS 2022 Community"
    goto :found_vs
)
echo [ERROR] Visual Studio 2022 or 2026 not found.
exit /b 1

:found_vs
echo [*] Compiler : %VS_TAG%

:: ── Locate cmake — track full path so we can add dir to PATH ─────────────────
set "CMAKE_FULL="

where cmake >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%P in ('where cmake') do (
        set "CMAKE_FULL=%%P"
        goto :cmake_found
    )
)
for %%V in ("%VS2026%" "%VS2022E%" "%VS2022P%" "%VS2022%") do (
    set "_C=%%~V\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if exist "!_C!" (
        set "CMAKE_FULL=!_C!"
        goto :cmake_found
    )
)
echo [ERROR] cmake.exe not found.
echo         Install "C++ CMake tools for Windows" via VS Installer.
exit /b 1

:cmake_found
:: Add cmake directory to PATH so it's callable as "cmake" anywhere
for %%P in ("%CMAKE_FULL%") do set "CMAKE_DIR=%%~dpP"
set "PATH=%CMAKE_DIR%;%PATH%"
echo [*] cmake    : %CMAKE_FULL%

:: ── Locate ninja — track full path, pass to cmake via -DCMAKE_MAKE_PROGRAM ───
set "NINJA_FULL="

where ninja >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%P in ('where ninja') do (
        set "NINJA_FULL=%%P"
        goto :ninja_found
    )
)
for %%V in ("%VS2026%" "%VS2022E%" "%VS2022P%" "%VS2022%") do (
    set "_N=%%~V\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
    if exist "!_N!" (
        set "NINJA_FULL=!_N!"
        goto :ninja_found
    )
)
echo [ERROR] ninja.exe not found.
echo         Install "C++ CMake tools for Windows" via VS Installer, or
echo         download from https://github.com/ninja-build/ninja/releases
exit /b 1

:ninja_found
echo [*] ninja    : %NINJA_FULL%

cmake --version 2>nul | findstr /b "cmake version"
ninja --version 2>nul

if not exist "%BIN_DIR%"    mkdir "%BIN_DIR%"
if not exist "%BUILD_ROOT%" mkdir "%BUILD_ROOT%"

set "NPROC=%NUMBER_OF_PROCESSORS%"
if "%NPROC%"=="" set "NPROC=4"
set "FAIL=0"

:: ── x64 ───────────────────────────────────────────────────────────────────────
if "%BUILD_X64%"=="1" (
    echo.
    echo ================================================================
    echo  Building x64 AMD64 -- Release
    echo ================================================================
    if not exist "%BUILD_ROOT%\x64" mkdir "%BUILD_ROOT%\x64"

    call "%HELPER%" x64 "%VCVARSALL%" "%ROOT%" "%BUILD_ROOT%\x64" "%NINJA_FULL%" %NPROC%
    if errorlevel 1 (
        set "FAIL=1"
        echo [FAIL] x64 build failed.
    ) else (
        if exist "%BUILD_ROOT%\x64\structscan.dll" (
            copy /y "%BUILD_ROOT%\x64\structscan.dll" "%BIN_DIR%\structscan_x64.dll" >nul
        ) else if exist "%BUILD_ROOT%\x64\Release\structscan.dll" (
            copy /y "%BUILD_ROOT%\x64\Release\structscan.dll" "%BIN_DIR%\structscan_x64.dll" >nul
        )
        if exist "%BIN_DIR%\structscan_x64.dll" (
            echo [OK]   bin\structscan_x64.dll
        )
    )
)

:: ── ARM64 ─────────────────────────────────────────────────────────────────────
if "%BUILD_ARM64%"=="1" (
    echo.
    echo ================================================================
    echo  Building ARM64 AArch64 -- Release
    echo ================================================================
    if not exist "%BUILD_ROOT%\arm64" mkdir "%BUILD_ROOT%\arm64"

    call "%HELPER%" arm64 "%VCVARSALL%" "%ROOT%" "%BUILD_ROOT%\arm64" "%NINJA_FULL%" %NPROC%
    if errorlevel 1 (
        set "FAIL=1"
        echo [FAIL] ARM64 build failed.
    ) else (
        if exist "%BUILD_ROOT%\arm64\structscan.dll" (
            copy /y "%BUILD_ROOT%\arm64\structscan.dll" "%BIN_DIR%\structscan_arm64.dll" >nul
        ) else if exist "%BUILD_ROOT%\arm64\Release\structscan.dll" (
            copy /y "%BUILD_ROOT%\arm64\Release\structscan.dll" "%BIN_DIR%\structscan_arm64.dll" >nul
        )
        if exist "%BIN_DIR%\structscan_arm64.dll" (
            echo [OK]   bin\structscan_arm64.dll
        )
    )
)

:: ── Summary ───────────────────────────────────────────────────────────────────
echo.
echo ================================================================
echo  Summary
echo ================================================================
if "%BUILD_X64%"=="1" (
    if exist "%BIN_DIR%\structscan_x64.dll" (
        echo  [OK]  bin\structscan_x64.dll
    ) else (
        echo  [--]  bin\structscan_x64.dll missing
    )
)
if "%BUILD_ARM64%"=="1" (
    if exist "%BIN_DIR%\structscan_arm64.dll" (
        echo  [OK]  bin\structscan_arm64.dll
    ) else (
        echo  [--]  bin\structscan_arm64.dll missing
    )
)
echo.
echo  WinDbg:
echo    .load C:\Tools\structscan_x64.dll
echo    !structscan nt!PsInitialSystemProcess 0x480
echo    !uaf nt!PsInitialSystemProcess 0x480
echo.
if "%FAIL%"=="1" (
    echo [!!] One or more builds FAILED.
    exit /b 1
)
echo [OK] All builds succeeded.
exit /b 0

:: ── Clean ─────────────────────────────────────────────────────────────────────
:clean
echo [*] Removing build\x64 and build\arm64 ...
if exist "%BUILD_ROOT%\x64"   rmdir /s /q "%BUILD_ROOT%\x64"
if exist "%BUILD_ROOT%\arm64" rmdir /s /q "%BUILD_ROOT%\arm64"
echo [OK] Done. bin\ preserved.
exit /b 0
