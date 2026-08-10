@echo off
:: _build_arch.bat — called by build.bat, do not run directly.
::
::   %1 = arch           (x64 | arm64)
::   %2 = vcvarsall.bat  full path
::   %3 = source dir     full path
::   %4 = build dir      full path
::   %5 = ninja.exe      full path  (may contain spaces — passed as single arg)
::   %6 = nproc          parallel job count

if "%~1"=="" ( echo [ERROR] _build_arch.bat: missing arch & exit /b 1 )
if "%~2"=="" ( echo [ERROR] _build_arch.bat: missing vcvarsall & exit /b 1 )
if "%~5"=="" ( echo [ERROR] _build_arch.bat: missing ninja path & exit /b 1 )

echo [*] vcvarsall %~1 ...
call "%~2" %~1 >nul 2>&1
if errorlevel 1 ( echo [FAIL] vcvarsall %~1 failed & exit /b 1 )

echo [*] cmake configure ...
cmake -S "%~3" -B "%~4" ^
    -G Ninja ^
    "-DCMAKE_MAKE_PROGRAM=%~5" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_C_COMPILER=cl ^
    -DCMAKE_CXX_COMPILER=cl ^
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL ^
    --no-warn-unused-cli
if errorlevel 1 ( echo [FAIL] cmake configure failed & exit /b 1 )

echo [*] cmake build jobs: %~6 ...
cmake --build "%~4" -- -j%~6
if errorlevel 1 ( echo [FAIL] cmake build failed & exit /b 1 )

exit /b 0
