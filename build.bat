@echo off

REM Set the path to the Visual Studio 2022 Community environment
REM Adjust this path if your installation is different
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

IF NOT EXIST MyCustomApp_Example\build mkdir MyCustomApp_Example\build

pushd MyCustomApp_Example\build

REM Generate Visual Studio project files for x64
cmake .. -G "Visual Studio 17 2022" -A x64
IF %ERRORLEVEL% NEQ 0 (
    echo CMake generation failed.
    popd
    goto :eof
)

REM Build the project in Release configuration
cmake --build . --config Release
IF %ERRORLEVEL% NEQ 0 (
    echo Build failed.
    popd
    goto :eof
)

echo MyCustomApp_Example built successfully to MyCustomApp_Example\build\Release\MyCustomApp.exe

popd 