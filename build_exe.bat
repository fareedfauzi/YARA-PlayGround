@echo off
echo [*] Starting YARAPlayground Build Sequence (Windows)...

:: Precise path configuration for the user's environment (EDIT THIS IF YOU FACE AN ERROR TO FIND PYTHON)!
set "PYTHON_EXE=python.exe"
set "PYINSTALLER_EXE=pyinstaller.exe"

:: Check if PyInstaller exists
if not exist "%PYINSTALLER_EXE%" (
    echo [!] Error: PyInstaller not found at expected path.
    echo [*] Attempting fallback to module call...
    "%PYTHON_EXE%" -m PyInstaller --version >nul 2>&1
    if %errorlevel% neq 0 (
         echo [!] Critical Error: PyInstaller not found.
         pause
         exit /b 1
    )
    set "BUILD_CMD="%PYTHON_EXE%" -m PyInstaller"
) else (
    set "BUILD_CMD="%PYINSTALLER_EXE%""
)

echo [*] Delete old binary...
del YARAPlayground.exe

:: Run PyInstaller
echo [*] Compiling binary...
%BUILD_CMD% --noconfirm --onefile --windowed --name "YARAPlayground" --collect-all customtkinter --collect-all tkinterdnd2 Scripts\yara_playground.py

:: Move Binary
if exist dist\YARAPlayground.exe (
    echo [*] Moving binary to root...
    taskkill /F /IM YARAPlayground.exe >nul 2>&1
    :: Try direct move
    move /y dist\YARAPlayground.exe . >nul 2>&1
    if %errorlevel% neq 0 (
        echo [!] Hot-swap: Executable is locked. Renaming old version and deploying new one...
        if exist YARAPlayground.exe.old del /f /q YARAPlayground.exe.old
        ren YARAPlayground.exe YARAPlayground.exe.old
        move /y dist\YARAPlayground.exe .
    )
)

:: Cleanup
echo [*] Cleaning up build artifacts...
if exist YARAPlayground.spec del /f /q YARAPlayground.spec
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [+] Build Complete: YARAPlayground.exe is ready.
start "" YARAPlayground.exe