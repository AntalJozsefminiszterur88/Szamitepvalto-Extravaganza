@echo off
REM build_linux.bat - Build a Linux executable using PyInstaller via WSL
REM Requires WSL with Python installed. PyInstaller will be installed if missing.

setlocal
set PROJ_DIR=%~dp0

wsl bash -ic "cd $(wslpath '%PROJ_DIR%') && python3 -m pip install --user pyinstaller && python3 -m PyInstaller --onefile main.py"

endlocal
