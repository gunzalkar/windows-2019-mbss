
@echo off
setlocal

:: Set the Python version and installation path
set PYTHON_VERSION=3.11.0
set INSTALL_PATH=C:\Python%%PYTHON_VERSION%%

:: URL to download Python
set PYTHON_URL=https://www.python.org/ftp/python/%%PYTHON_VERSION%%/python-%%PYTHON_VERSION%%-amd64.exe

:: Temporary file for downloading Python
set TEMP_PYTHON_INSTALLER=%%TEMP%%\python-installer.exe

echo Downloading Python %%PYTHON_VERSION%%...
bitsadmin /transfer "DownloadPython" %%PYTHON_URL%% %%TEMP_PYTHON_INSTALLER%%

echo Installing Python %%PYTHON_VERSION%%...
%%TEMP_PYTHON_INSTALLER%% /quiet InstallAllUsers=1 PrependPath=1 TargetDir=%%INSTALL_PATH%%

echo Python %%PYTHON_VERSION%% installed successfully!

:: Clean up
del %%TEMP_PYTHON_INSTALLER%%

endlocal
pause
