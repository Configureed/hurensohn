@echo off
echo Cleaning project for GitHub upload...
echo.

echo Deleting backend node_modules...
if exist "backend\node_modules" rd /s /q "backend\node_modules"

echo Deleting frontend node_modules...
if exist "frontend\node_modules" rd /s /q "frontend\node_modules"

echo Deleting frontend dist/build...
if exist "frontend\dist" rd /s /q "frontend\dist"

echo Deleting Python caches...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"

echo.
echo DONE! You can now upload everything to GitHub.
echo Note: node_modules will be reinstalled on the server automatically.
pause