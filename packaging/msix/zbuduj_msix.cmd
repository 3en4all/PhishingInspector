@echo off
rem Jedno klikniecie: buduje paczke MSIX do Microsoft Store i instaluje ja testowo na tym PC.
rem Wynik: dist\PhishingInspector-<wersja>-x64.msix
cd /d "%~dp0..\.."
powershell -NoProfile -ExecutionPolicy Bypass -File packaging\msix\build_msix.ps1 -Test
pause
