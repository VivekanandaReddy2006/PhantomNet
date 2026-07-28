@echo off
echo Installing dependencies...
python -m pip install xhtml2pdf markdown
echo.
echo Running test script...
python test_pdf.py
echo.
pause
