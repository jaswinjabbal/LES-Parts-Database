@echo off
echo Installing dependencies...
pip install -r requirements.txt

echo Starting the Flask app...
python app.py

pause
