$PYTHON3=(Get-Command python).Path

virtualenv -p $PYTHON3 .
Remove-Item .gitignore
Copy-Item .\malurlscan.conf_example -Destination .\malurlscan.conf
.\Scripts\activate
pip3 install -r requirements.txt
deactivate