#!/bin/bash

virtualenv .
rm .gitignore
source bin/activate
pip3 install -r requirements.txt
deactivate