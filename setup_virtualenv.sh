#!/bin/bash

GITEMP=".gitignore_temp"

mv .gitignore $GITEMP
virtualenv .
mv $GITEMP .gitignore
source bin/activate
pip3 install -r requirements.txt