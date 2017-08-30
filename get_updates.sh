#!/usr/bin/env bash

API_WEB_ROOT="/var/www/api.insecurityscanner.com"
ANG_WEB_ROOT="/var/www/insecurityscanner.com"

# API
cd $API_WEB_ROOT
git reset --hard [HEAD]
git pull
composer update

# Frontend
cd $ANG_WEB_ROOT
git reset --hard [HEAD]
git pull
