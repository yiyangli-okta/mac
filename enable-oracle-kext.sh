#!/bin/sh

# Enable the Oracle Developer ID to allow Oracle-created kernel extensions.
# This is required for virtualbox:
/usr/sbin/spctl kext-consent add VB5E2TV963
