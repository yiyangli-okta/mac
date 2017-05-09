#
# Copyright (C) 2017 Okta, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#!/usr/bin/env bash

# This script is initially based on Mike McQuaid's strap project, with additions:
# https://github.com/MikeMcQuaid/strap

set -e

# Keep sudo timestamp updated while Strap is running.
if [ "$1" = "--sudo-wait" ]; then
  while true; do
    mkdir -p "/var/db/sudo/$SUDO_USER"
    touch "/var/db/sudo/$SUDO_USER"
    sleep 1
  done
  exit 0
fi

[ "$1" = "--debug" ] && STRAP_DEBUG="1"
STRAP_SUCCESS=""

cleanup() {
  set +e
  if [ -n "$STRAP_SUDO_WAIT_PID" ]; then
    sudo kill "$STRAP_SUDO_WAIT_PID"
  fi
  sudo -k
  rm -f "$CLT_PLACEHOLDER"
  if [ -z "$STRAP_SUCCESS" ]; then
    if [ -n "$STRAP_STEP" ]; then
      echo "!!! $STRAP_STEP FAILED" >&2
    else
      echo "!!! FAILED" >&2
    fi
    if [ -z "$STRAP_DEBUG" ]; then
      echo "!!! Run '$0 --debug' for debugging output." >&2
      echo "!!! If you're stuck: file an issue with debugging output at:" >&2
      echo "!!!   $STRAP_ISSUES_URL" >&2
    fi
  fi
}

trap "cleanup" EXIT

if [ -n "$STRAP_DEBUG" ]; then
  set -x
else
  STRAP_QUIET_FLAG="-q"
  Q="$STRAP_QUIET_FLAG"
fi

STDIN_FILE_DESCRIPTOR="0"
[ -t "$STDIN_FILE_DESCRIPTOR" ] && STRAP_INTERACTIVE="1"

STRAP_GIT_NAME="$(id -F)"
STRAP_GIT_EMAIL=
STRAP_GITHUB_USER=
STRAP_GITHUB_TOKEN=
STRAP_ISSUES_URL="https://github.com/les-okta/mac/issues/new"

STRAP_FULL_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

abort() { STRAP_STEP="";   echo "!!! $*" >&2; exit 1; }
log()   { STRAP_STEP="$*"; echo "--> $*"; }
logn()  { STRAP_STEP="$*"; printf -- "--> $* "; }
logk()  { STRAP_STEP="";   echo "OK"; }

##
# Prompts a user for a value and potential confirmation value, and if both match, places the result
# in the $1 argument.  Can safely read secure values - see the $3 argument description below.
#
# Example usage
# -------------
#
# RESULT=''
# readval RESULT "Enter your value"
#
# # RESULT will now contain the read value.  For example:
# echo "$RESULT"
#
# Example password usage
# ----------------------
#
# readval RESULT "Enter your password" true
#
# If $3 is true (i.e. secure = true) nd you don't specify a 4th argument, the user will be prompted
# twice by default.
#
#
# Arguments:
#
#  $1: output variable, required.  The read result will be stored in this variable.
#
#  $2: prompt - a string, optional.
#               Defauls to "Enter value"
#               Do not end it with a colon character ':', as one will always be printed
#               at the end of the prompt string automatically.
#
#  $3: secure - a boolean, optional.
#               if true, the user's typing will not echo to the terminal.
#               if false, the user will see what they type.
#
#  $4: confirm - a boolean, optional.
#                Defaults to true if $secure = true.
#                if true, the user will be prompted again with an " (again)" suffix added to
#                the $prompt text.
##
readval() {
  local result=$1
  local prompt="$2" && [ -z "$prompt" ] && prompt="Enter value" #default value
  local secure=$3
  local confirm=$4 && [ -z "$confirm" ] && [ "$secure" = true ] && confirm=true
  local first
  local second

  while [ -z "$first" ] || [ -z "$second" ] || [ "$first" != "$second" ]; do
      printf "$prompt: "
      if [ "$secure" = true ]; then read -s first; printf "\n"; else read first; fi

      if [ "$confirm" = true ]; then
          printf "$prompt (again): "
          if [ "$secure" = true ]; then read -s second; printf "\n"; else read second; fi
      else
        # if we don't need confirmation, simulate a second entry to stop the loop:
        [ "$confirm" != true ] && second="$first"
      fi

      [ "$first" != "$second" ] && echo "Values are not equal. Please try again."
  done
  eval $result=\$first
}

_STRAP_MACOSX_VERSION="$(sw_vers -productVersion)"
echo "$_STRAP_MACOSX_VERSION" | grep $Q -E "^10.(9|10|11|12)" || { abort "Run Strap on Mac OS X 10.9/10/11/12."; }

[ "$USER" = "root" ] && abort "Run Strap as yourself, not root."
groups | grep $Q admin || abort "Add $USER to the admin group."

# Initialise sudo now to save prompting later.
log "Enter your password (for sudo access):"
sudo -k
sudo /usr/bin/true
[ -f "$STRAP_FULL_PATH" ]
sudo bash "$STRAP_FULL_PATH" --sudo-wait &
STRAP_SUDO_WAIT_PID="$!"
ps -p "$STRAP_SUDO_WAIT_PID" &>/dev/null
logk

logn "Checking ~/.bash_profile:"
[ ! -f "$HOME/.bash_profile" ] && echo && log "Creating ~/.bash_profile..." && touch "$HOME/.bash_profile"
logk

logn "Checking security settings:"
defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabled -bool false
defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabledForLocalFiles -bool false
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0
sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 1
sudo launchctl load /System/Library/LaunchDaemons/com.apple.alf.agent.plist 2>/dev/null
if [ -n "$STRAP_GIT_NAME" ] && [ -n "$STRAP_GIT_EMAIL" ]; then
  sudo defaults write /Library/Preferences/com.apple.loginwindow \
    LoginwindowText \
    "Found this computer? Please contact $STRAP_GIT_NAME at $STRAP_GIT_EMAIL."
fi
logk

logn "Checking keyboard and finder settings:"
# speed up the keyboard.  Defaults are *slow* for developers:
restart_finder=false
defaults write -g KeyRepeat -int 2
defaults write -g InitialKeyRepeat -int 14
if [ "$(defaults read com.apple.finder AppleShowAllFiles)" != "YES" ]; then
  defaults write com.apple.finder AppleShowAllFiles YES; # show hidden files
  restart_finder=true
fi
if [ "$(defaults read NSGlobalDomain AppleShowAllExtensions)" != "1" ]; then
  defaults write NSGlobalDomain AppleShowAllExtensions -bool true # show all file extensions
  restart_finder=true
fi
[ $restart_finder = true ] && killall Finder 2>/dev/null
logk

# Check and enable full-disk encryption.
logn "Checking full-disk encryption status:"
if fdesetup status | grep $Q -E "FileVault is (On|Off, but will be enabled after the next restart)."; then
  logk
elif [ -n "$STRAP_INTERACTIVE" ]; then
  echo && log "Enabling full-disk encryption on next reboot:"
  sudo fdesetup enable -user "$USER" | tee ~/Desktop/"FileVault Recovery Key.txt"
  logk
else
  echo && abort "Run 'sudo fdesetup enable -user \"$USER\"' to enable full-disk encryption."
fi

logn "Checking Xcode Developer Tools:"
XCODE_DIR=$(xcode-select -print-path 2>/dev/null || true)
if [ -z "$XCODE_DIR" ] || ! [ -f "$XCODE_DIR/usr/bin/git" ] || ! [ -f "/usr/include/iconv.h" ]; then

  log "Installing Xcode Command Line Tools..."
  CLT_PLACEHOLDER="/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress"
  sudo touch "$CLT_PLACEHOLDER"
  CLT_PACKAGE=$(softwareupdate -l | grep -B 1 -E "Command Line (Developer|Tools)" | \
                awk -F"*" '/^ +\*/ {print $2}' | sed 's/^ *//' | head -n1)
  sudo softwareupdate -i "$CLT_PACKAGE"
  sudo rm -f "$CLT_PLACEHOLDER"
  if ! [ -f "/usr/include/iconv.h" ]; then
    if [ -n "$STRAP_INTERACTIVE" ]; then
      echo
      logn "Requesting user install of Xcode Command Line Tools:"
      xcode-select --install
    else
      echo
      abort "Run 'xcode-select --install' to install the Xcode Command Line Tools."
    fi
  fi
fi
logk

# Check if the Xcode license is agreed to and agree if not.
xcode_license() {
  if /usr/bin/xcrun clang 2>&1 | grep $Q license; then
    if [ -n "$INTERACTIVE" ]; then
      logn "Asking for Xcode license confirmation:"
      sudo xcodebuild -license
      logk
    else
      abort "Run 'sudo xcodebuild -license' to agree to the Xcode license."
    fi
  fi
}
xcode_license

# Check and install any remaining software updates.
logn "Checking Apple software updates:"
if ! softwareupdate -l 2>&1 | grep $Q "No new software available."; then
  echo && log "Installing Apple software updates.  This could take a while..."
  sudo softwareupdate --install --all
  xcode_license
fi
logk

# Homebrew
logn "Checking Homebrew:"
if ! command -v brew >/dev/null 2>&1; then
  echo && log "Installing Homebrew..."
  yes '' | /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)";

  if [[ "$PATH" != *"/usr/local/bin"* ]]; then
    echo '' >> ~/.bash_profile;
    echo '# homebrew' >> ~/.bash_profile;
    echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bash_profile;
    source "$HOME/.bash_profile"
  fi
fi
logk

logn "Checking Homebrew Cask:"
if ! brew tap | grep ^caskroom/cask$ >/dev/null 2>&1; then
  echo && log "Tapping caskroom/cask..."
  brew tap caskroom/cask
fi
logk

logn "Checking Homebrew Versions:"
if ! brew tap | grep ^caskroom/versions$ >/dev/null 2>&1; then
  echo && log "Tapping caskroom/versions..."
  brew tap caskroom/versions
fi
logk

logn "Checking Homebrew updates:"
brew update
brew upgrade
logk

ensure_formula() {
  local command="$1" && [ -z "$command" ] && abort 'ensure_formula: $1 must be the command'
  local formula="$2" && [ -z "$formula" ] && abort 'ensure_formula: $2 must be the formula id'
  local name="$3" && [ -z "$3" ] && name="$formula"

  logn "Checking $name:"
  if ! ${command} list ${formula} >/dev/null 2>&1; then
    echo && log "Installing $name..."
    ${command} install ${formula}
  fi
  logk
}
ensure_brew() { ensure_formula "brew" $1 $2; }
ensure_cask() {
  local formula="$1" && [ -z "$formula" ] && abort 'ensure_cask: $1 must be the formula id'
  local apppath="$2"

  if [ ! -z "$apppath" ] && [ -d "$apppath" ]; then
    # simulate checking message:
    logn "Checking $formula:"
    if ! brew cask list "$formula" >/dev/null 2>&1; then
      logk
      log
      log "Note: $formula appears to have been manually installed to $apppath."
      log "If you want strap or homebrew to manage $formula version upgrades"
      log "automatically (recommended), you should manually uninstall $apppath"
      log "and re-run strap or manually run 'brew cask install $formula'."
      log
    else
      logk
    fi
  else
    ensure_formula "brew cask" "$formula"
  fi
}
ensure_brew_bash_profile() {
  local formula="$1"
  local path="$2"
  [ -z "$formula" ] && abort "ensure_brew_bash_profile: \$1 must be the formula id"
  [ -z "$path" ] && abort "ensure_brew_bash_profile: \$1 must be the brew script relative path"

  logn "Checking ${formula} in ~/.bash_profile:"
  if ! grep -q ${path} "$HOME/.bash_profile"; then
    echo && log "Enabling ${formula} in ~/.bash_profile"
    echo '' >> "$HOME/.bash_profile"
    echo "# strap:${formula}" >> "$HOME/.bash_profile"
    echo "if [ -f \$(brew --prefix)/${path} ]; then" >> "$HOME/.bash_profile"
    echo "  . \$(brew --prefix)/${path}" >> "$HOME/.bash_profile"
    echo 'fi' >> "$HOME/.bash_profile"
  fi
  logk
}

ensure_brew "bash-completion"
ensure_brew_bash_profile "bash-completion" "etc/bash_completion"

ensure_brew "openssl"

logn "Checking Okta Root CA Cert in OS X keychain:"
_STRAP_USER_DIR="$HOME/.strap/okta"
mkdir -p "$_STRAP_USER_DIR"
_STRAP_OKTA_ROOT_CA_CERT="$_STRAP_USER_DIR/Okta-Root-CA.pem"
[ -f "$_STRAP_OKTA_ROOT_CA_CERT" ] || curl -sL http://ca.okta.com/Okta-Root-CA.pem -o "$_STRAP_OKTA_ROOT_CA_CERT"
if ! sudo security find-certificate -c "Okta Root CA" /Library/Keychains/System.keychain >/dev/null 2>&1; then
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$_STRAP_OKTA_ROOT_CA_CERT"
fi
# sudo security delete-certificate -c "Okta Root CA"
logk

ensure_brew "jq"
ensure_brew "git"

logn "Checking git config:"
if git config --global github.user >/dev/null; then
  STRAP_GITHUB_USER="$(git config --global github.user)"
else
  [ -z "$STRAP_GITHUB_USER" ] && printf "\n" && readval STRAP_GITHUB_USER "Enter your GitHub username" false true
  git config --global github.user "$STRAP_GITHUB_USER"
fi

_STRAP_KEYCHAIN_ENTRY_LABEL="Okta Strap GitHub API personal access token"
_STRAP_GITHUB_API_TOKEN="${STRAP_GITHUB_TOKEN}"
_STRAP_GITHUB_TOKEN_COMMENT='User-supplied GitHub personal access token'
_store_github_token=false

if [ ! -z "$_STRAP_GITHUB_API_TOKEN" ]; then # user specified a token - let's check to see if it is valid:
  _http_code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: token $_STRAP_GITHUB_API_TOKEN" https://api.github.com)"
  [[ "$_http_code" == "4*" ]] && abort 'Specified STRAP_GITHUB_TOKEN is invalid. GitHub authentication failed.'
  _STRAP_GITHUB_TOKEN_COMMENT='User-supplied GitHub personal access token'
  _store_github_token=true
elif security find-internet-password -a "$STRAP_GITHUB_USER" -s api.github.com -l "$_STRAP_KEYCHAIN_ENTRY_LABEL" >/dev/null 2>&1; then
  _STRAP_GITHUB_API_TOKEN=$(security find-internet-password -a "$STRAP_GITHUB_USER" -s api.github.com -l "$_STRAP_KEYCHAIN_ENTRY_LABEL" -w)
  _store_github_token=false # it is already stored
else
  STRAP_GITHUB_PASSWORD=
  # no token yet, we need to get one.  This requires a github password:
  [ -z "$STRAP_GITHUB_PASSWORD" ] && readval STRAP_GITHUB_PASSWORD "Enter (or cmd-v paste) your GitHub password" true

  _STRAP_UTC_DATE="$(date -u +%FT%TZ)"
  _request_body="{\"scopes\":[\"repo\",\"admin:org\",\"admin:public_key\",\"admin:repo_hook\",\"admin:org_hook\",\"gist\",\"notifications\",\"user\",\"delete_repo\",\"admin:gpg_key\"],\"note\":\"Okta Strap-generated token, created at $_STRAP_UTC_DATE\"}"
  _creds="$STRAP_GITHUB_USER:$STRAP_GITHUB_PASSWORD"
  _response=$(curl --silent --show-error -i -u "$_creds" -H "Content-Type: application/json" -X POST -d "$_request_body" https://api.github.com/authorizations)
  _status=$(echo "$_response" | grep 'HTTP/1.1' | awk '{print $2}')
  _otp_type=$(echo "$_response" | grep 'X-GitHub-OTP:' | awk '{print $3}')
  _response_body=$(echo "$_response" | sed '1,/^\r\{0,1\}$/d')

  if [ ! -z "$_otp_type" ]; then #2factor required - ask for code:
    _strap_github_otp=
    readval _strap_github_otp "Enter GitHub two-factor code"

    #try again, this time with the OTP code
    _response_body=$(curl --silent --show-error -u "$_creds" -H "X-GitHub-OTP: $_strap_github_otp" -H "Content-Type: application/json" -X POST -d "$_request_body" https://api.github.com/authorizations)
    #_status=$(echo "$_response" | grep 'HTTP/1.1' | awk '{print $2}')
    #_otp_type=$(echo "$_response" | grep 'X-GitHub-OTP:' | awk '{print $3}')
    #_response_body=$(echo "$_response" | sed '1,/^\r\{0,1\}$/d')
  fi

  _STRAP_GITHUB_API_TOKEN=$(echo "$_response_body" | jq -er '.token')
  _STRAP_GITHUB_TOKEN_COMMENT=$(echo "$_response_body" | jq -er '.url') # use the token url as the comment in this case
  _store_github_token=true

  if [ -z "$_STRAP_GITHUB_API_TOKEN" ] || [ "$_STRAP_GITHUB_API_TOKEN" == "null" ]; then
      abort 'Unable to create GitHub API personal access token'
  fi
fi
if [ $_store_github_token = true ]; then
  security add-internet-password -r htps -s api.github.com -l "$_STRAP_KEYCHAIN_ENTRY_LABEL" -j "$_STRAP_GITHUB_TOKEN_COMMENT" -t http -a "$STRAP_GITHUB_USER" -w "$_STRAP_GITHUB_API_TOKEN" || { abort "Unable to save GitHub API personal access token to Mac OS X Keychain";}
fi

if git config --global user.email >/dev/null; then
  STRAP_GIT_EMAIL="$(git config --global user.email)"
else
  if [ -z "$STRAP_GIT_EMAIL" ]; then

    #try to find it from the GitHub account:
    JSON=$(curl --silent --show-error -u "$STRAP_GITHUB_USER:$_STRAP_GITHUB_API_TOKEN" https://api.github.com/user/emails)

    STRAP_GIT_EMAIL=$(echo "$JSON" | jq -er '.[] | select(.primary == true) | .email')

    if [ -z "$STRAP_GIT_EMAIL" ] || [ "$STRAP_GIT_EMAIL" == "null" ]; then
      #read from the user, but ensure the read value has an 'at' sign:
      while [[ "$STRAP_GIT_EMAIL" != *"@"* ]]; do
        readval STRAP_GIT_EMAIL "Enter your email address" false true
      done
    fi
  fi

  git config --global user.email "$STRAP_GIT_EMAIL"
fi

if git config --global user.name >/dev/null; then
  STRAP_GIT_NAME="$(git config --global user.name)"
else
  [ -z "$STRAP_GIT_NAME" ] && readval STRAP_GIT_NAME "Enter your first and last name"
  git config --global user.name "$STRAP_GIT_NAME"
fi

if ! git config --global push.default >/dev/null; then
  git config --global push.default simple
fi

if ! git config --global branch.autosetupmerge >/dev/null; then
  git config --global branch.autosetupmerge always
fi

if git credential-osxkeychain 2>&1 | grep $Q "git.credential-osxkeychain"; then

  if [ "$(git config --global credential.helper)" != "osxkeychain" ]; then
    git config --global credential.helper osxkeychain
  fi

  printf "protocol=https\nhost=github.com\n" | git credential-osxkeychain erase
  printf "protocol=https\nhost=github.com\nusername=%s\npassword=%s\n" \
        "$STRAP_GITHUB_USER" "$_STRAP_GITHUB_API_TOKEN" \
        | git credential-osxkeychain store
fi

logk

#####################################
# SSH Begin
#####################################

logn "Checking SSH config:"
_STRAP_SSH_DIR="$HOME/.ssh"
mkdir -p $_STRAP_SSH_DIR
chmod 700 $_STRAP_SSH_DIR

_STRAP_SSH_CONFIG_FILE="$_STRAP_SSH_DIR/config"
_STRAP_SSH_AUTHZ_KEYS="$_STRAP_SSH_DIR/authorized_keys"
[ -f "$_STRAP_SSH_AUTHZ_KEYS" ] || touch "$_STRAP_SSH_AUTHZ_KEYS"
chmod 600 "$_STRAP_SSH_AUTHZ_KEYS"

_STRAP_SSH_KNOWN_HOSTS="$_STRAP_SSH_DIR/known_hosts"
[ -f "$_STRAP_SSH_KNOWN_HOSTS" ] || touch "$_STRAP_SSH_KNOWN_HOSTS"
chmod 600 "$_STRAP_SSH_KNOWN_HOSTS"

_STRAP_SSH_KEY="$_STRAP_SSH_DIR/id_rsa"
_STRAP_SSH_PUB_KEY="$_STRAP_SSH_KEY.pub"
_STRAP_SSH_KEY_PASSPHRASE="$(openssl rand 48 -base64)"

if [[ $_STRAP_MACOSX_VERSION == "10.12"* ]] && [ ! -f "$_STRAP_SSH_CONFIG_FILE" ]; then
  touch $_STRAP_SSH_CONFIG_FILE
  echo 'Host *' >> $_STRAP_SSH_CONFIG_FILE
  echo '  UseKeychain yes' >> $_STRAP_SSH_CONFIG_FILE
  echo '  AddKeysToAgent yes' >> $_STRAP_SSH_CONFIG_FILE
fi

_strap_created_ssh_key=false

if [ ! -f "$_STRAP_SSH_KEY" ]; then

  [ -z "$STRAP_GIT_EMAIL" ] && readval STRAP_GIT_EMAIL "Enter your email address" false true

  _STRAP_SSH_AGENT_PID=$(ps aux|grep '[s]sh-agent -s'|sed -E -n 's/[^[:space:]]+[[:space:]]+([[:digit:]]+).*/\1/p')
  if [ -z "$_STRAP_SSH_AGENT_PID" ]; then
    ssh-agent -s >/dev/null
  fi

  ssh-keygen -t rsa -b 4096 -C "strap auto-generated key for $STRAP_GIT_EMAIL" -P "$_STRAP_SSH_KEY_PASSPHRASE" -f "$_STRAP_SSH_KEY" -q

  _strap_created_ssh_key=true

  expect << EOF
    spawn ssh-add -K $_STRAP_SSH_KEY
    expect "Enter passphrase"
    send "$_STRAP_SSH_KEY_PASSPHRASE\r"
    expect eof
EOF

fi

chmod 400 "$_STRAP_SSH_KEY"
chmod 400 "$_STRAP_SSH_PUB_KEY"
[ -f "$_STRAP_SSH_CONFIG_FILE" ] && chmod 600 "$_STRAP_SSH_CONFIG_FILE"
logk
#####################################
# SSH End
#####################################

#####################################
# Github SSH Key Begin
#####################################
logn "Checking GitHub SSH config:"

_STRAP_GITHUB_KNOWN_HOST="github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="

if [ $_strap_created_ssh_key = true ]; then
  _STRAP_SSH_PUB_KEY_CONTENTS="$(<$_STRAP_SSH_PUB_KEY)"

  _NOW="$(date -u +%FT%TZ)"
  _RESULT=$(curl --silent --show-error --output /dev/null --write-out %{http_code} \
         -u "$STRAP_GITHUB_USER:$_STRAP_GITHUB_API_TOKEN" \
         -d "{ \"title\": \"Okta Strap-generated RSA public key on $_NOW\", \"key\": \"$_STRAP_SSH_PUB_KEY_CONTENTS\" }" \
         https://api.github.com/user/keys) 2>/dev/null

  [ "$_RESULT" -ne "201" ] && abort 'Unable to upload Strap-generated RSA private key to GitHub'
fi

# Add github to known hosts:
[ ! -f "$_STRAP_SSH_KNOWN_HOSTS" ] && touch "$_STRAP_SSH_KNOWN_HOSTS"
if ! grep "^github.com" "$_STRAP_SSH_KNOWN_HOSTS" >/dev/null 2>&1; then
  echo "$_STRAP_GITHUB_KNOWN_HOST" >> "$_STRAP_SSH_KNOWN_HOSTS"
fi

chmod 600 "$_STRAP_SSH_KNOWN_HOSTS"

logk
#####################################
# Github SSH Key End
#####################################

ensure_brew "gnupg"
ensure_brew "httpie"
ensure_brew "mysql"
ensure_brew "percona-toolkit"
ensure_brew "liquidprompt"
ensure_brew_bash_profile "liquidprompt" "share/liquidprompt"
ensure_cask "java"
ensure_cask "java7"
ensure_cask "jce-unlimited-strength-policy"

_OLD_JENV_GLOBAL=""
logn "Checking jenv:"
if brew list | grep ^jenv$ >/dev/null 2>&1; then
  eval "$(jenv init -)"
  _OLD_JENV_GLOBAL="$(jenv global)"
else
  echo
  log "Installing jenv..."
  brew install jenv
  export PATH="$HOME/.jenv/bin:$PATH"
  eval "$(jenv init -)"
  jenv add "$(/usr/libexec/java_home)"
  jenv global 1.8
  jenv enable-plugin export
  jenv enable-plugin maven
  jenv enable-plugin groovy
  jenv enable-plugin springboot
fi
logk

logn "Checking jenv in ~/.bash_profile:"
if ! grep -q jenv "$HOME/.bash_profile"; then
  echo && log "Enabling jenv in ~/.bash_profile..."
  echo '' >> ~/.bash_profile;
  echo '# strap:jenv (will also set JAVA_HOME env var due to jenv export plugin)' >> ~/.bash_profile;
  echo 'export PATH="$HOME/.jenv/bin:$PATH"' >> ~/.bash_profile;
  echo 'if command -v jenv >/dev/null; then eval "$(jenv init -)"; fi;' >> ~/.bash_profile;
fi
logk

if ! jenv versions --bare | grep -q "^1.8$"; then jenv add "$(/usr/libexec/java_home)"; fi
if ! jenv versions --bare | grep -q "^1.7$"; then jenv add "$(/usr/libexec/java_home -v 1.7)"; fi

ensure_java_cert() {
  local cert="$1" && [ ! -f "$cert" ] && abort 'add_java_cert: $1 is not a file'
  local alias="$2" && [ -z "$alias" ] && abort 'add_java_cert: $2 is required and must be a keystore alias name'
  JAVA_HOME="$(jenv javahome)"
  if ! sudo keytool -list -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass "changeit" -alias "$alias" >/dev/null 2>&1; then
    sudo keytool -import -trustcacerts -noprompt -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass "changeit" -alias "$alias" -file "$cert" >/dev/null 2>&1
  fi
  #sudo keytool -delete -noprompt -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass "changeit" -alias "$alias"
}

logn "Checking Okta Root CA Cert in Java Keystore:"
jenv global 1.8
ensure_java_cert "$_STRAP_OKTA_ROOT_CA_CERT" 'oktaroot'
jenv global 1.7
ensure_java_cert "$_STRAP_OKTA_ROOT_CA_CERT" 'oktaroot'
logk

logn "Checking Okta Internet CA Cert in Java Keystore:"
_STRAP_OKTA_NET_CA_CERT="$_STRAP_USER_DIR/Okta-Internet-CA.pem"
[ -f "$_STRAP_OKTA_NET_CA_CERT" ] || curl -sL http://ca.okta.com/Okta-Internet-CA.pem -o "$_STRAP_OKTA_NET_CA_CERT"
jenv global 1.8
ensure_java_cert "$_STRAP_OKTA_NET_CA_CERT" "mavensrv"
jenv global 1.7
ensure_java_cert "$_STRAP_OKTA_NET_CA_CERT" "mavensrv"
logk

logn "Checking java7 unlimited cryptography:"
jenv global 1.7
JAVA_HOME="$(jenv javahome)"
JCE_DIR="$JAVA_HOME/jre/lib/security"
if [ -f "$JCE_DIR/local_policy.jar.orig" ]; then
  logk
else
  echo
  log "Installing java7 unlimited cryptography..."
  pushd $JCE_DIR >/dev/null
  # backup existing JVM files that we will replace just in case:
  sudo mv local_policy.jar local_policy.jar.orig
  sudo mv US_export_policy.jar US_export_policy.jar.orig
  sudo curl -sLO 'http://download.oracle.com/otn-pub/java/jce/7/UnlimitedJCEPolicyJDK7.zip' -H 'Cookie: oraclelicense=accept-securebackup-cookie'
  sudo unzip -q UnlimitedJCEPolicyJDK7.zip
  sudo mv UnlimitedJCEPolicy/US_export_policy.jar .
  sudo mv UnlimitedJCEPolicy/local_policy.jar .
  sudo chown root:wheel US_export_policy.jar
  sudo chown root:wheel local_policy.jar
  # cleanup download file:
  sudo rm -rf UnlimitedJCEPolicyJDK7.zip
  sudo rm -rf UnlimitedJCEPolicy
  popd >/dev/null
  logk
fi

# restore original jenv global if there was one:
[ ! -z "$_OLD_JENV_GLOBAL" ] && jenv global "$_OLD_JENV_GLOBAL"

ensure_brew "maven"
ensure_brew "groovy"
ensure_brew "lhazlewood/tap/spin"

ensure_brew 'perl'
ensure_brew 'cpanminus'
logn "Checking perl cpan DBD::mysql module:"
if ! perl -MDBD::mysql -e 1 >/dev/null 2>&1; then
  echo && log "Installing perl cpan DBD::mysql module..."
  cpanm DBD::mysql >/dev/null
fi
logk

######################################
# Docker Begin
######################################
#
# We *DO NOT* run 'Docker for Mac' on purpose.  Docker for Mac does not yet
# support bridge networks on the host OS (Mac OS X) into the docker containers,
# which means you can't run the product (or in IntelliJ) in Mac OS because
# network connections from the host OS into the docker containers are not possible.
#
# More info: https://github.com/docker/docker/issues/22753
#
# Because of this pretty severe limitation, we explicitly install the same functionality
# as individual commands, including most notably virtualbox and docker-machine.  These
# provide the same functionality as 'Docker for Mac', but allow bridge networks.
#
# Note that this approach is also a fully supported usage scenario for Docker.  The
# Docker documentation explicitly indicates this is a fine approach for 'power users'
# or scenarios where you might need to run more than one Docker VM.  See this page:
#
# https://docs.docker.com/docker-for-mac/docker-toolbox/#setting-up-to-run-docker-for-mac
#
# (specifically the 'Docker Toolbox and Docker for Mac coexistence' section).
ensure_cask "virtualbox"
ensure_brew "docker"
ensure_brew "docker-machine"
ensure_brew "docker-compose"
ensure_brew "docker-clean"

# We name our docker vm 'dev', so ensure this is in bash profile:
logn "Checking 'dev' docker-machine in ~/.bash_profile:"
if ! grep -q 'docker-machine env dev' "$HOME/.bash_profile"; then
  echo && log "Enabling dev docker-machine check in ~/.bash_profile"
  echo ''  >> "$HOME/.bash_profile"
  echo '# strap:docker-machine:dev'  >> "$HOME/.bash_profile"
  echo 'if command -v docker-machine >/dev/null && [ "$(docker-machine status dev 2> /dev/null)" == "Running" ]; then'  >> "$HOME/.bash_profile"
  echo '  eval "$(docker-machine env dev)"' >> "$HOME/.bash_profile"
  echo 'fi'  >> "$HOME/.bash_profile"
fi
logk
######################################
# Docker End
######################################

ensure_cask "iterm2" "/Applications/iTerm.app"
ensure_cask "intellij-idea" "/Applications/IntelliJ IDEA.app"
# TODO: add gmavenplus plugin to intellij
#echo
#log "Installing GMavenPlus plugin for intellij-idea..."
#INTELLIJ_VERSION=`brew cask info intellij-idea | head -n1 | awk 'BEGIN { FS = "[:. ]" }; { print $3"."$4 }'`
#curl -s \
#   https://raw.githubusercontent.com/mycila/gmavenplus-intellij-plugin/master/gmavenplus-intellij-plugin.jar > \
#   ~/Library/Application\ Support/IntelliJIdea$INTELLIJ_VERSION/gmavenplus-intellij-plugin.jar
#logk

logn "Checking Okta thirdparty tools:"
mkdir -p "$HOME/okta"
if [ ! -d "$HOME/okta/thirdparty" ]; then
  pushd "$HOME/okta" >/dev/null
  git clone git@github.com:okta/thirdparty.git
  popd >/dev/null
else
  pushd "$HOME/okta/thirdparty" >/dev/null
  if [ "$(git rev-parse --abbrev-ref HEAD)" == "master" ] && git diff-index --quiet HEAD >/dev/null; then
    git pull >/dev/null
  fi
  popd >/dev/null
fi
logk

githubdl() {
  local repo="$1" && [ -z "$repo" ] && abort 'githubdl: $1 must be a qualified repo, e.g. user/reponame'
  local path="$2" && [ -z "$path" ] && abort 'githubdl: $2 must be the repo file path, e.g. file.txt or my/other/file.txt'
  local file="$3" && [ -z "$file" ] && abort 'githubdl: $3 must be the destination file'
  local filedir="${file%/*}"
  mkdir -p "$filedir"
  curl -H "Authorization: token $_STRAP_GITHUB_API_TOKEN" \
       -H "Accept: application/vnd.github.v3.raw" \
       -s -L "https://api.github.com/repos/$repo/contents/$path" --output "$file"
}

ensure_strap_file() {
  local path="$1" && [ -z "$path" ] && abort 'ensure_strap_file: $1 must be a strap file path'
  local dstdir="$2" && [ -z "$dstdir" ] && dstdir="$_STRAP_USER_DIR" #default
  local file="$dstdir/$path"
  [ ! -f "$file" ] && githubdl 'okta/strap' "$path" "$file"
  chmod go-rwx "$file"
}

ensure_cask 'tunnelblick' '/Applications/Tunnelblick.app'

logn "Checking tunnelblick config files:"
# we don't want to use $_STRAP_USER_DIR to store client.key or client.crt;
# if the user deletes ~/.strap (thinking they're 'cleaning up'), we don't want
# them to lose the ITSON-issued client.crt file (whereby their VPN would stop working),
# so we keep these files in a separate directory that holds tunnelblick-only config:
_dstdir="$HOME/.tunnelblick/okta"
_path='okta-vpc.tblk/client.down' && ensure_strap_file "$_path" "$_dstdir" && chmod u+x "$_dstdir/$_path"
_path='okta-vpc.tblk/client.up' && ensure_strap_file "$_path" "$_dstdir" && chmod u+x "$_dstdir/$_path"
ensure_strap_file 'okta-vpc.tblk/okta-vpc-dev.ovpn' "$_dstdir"
ensure_strap_file 'okta-vpc.tblk/okta_internal_ca.crt' "$_dstdir"
_path='okta-vpc.tblk/client.key'
_src="$HOME/$_path"
_dst="$_dstdir/$_path"
_filedir="${_dst%/*}"
if [ ! -f "$_dst" ]; then
  mkdir -p "$_filedir"
  if [ -f "$_src" ]; then
    cp "$_src" "$_dst" >/dev/null
  else
    _STRAP_UTC_DATE="$(date -u +%FT%TZ)"
    export _STRAP_CLIENT_KEY_PASS="$(openssl rand 48 -base64)"
    openssl genrsa -aes256 -passout env:_STRAP_CLIENT_KEY_PASS -out "$_dst" 2048 >/dev/null 2>&1 && chmod 400 "$_dst" >/dev/null
    openssl req -batch -sha256 -new -subj "/C=US/O=Okta, Inc./OU=Engineering/CN=$STRAP_GIT_NAME" -days 1825 -key "$_dst" -passin env:_STRAP_CLIENT_KEY_PASS -out "$_filedir/client.csr"
    if ! security find-generic-password -a "$USER" -s 'okta-strap-tunnelblick-dev-vpc' >/dev/null 2>&1; then
      security add-generic-password -a "$USER" -s 'okta-strap-tunnelblick-dev-vpc' -l "Okta Strap Tunnelblick client.key passphrase" -j "Okta strap-generated passphrase for $_dst on $_STRAP_UTC_DATE" -w "$_STRAP_CLIENT_KEY_PASS"
    fi
    # security delete-generic-password -a "$USER" -s 'okta-vpc'
    unset _STRAP_CLIENT_KEY_PASS
  fi
fi
_path='okta-vpc.tblk/client.crt'
_src="$HOME/$_path"
_dst="$_dstdir/$_path"
if [ ! -f "$_dst" ] && [ -f "$_src" ]; then cp "$_src" "$_dst" >/dev/null; fi
chmod -R go-rwx "$HOME/.tunnelblick"
logk

logn 'Checking /etc/hosts loopback aliases:'
ensure_loopback() {
  local alias="$1" && [ -z "$1" ] && abort 'ensure_loopback: $1 must be an alias'
  alias="$(echo -e ${alias} | tr -d '[:space:]')" # strip any whitespace in the hostname
  local file="/etc/hosts"
  if ! grep -F "${alias}" "$file" >/dev/null 2>&1; then
    sudo bash -c "echo \"127.0.0.1 ${alias}\" >> \"$file\""
  fi
}
_srcfilename="loopback-aliases.txt"
_srcfile="$HOME/.strap/okta/$_srcfilename"
ensure_strap_file "$_srcfilename"
while read line; do ensure_loopback "$line"; done <"$_srcfile"
logk

ensure_brew "nvm"
mkdir -p "$HOME/.nvm"
logn "Checking nvm in ~/.bash_profile:"
if ! grep -q "NVM_DIR" "$HOME/.bash_profile"; then
  echo && log "Enabling nvm in ~/.bash_profile:"
  echo '' >> "$HOME/.bash_profile"
  echo "# strap:nvm" >> "$HOME/.bash_profile"
  echo 'export NVM_DIR="$HOME/.nvm"' >> "$HOME/.bash_profile"
  echo 'if [ -f "$(brew --prefix)/opt/nvm/nvm.sh" ]; then' >> "$HOME/.bash_profile"
  echo ' . "$(brew --prefix)/opt/nvm/nvm.sh"' >> "$HOME/.bash_profile"
  echo 'fi' >> "$HOME/.bash_profile"
fi
logk

if ! command -v nvm >/dev/null; then
  export NVM_DIR="$HOME/.nvm"
  . "$(brew --prefix)/opt/nvm/nvm.sh"
fi

version="5.6.0"
logn "Checking node $version:"
if command -v nvm >/dev/null && ! nvm ls "$version" >/dev/null; then
  echo && log "Installing node $version..."
  nvm install "$version" >/dev/null
fi
logk

version="3.9.6"
logn "Checking npm $version:"
if [ "$(npm --version)" != "$version" ]; then
  echo && log "Installing npm $vesion..."
  npm install -g "npm@$version" >/dev/null
fi
logk

logn "Checking grunt:"
if ! command -v grunt >/dev/null; then
  echo && log "Installing grunt..."
  npm config set strict-ssl false
  npm install -g grunt-cli >/dev/null
  npm config delete strict-ssl
fi
logk

ensure_brew 'yarn'
ensure_brew 'phantomjs'

logn "Checking .npmrc:"
file="$HOME/.npmrc"
[ ! -f "$file" ] && githubdl 'okta/strap' '.npmrc' "$file"
if ! grep -q "^cafile" "$file"; then echo "cafile=$_STRAP_OKTA_ROOT_CA_CERT" >> "$file"; fi
logk

logn "Checking okta_bash_profile in ~/.bash_profile:"
ensure_strap_file "okta_bash_profile"
if ! grep -q "okta_bash_profile" "$HOME/.bash_profile"; then
  echo && log "Enabling okta_bash_profile in ~/.bash_profile"
  echo '' >> "$HOME/.bash_profile"
  echo "# strap:okta_bash_profile" >> "$HOME/.bash_profile"
  echo "if [ -f \"\$HOME/.strap/okta/okta_bash_profile\" ]; then" >> "$HOME/.bash_profile"
  echo "  . \"\$HOME/.strap/okta/okta_bash_profile\"" >> "$HOME/.bash_profile"
  echo 'fi' >> "$HOME/.bash_profile"
fi
. "$HOME/.strap/okta/okta_bash_profile"
logk

logn 'Checking ~/okta/override.properties:'
file="$OKTA_HOME/override.properties"
[ ! -f "$file" ] && echo 'default.services.host=192.168.99.100' > "$file"
logk

logn 'Checking ~/okta/spin.groovy:'
file="$OKTA_HOME/spin.groovy"
[ ! -f "$file" ] && githubdl 'okta/strap' 'spin.groovy' "$file"
logk

file="$OKTA_HOME/certs/tomcat-jmx-keystore.jks"
logn "Checking $file:"
if [ ! -f "$file" ]; then
  mkdir -p "$OKTA_HOME/certs"
  keytool -genkeypair -alias seleniumtest -keyalg RSA -validity 365 -keystore "$file" -storepass "$JMXKEYSTOREPASS" -keypass "$JMXKEYSTOREPASS" -dname "CN=Engineering Productivity, OU=Eng CI, O=Okta, L=San Francisco, S=CA, C=US"
fi
logk

file="$OKTA_HOME/certs/tomcat-jmx-truststore.jks"
logn "Checking $file:"
if [ ! -f "$file" ]; then
  mkdir -p "$OKTA_HOME/certs"
  echo "yes" | keytool -v -noprompt -alias jmxTrustStore -import -file "$_STRAP_OKTA_ROOT_CA_CERT" -keystore "$file" --storepass "$JMXKEYSTOREPASS" >/dev/null 2>&1
fi
logk

# make config/state a little more secure, just in case:
chmod -R go-rwx "$HOME/.strap"

STRAP_SUCCESS="1"
log "Your system is now Strap'd!"