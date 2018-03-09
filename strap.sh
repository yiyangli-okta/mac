#!/usr/bin/env bash

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
#
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

# allow subshells to call these functions:
export -f abort
export -f log
export -f logn
export -f logk
export -f readval

export _STRAP_MACOSX_VERSION="$(sw_vers -productVersion)"
echo "$_STRAP_MACOSX_VERSION" | grep $Q -E "^10.(9|10|11|12|13)" || { abort "Run Strap on Mac OS X 10.9/10/11/12/13."; }

[ "$USER" = "root" ] && abort "Run Strap as yourself, not root."
groups | grep $Q admin || abort "Add $USER to the admin group."

# Detect the user's login shell rc file.
detect_login_shell_and_rc_file() {
  export STRAP_SHELL_CANONICAL=$(basename $SHELL)

  local STRAP_SHELL_RC_FILENAME
  case $STRAP_SHELL_CANONICAL in
    'zsh') STRAP_SHELL_RC_FILENAME='.zshrc';;
    'bash') STRAP_SHELL_RC_FILENAME='.bash_profile';;
    *) echo "!!! Warning: unknown shell \$SHELL='$SHELL' has been detected. No shell rc files (e.g. '~/.bashrc') will be modified."
    ;;
  esac

  export STRAP_SHELL_RC_FILE="$HOME/$STRAP_SHELL_RC_FILENAME"
}
detect_login_shell_and_rc_file
append_line_to_shell_rc_file() {
  echo $1 >> $STRAP_SHELL_RC_FILE
}
export append_line_to_shell_rc_file

logn "Checking $STRAP_SHELL_RC_FILE:"
[ ! -f $STRAP_SHELL_RC_FILE ] && echo && log "Creating $STRAP_SHELL_RC_FILE..." && touch $STRAP_SHELL_RC_FILE
logk

# Initialise sudo now to save prompting later.
log "Enter your password (for sudo access):"
sudo -k
sudo /usr/bin/true
[ -f "$STRAP_FULL_PATH" ]
sudo bash "$STRAP_FULL_PATH" --sudo-wait &
STRAP_SUDO_WAIT_PID="$!"
ps -p "$STRAP_SUDO_WAIT_PID" &>/dev/null
logk

export _STRAP_USER_DIR="$HOME/.strap/okta"
mkdir -p "$_STRAP_USER_DIR"

logn "Checking security settings:"
defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabled -bool false
defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabledForLocalFiles -bool false
sudo defaults write com.apple.screensaver askForPassword -int 1
sudo defaults write com.apple.screensaver askForPasswordDelay -int 0
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
    append_line_to_shell_rc_file ''
    append_line_to_shell_rc_file '# homebrew'
    append_line_to_shell_rc_file 'export PATH="/usr/local/bin:$PATH"'
    source $STRAP_SHELL_RC_FILE
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
ensure_brew_shell_rc_file() {
  local formula="$1"
  local path="$2"
  [ -z "$formula" ] && abort "ensure_brew_shell_rc_file: \$1 must be the formula id"
  [ -z "$path" ] && abort "ensure_brew_shell_rc_file: \$1 must be the brew script relative path"

  logn "Checking ${formula} in $STRAP_SHELL_RC_FILE:"
  if ! grep -q ${path} $STRAP_SHELL_RC_FILE; then
    echo && log "Enabling ${formula} in $STRAP_SHELL_RC_FILE"
    append_line_to_shell_rc_file ''
    append_line_to_shell_rc_file "# strap:${formula}"
    append_line_to_shell_rc_file "if [ -f \$(brew --prefix)/${path} ]; then"
    append_line_to_shell_rc_file "  . \$(brew --prefix)/${path}"
    append_line_to_shell_rc_file 'fi'
  fi
  logk
}

# allow subshells to call these functions:
export -f ensure_formula
export -f ensure_brew
export -f ensure_cask
export -f ensure_brew_shell_rc_file

if [ $STRAP_SHELL_CANONICAL = 'bash' ]; then
  ensure_brew "bash-completion"
  ensure_brew_shell_rc_file "bash-completion" "etc/bash_completion"
fi

ensure_brew "openssl"
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
export _STRAP_GITHUB_API_TOKEN="${STRAP_GITHUB_TOKEN}"
_STRAP_GITHUB_TOKEN_COMMENT='User-supplied GitHub personal access token'
_store_github_token=false

if [ ! -z "$_STRAP_GITHUB_API_TOKEN" ]; then # user specified a token - let's check to see if it is valid:
  _http_code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: token $_STRAP_GITHUB_API_TOKEN" https://api.github.com)"
  [[ "$_http_code" == "4*" ]] && abort 'Specified STRAP_GITHUB_TOKEN is invalid. GitHub authentication failed.'
  _STRAP_GITHUB_TOKEN_COMMENT='User-supplied GitHub personal access token'
  _store_github_token=true
elif security find-internet-password -a "$STRAP_GITHUB_USER" -s api.github.com -l "$_STRAP_KEYCHAIN_ENTRY_LABEL" >/dev/null 2>&1; then
  export _STRAP_GITHUB_API_TOKEN=$(security find-internet-password -a "$STRAP_GITHUB_USER" -s api.github.com -l "$_STRAP_KEYCHAIN_ENTRY_LABEL" -w)
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

  export _STRAP_GITHUB_API_TOKEN=$(echo "$_response_body" | jq -er '.token')
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
export -f githubdl
export -f ensure_strap_file

_srcfilename="strap-private.sh"
_srcfile="$HOME/.strap/okta/$_srcfilename"
ensure_strap_file "$_srcfilename"
source "$_srcfile"

# make config/state a little more secure, just in case:
chmod -R go-rwx "$HOME/.strap"

STRAP_SUCCESS="1"
log "Your system is now Strap'd!"
