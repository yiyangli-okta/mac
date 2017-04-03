#
# Copyright (C) 2016 Stormpath, Inc.
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

STRAP_GIT_NAME=
STRAP_GIT_EMAIL=
STRAP_GITHUB_USER=
STRAP_GITHUB_TOKEN=
STRAP_ISSUES_URL="https://github.com/les-okta/mac/issues/new"

STRAP_FULL_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

abort() { STRAP_STEP="";   echo "!!! $*" >&2; exit 1; }
log()   { STRAP_STEP="$*"; echo "--> $*"; }
logn()  { STRAP_STEP="$*"; printf -- "--> $* "; }
logk()  { STRAP_STEP="";   echo "OK"; }

sw_vers -productVersion | grep $Q -E "^10.(9|10|11|12)" || {
  abort "Run Strap on Mac OS X 10.9/10/11/12."
}

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
if [ -f "$HOME/.bash_profile" ]; then
  logk
else
  echo
  log "Creating ~/.bash_profile..."
  touch ~/.bash_profile
  logk
fi

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

logn "Ensuring keyboard and finder settings:"
# speed up the keyboard.  Defaults are *slow* for developers:
defaults write -g KeyRepeat -int 2;
defaults write -g InitialKeyRepeat -int 14;
defaults write com.apple.finder AppleShowAllFiles YES; # show hidden files
defaults write NSGlobalDomain AppleShowAllExtensions -bool true; # show all file extensions
killall Finder 2>/dev/null;
logk

# Check and enable full-disk encryption.
logn "Checking full-disk encryption status:"
if fdesetup status | grep $Q -E "FileVault is (On|Off, but will be enabled after the next restart)."; then
  logk
elif [ -n "$STRAP_INTERACTIVE" ]; then
  echo
  log "Enabling full-disk encryption on next reboot:"
  sudo fdesetup enable -user "$USER" | tee ~/Desktop/"FileVault Recovery Key.txt"
  logk
else
  echo
  abort "Run 'sudo fdesetup enable -user \"$USER\"' to enable full-disk encryption."
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
  logk
else
  logk
fi

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
if softwareupdate -l 2>&1 | grep $Q "No new software available."; then
  logk
else
  echo
  log "Installing Apple software updates.  This could take a while..."
  sudo softwareupdate --install --all
  xcode_license
  logk
fi

# Homebrew
logn "Checking Homebrew:"
if command -v brew >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing Homebrew..."
  HOMEBREW_PREFIX="/usr/local"
  [ -d "$HOMEBREW_PREFIX" ] || sudo mkdir -p "$HOMEBREW_PREFIX"
  sudo chown -R "$(logname):admin" "$HOMEBREW_PREFIX"
  yes '' | /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)";

  if [[ "$PATH" != *"/usr/local/bin"* ]]; then
    echo '' >> ~/.bash_profile;
    echo '# homebrew' >> ~/.bash_profile;
    echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bash_profile;
    source "$HOME/.bash_profile"
  fi

  logk
fi

logn "Checking Homebrew Cask:"
if brew tap | grep caskroom/cask >/dev/null 2>&1; then
  logk
else
  echo
  log "Tapping caskroom/cask..."
  brew tap caskroom/cask
  logk
fi

logn "Checking Homebrew updates:"
brew update
brew upgrade

# bash completion:
logn "Checking bash completion:"
if brew list | grep bash-completion >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing bash completion..."
  brew install bash-completion
  if ! grep -q bash_completion "$HOME/.bash_profile"; then
    echo '' >> ~/.bash_profile;
    echo '# bash completion' >> ~/.bash_profile;
    echo 'if [ -f $(brew --prefix)/etc/bash_completion ]; then' >> ~/.bash_profile;
    echo '  . $(brew --prefix)/etc/bash_completion' >> ~/.bash_profile;
    echo 'fi' >> ~/.bash_profile;
  fi
  logk
fi

logn "Checking openssl:"
if brew list | grep openssl >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing openssl..."
  brew install openssl
  logk
fi

logn "Checking git:"
if brew list | grep git >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing git..."
  brew install git
  logk
fi

logn "Configuring Git:"
if [ -n "$STRAP_GIT_NAME" ] && ! git config user.name >/dev/null; then
  git config --global user.name "$STRAP_GIT_NAME"
fi

if [ -n "$STRAP_GIT_EMAIL" ] && ! git config user.email >/dev/null; then
  git config --global user.email "$STRAP_GIT_EMAIL"
fi

if [ -n "$STRAP_GITHUB_USER" ] && [ "$(git config --global github.user)" != "$STRAP_GITHUB_USER" ]; then
  git config --global github.user "$STRAP_GITHUB_USER"
fi

if ! git config push.default >/dev/null; then
  git config --global push.default simple
fi

if ! git config branch.autosetupmerge >/dev/null; then
  git config --global branch.autosetupmerge always
fi

if git credential-osxkeychain 2>&1 | grep $Q "git.credential-osxkeychain"; then

  if [ "$(git config --global credential.helper)" != "osxkeychain" ]; then
    git config --global credential.helper osxkeychain
  fi

  if [ -n "$STRAP_GITHUB_USER" ] && [ -n "$STRAP_GITHUB_TOKEN" ]; then
    printf "protocol=https\nhost=github.com\n" | git credential-osxkeychain erase
    printf "protocol=https\nhost=github.com\nusername=%s\npassword=%s\n" \
          "$STRAP_GITHUB_USER" "$STRAP_GITHUB_TOKEN" \
          | git credential-osxkeychain store
  fi
fi
logk

logn "Checking httpie:"
if brew list | grep httpie >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing httpie..."
  brew install httpie
  logk
fi

logn "Checking mysql:"
if brew list | grep mysql >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing mysql..."
  brew install mysql
  logk
fi

logn "Checking percona toolkit:"
if brew list | grep percona >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing percona toolkit..."
  brew install percona-toolkit
  logk
fi

logn "Checking liquidprompt:"
if brew list | grep liquidprompt >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing liquidprompt..."
  brew install liquidprompt
fi

#if grep -q liquidprompt "$HOME/.bash_profile"; then
#  logk
#else
#  echo
#  log "Installing liquidprompt..."
#  mkdir -p ~/projects
#  cd ~/projects
#  git clone https://github.com/nojhan/liquidprompt.git
#  cd ~
#  echo '' >> ~/.bash_profile
#  echo '# LiquidPrompt' >> ~/.bash_profile
# echo '# Only load LiquidPrompt in interactive shells, not from a script or from scp' >> ~/.bash_profile
#  echo '[[ $- = *i* ]] && source ~/projects/liquidprompt/liquidprompt' >> ~/.bash_profile
#  logk
#fi

logn "Checking iterm2:"
if [ -d "/Applications/iTerm.app" ] || brew cask list | grep iterm2 >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing iterm2..."
  brew cask install iterm2
  logk
fi

#logn "Checking google-chrome:"
#if [ -d "/Applications/Google Chrome.app" ] || brew cask list | grep google-chrome >/dev/null 2>&1; then
#  logk
#else
#  echo
#  log "Installing google-chrome..."
#  brew cask install google-chrome
#  logk
#fi

logn "Checking java:"
if brew cask list | grep java >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing java..."
  brew cask install java
  logk
fi

logn "Checking JAVA_HOME:"
if grep -q JAVA_HOME "$HOME/.bash_profile"; then
  logk
else
  echo
  log "Setting JAVA_HOME..."
  echo '' >> ~/.bash_profile
  echo '# JAVA_HOME' >> ~/.bash_profile
  echo 'export JAVA_HOME="$(/usr/libexec/java_home)"' >> ~/.bash_profile
  echo 'export PATH="$JAVA_HOME/bin:$PATH"' >> ~/.bash_profile
  logk
fi

[ -z "$JAVA_HOME" ] && JAVA_HOME="$(/usr/libexec/java_home)"
[ -z "$JAVA_HOME" ] && abort "JAVA_HOME cannot be determined."

logn "Checking java unlimited cryptography:"
JCE_DIR="$JAVA_HOME/jre/lib/security"
if [ -f "$JCE_DIR/local_policy.jar.orig" ]; then
  logk
else
  echo
  log "Installing java unlimited cryptography..."
  cd $JCE_DIR
  # backup existing JVM files that we will replace just in case:
  sudo mv local_policy.jar local_policy.jar.orig
  sudo mv US_export_policy.jar US_export_policy.jar.orig
  sudo curl -sLO 'http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip' -H 'Cookie: oraclelicense=accept-securebackup-cookie'
  sudo unzip jce_policy-8.zip
  sudo mv UnlimitedJCEPolicyJDK8/US_export_policy.jar .
  sudo mv UnlimitedJCEPolicyJDK8/local_policy.jar .
  sudo chown root:wheel US_export_policy.jar
  sudo chown root:wheel local_policy.jar
  # cleanup download file:
  sudo rm -rf jce_policy-8.zip
  sudo rm -rf UnlimitedJCEPolicyJDK8
  cd ~
  logk
fi

logn "Checking jenv:"
if brew list | grep jenv >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing jenv..."
  brew install jenv

  if ! grep -q jenv "$HOME/.bash_profile"; then
    echo '' >> ~/.bash_profile;
    echo '# jenv' >> ~/.bash_profile;
    echo 'export PATH="$HOME/.jenv/bin:$PATH"' >> ~/.bash_profile;
    echo 'if command -v jenv >/dev/null; then eval "$(jenv init -)"; fi;' >> ~/.bash_profile;
  fi

  export PATH="$HOME/.jenv/bin:$PATH"
  eval "$(jenv init -)"
  jenv add "$(/usr/libexec/java_home)"
  jenv global 1.8
  jenv enable-plugin export
  jenv enable-plugin maven
  jenv enable-plugin groovy
  jenv enable-plugin springboot
  logk
fi

logn "Checking maven:"
if brew list | grep maven >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing maven..."
  brew install maven
  logk
fi

logn "Checking groovy:"
if brew list | grep groovy >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing groovy..."
  brew install groovy
  logk
fi

#logn "Checking docker:"
#if [ -d "/Applications/Docker.app" ] || brew cask list | grep docker >/dev/null 2>&1; then
#  logk
#else
#  echo
#  log "Installing docker..."
#  brew cask install docker
#  logk
#fi

logn "Checking intellij-idea:"
if [ -d "/Applications/IntelliJ IDEA.app" ] || brew cask list | grep intellij-idea >/dev/null 2>&1; then
  logk
else
  echo
  log "Installing intellij-idea..."
  brew cask install intellij-idea
  logk
  #echo
  #log "Installing GMavenPlus plugin for intellij-idea..."
  #INTELLIJ_VERSION=`brew cask info intellij-idea | head -n1 | awk 'BEGIN { FS = "[:. ]" }; { print $3"."$4 }'`
  #curl -s \
  #   https://raw.githubusercontent.com/mycila/gmavenplus-intellij-plugin/master/gmavenplus-intellij-plugin.jar > \
  #   ~/Library/Application\ Support/IntelliJIdea$INTELLIJ_VERSION/gmavenplus-intellij-plugin.jar
  #logk
fi

STRAP_SUCCESS="1"
log "Your system is now Strap'd!"
