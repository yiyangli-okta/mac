# Strap

Ensures that a new or existing Mac has necessary development software.

Run it, replacing quoted values with your own:

```bash
curl -sLO https://raw.githubusercontent.com/les-okta/mac/master/strap.sh
STRAP_GIT_NAME='Firstname Lastname'
STRAP_GIT_EMAIL='you@okta.com'
STRAP_GITHUB_USER='you-okta'
STRAP_GITHUB_TOKEN='your-github-api-token'
bash strap.sh
```

This ensures the following are installed:

* XCode Command Line Tools
* Apple operating system and security updates
* Homebrew
* Homebrew Cask
* bash completion
* openssl
* git
* httpie
* jenv
* liquidprompt
* iTerm2
* Oracle JDK 8 with unlimited strength cryptography
* maven
* groovy
* Docker
* IntelliJ IDEA
* GMavenPlus Plugin for IntelliJ IDEA
