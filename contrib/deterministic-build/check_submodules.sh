#!/usr/bin/env bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../.."
LOCALE="$PROJECT_ROOT/electrum/locale/"

cd "$PROJECT_ROOT"

git submodule init
git submodule update

function get_git_mtime {
    if [ $# -eq 1 ]; then
        git log --pretty=%at -n1 -- $1
    else
        git log --pretty=%ar -n1 -- $2
    fi
}

fail=0


# note: warning only. Upstream electrum gates releases on fresh crowdin
# translations, but this fork tracks spesmilo/electrum-locale as-is and
# upstream regularly goes more than 2 weeks between translation merges,
# which would fail our releases through no fault of ours.
if [ $(date +%s -d "2 weeks ago") -gt $(get_git_mtime "$LOCALE") ]; then
    echo "Warning: last update from electrum-locale is older than 2 weeks."
fi

exit ${fail}
