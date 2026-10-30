#!/bin/sh
#
# bootstrap.sh -- create the venv, install/update dependencies, run the tests.
#
# Usage: ./bootstrap.sh [--no-test]
#
# Safe to re-run; it updates an existing venv in place.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
venv="$here/venv"
run_tests=yes

for arg in "$@"; do
    case "$arg" in
        --no-test) run_tests=no ;;
        -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

python=${PYTHON:-python3}

if [ ! -d "$venv" ]; then
    echo "creating venv in $venv"
    "$python" -m venv "$venv"
fi

# Windows layout puts the interpreter in Scripts/ rather than bin/
if [ -x "$venv/bin/python" ]; then
    vpy="$venv/bin/python"
else
    vpy="$venv/Scripts/python.exe"
fi

echo "updating pip"
"$vpy" -m pip install --quiet --upgrade pip

echo "installing package and test dependencies"
"$vpy" -m pip install --quiet --upgrade -e "$here[test]"

if [ "$run_tests" = yes ]; then
    echo "running tests"
    "$vpy" -m pytest "$here/tests"
fi

echo
echo "done. activate with:  . $venv/bin/activate"
echo "then try:             fermi-sso-probe -u \$USER"
echo "inspect a jar with:   fermi-sso-cookies ~/.fermi_sso.cookies"
echo "prime every site:     fermi-sso-jar setup && fermi-sso-jar prime --all"
echo "watch the jar:        fermi-sso-jar-tui   (or fermi-sso-jar-gui with PySide6)"
