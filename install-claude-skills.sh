#!/bin/sh
#
# install-claude-skills.sh -- install this package's Claude Code skills.
#
# Usage: ./install-claude-skills.sh [options]
#   -t, --target DIR   Claude config dir to install into (repeatable);
#                      default ${CLAUDE_CONFIG_DIR:-~/.claude}
#   -a, --all          every Claude config dir found: ~/.claude, ~/.claude-*,
#                      and $CLAUDE_CONFIG_DIR
#   -l, --link         symlink the skills instead of copying them
#   -u, --uninstall    remove the skills instead of installing them
#   -f, --force        replace an existing skill dir that is not ours
#   -n, --dry-run      show what would be done, change nothing
#   -h, --help         this text
#
# Skills go to DIR/skills/<name>/. Safe to re-run; it updates in place.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
src="$here/claude-skills"
marker=".installed-from-requests-fermi-sso"

targets=""
all=no
mode=copy
action=install
force=no
dry=no

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--target) [ $# -ge 2 ] || { echo "$1 needs a directory" >&2; exit 2; }
                     targets="$targets
$2"; shift ;;
        -a|--all) all=yes ;;
        -l|--link) mode=link ;;
        -u|--uninstall) action=uninstall ;;
        -f|--force) force=yes ;;
        -n|--dry-run) dry=yes ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

[ -d "$src" ] || { echo "no skills directory at $src" >&2; exit 1; }

# A directory counts as a Claude Code config dir if it holds one of the files
# or directories Claude Code itself creates there.
is_claude_dir() {
    for f in settings.json projects skills CLAUDE.md sessions plugins; do
        [ -e "$1/$f" ] && return 0
    done
    return 1
}

if [ "$all" = yes ]; then
    for d in "$HOME/.claude" "$HOME"/.claude-* ${CLAUDE_CONFIG_DIR:+"$CLAUDE_CONFIG_DIR"}; do
        [ -d "$d" ] || continue
        if is_claude_dir "$d"; then
            targets="$targets
$d"
        else
            echo "skip  $d (not a Claude Code config dir; use -t to force it)"
        fi
    done
fi
[ -n "$targets" ] || targets="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

run() {
    if [ "$dry" = yes ]; then echo "  would: $*"; else "$@"; fi
}

# de-duplicate by resolved path so ~/.claude given twice installs once
seen=""
echo "$targets" | while IFS= read -r t; do
    [ -n "$t" ] || continue
    case "$t" in "~"|"~/"*) t="$HOME${t#\~}" ;; esac   # a quoted ~ from -t
    if [ -d "$t" ]; then
        real=$(cd "$t" && pwd -P)
    elif [ "$dry" = yes ]; then
        real=$t
    else
        mkdir -p "$t" || { echo "FAIL  cannot create $t" >&2; continue; }
        real=$(cd "$t" && pwd -P)
    fi
    case "$seen" in *"|$real|"*) continue ;; esac
    seen="$seen|$real|"
    echo "$action into $real/skills"
    for skill in "$src"/*/; do
        name=$(basename "$skill")
        [ -f "$skill/SKILL.md" ] || continue
        dest="$real/skills/$name"
        ours=no
        if [ -L "$dest" ] || [ -f "$dest/$marker" ]; then ours=yes; fi
        if [ "$action" = uninstall ]; then
            if [ -e "$dest" ] || [ -L "$dest" ]; then
                if [ "$ours" = yes ] || [ "$force" = yes ]; then
                    run rm -rf "$dest"; echo "  removed  $name"
                else
                    echo "  kept     $name (not installed by this script; -f removes it)"
                fi
            fi
            continue
        fi
        if [ -e "$dest" ] && [ "$ours" = no ] && [ "$force" = no ]; then
            echo "  kept     $name (exists and was not installed by this script; -f replaces it)"
            continue
        fi
        run mkdir -p "$real/skills"
        run rm -rf "$dest"
        if [ "$mode" = link ]; then
            run ln -s "${skill%/}" "$dest"
        else
            run cp -R "${skill%/}" "$dest"
            if [ "$dry" = no ]; then echo "$here" > "$dest/$marker"; fi
        fi
        echo "  $mode     $name"
    done
done
