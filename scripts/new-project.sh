#!/bin/sh
# Turns this template into a new project: renames it everywhere and,
# optionally, drops cargo features from the default build.
#
#   scripts/new-project.sh <name> [--title "Display Name"] [--without feature,...]
#
# <name> becomes the package name: lowercase letters, digits, and single
# hyphens, starting with a letter. The crate, binary, database, Docker, CI,
# and editor names follow from it (as my_app where an identifier cannot hold
# a hyphen). The display name, "Luxor" in the console and the README, becomes
# --title, by default <name> in title case.
#
# --without drops features from the default build: any of redis, kafka, otel,
# sentry, realtime, demo, embedded-postgres. Their code stays, compiled out;
# the README's "Removing the demo" section lists what to delete for good.
#
# Run it once, on a fresh copy of the template, before the new project's first
# commit. It edits files in place; review the result with `git diff`.

set -eu

TEMPLATE=luxor
TEMPLATE_TITLE=Luxor
TOGGLEABLE="redis kafka otel sentry realtime demo embedded-postgres"
# Rust keywords and the names of the built-in crates, which a package cannot
# take because its crate name would collide with them.
RESERVED="as async await break const continue crate dyn else enum extern false fn for
if impl in let loop match mod move mut pub ref return self static struct super trait
true type unsafe use where while abstract become box do final gen macro override priv
try typeof unsized virtual yield alloc core proc-macro std test"

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

name=
title=
without=
while [ $# -gt 0 ]; do
    case $1 in
        -h | --help) usage ;;
        --title)
            [ $# -ge 2 ] || fail "--title needs a value"
            title=$2
            shift 2
            ;;
        --title=*)
            title=${1#--title=}
            shift
            ;;
        --without)
            [ $# -ge 2 ] || fail "--without needs a value"
            without=$2
            shift 2
            ;;
        --without=*)
            without=${1#--without=}
            shift
            ;;
        -*) fail "unknown option $1 (see --help)" ;;
        *)
            [ -z "$name" ] || fail "unexpected argument $1 (see --help)"
            name=$1
            shift
            ;;
    esac
done
[ -n "$name" ] || usage 1

case $name in
    [a-z]*) ;;
    *) fail "the name must start with a lowercase letter" ;;
esac
case $name in
    *[!a-z0-9-]* | *- | *--*)
        fail "the name may contain only lowercase letters, digits, and single hyphens between them"
        ;;
esac
[ "${#name}" -le 64 ] || fail "the name must be at most 64 characters"
[ "$name" != "$TEMPLATE" ] || fail "the project is already called $TEMPLATE"
for reserved in $RESERVED; do
    [ "$name" != "$reserved" ] || fail "$name is reserved by Rust and cannot name a package"
done

snake=$(printf '%s' "$name" | tr - _)
if [ -z "$title" ]; then
    title=$(printf '%s\n' "$name" | awk -F- '{
        for (i = 1; i <= NF; i++) $i = toupper(substr($i, 1, 1)) substr($i, 2)
        print
    }' OFS=' ')
fi
case $title in
    '' | *[!A-Za-z0-9\ .-]*)
        fail "the title may contain only letters, digits, spaces, dots, and hyphens"
        ;;
esac

cd "$(dirname "$0")/.."
grep -q "^name = \"$TEMPLATE\"\$" Cargo.toml ||
    fail "Cargo.toml does not name the package $TEMPLATE; has this copy been renamed already?"

# --- features ---------------------------------------------------------------

listed() {
    case ",$without," in
        *",$1,"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Removes "$2" from the one-line feature list `$1 = [...]` in Cargo.toml.
drop_feature() {
    grep -q "^$1 = \\[.*\"$2\"" Cargo.toml ||
        fail "$2 is not in the $1 feature list of Cargo.toml"
    awk -v key="$1" -v feature="\"$2\"" '
        index($0, key " = [") == 1 {
            inner = substr($0, length(key) + 5)
            sub(/\][[:space:]]*$/, "", inner)
            count = split(inner, items, /,[[:space:]]*/)
            kept = ""
            for (i = 1; i <= count; i++) {
                if (items[i] != feature && items[i] != "") {
                    kept = kept (kept == "" ? "" : ", ") items[i]
                }
            }
            $0 = key " = [" kept "]"
        }
        { print }
    ' Cargo.toml >Cargo.toml.new
    mv Cargo.toml.new Cargo.toml
}

if [ -n "$without" ]; then
    without=$(printf '%s' "$without" | tr -d ' ')
    for feature in $(printf '%s' "$without" | tr ',' ' '); do
        case " $TOGGLEABLE " in
            *" $feature "*) ;;
            *) fail "unknown feature $feature; choose from: $TOGGLEABLE" ;;
        esac
    done
    # The demo enables otel and realtime itself, so dropping either while it
    # stays would change nothing.
    if ! listed demo && { listed otel || listed realtime; }; then
        fail "the demo needs otel and realtime; drop demo as well, or keep them"
    fi
    for feature in $(printf '%s' "$without" | tr ',' ' '); do
        if [ "$feature" = embedded-postgres ]; then
            drop_feature default "$feature"
        else
            drop_feature app "$feature"
        fi
        printf 'dropped the %s feature from the default build\n' "$feature"
    done
fi

# --- names ------------------------------------------------------------------

project_files() {
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git ls-files --cached --others --exclude-standard
    else
        find . -type f ! -path './.git/*' ! -path './target/*' ! -path './wasm/target/*' \
            ! -path "./.$TEMPLATE/*" | sed 's|^\./||'
    fi
}

project_files | sort -u | while IFS= read -r file; do
    # Skip paths deleted from the working tree, this script, binaries, and
    # files that do not mention the template.
    [ -f "$file" ] || continue
    [ "$file" != scripts/new-project.sh ] || continue
    grep -Iq . "$file" || continue
    grep -qi "$TEMPLATE" "$file" || continue
    case $file in
        # In Rust sources the name is only ever the crate path.
        *.rs)
            sed -i.rename-backup \
                -e "s/$TEMPLATE/$snake/g" \
                -e "s/$TEMPLATE_TITLE/$title/g" \
                "$file"
            ;;
        # Elsewhere, identifiers that cannot hold a hyphen (database names and
        # users, log targets, the library target) take the underscored form;
        # everything else takes the package name, and the display name the
        # title.
        *)
            sed -i.rename-backup \
                -e "s/${TEMPLATE}_wasm/${snake}_wasm/g" \
                -e "s/${TEMPLATE}-wasm/${name}-wasm/g" \
                -e "s|postgres://$TEMPLATE:$TEMPLATE@|postgres://$snake:$snake@|g" \
                -e "s|localhost:5432/$TEMPLATE|localhost:5432/$snake|g" \
                -e "s/$TEMPLATE=info/$snake=info/g" \
                -e "s/POSTGRES_DB: $TEMPLATE/POSTGRES_DB: $snake/g" \
                -e "s/POSTGRES_USER: $TEMPLATE/POSTGRES_USER: $snake/g" \
                -e "s/POSTGRES_PASSWORD: $TEMPLATE/POSTGRES_PASSWORD: $snake/g" \
                -e "s/-U $TEMPLATE -d $TEMPLATE/-U $snake -d $snake/g" \
                -e "s/$TEMPLATE::/$snake::/g" \
                -e "s/\"name\": \"$TEMPLATE\", \"kind\": \"lib\"/\"name\": \"$snake\", \"kind\": \"lib\"/g" \
                -e "s/$TEMPLATE/$name/g" \
                -e "s/$TEMPLATE_TITLE/$title/g" \
                "$file"
            ;;
    esac
    rm -f "$file.rename-backup"
    printf 'renamed in %s\n' "$file"
done

# A longer or shorter name moves line lengths, so the Rust sources are
# formatted again to keep `cargo fmt --check` passing.
if command -v cargo >/dev/null 2>&1; then
    cargo fmt --all
else
    printf 'cargo is not installed; run `cargo fmt --all` before committing\n'
fi

cat <<EOF

The project is now $name ("$title").

Next:
  cargo test          # builds and tests the renamed project
  git diff            # reviews every change this script made
  Rewrite README.md for the new project, and delete scripts/new-project.sh.
EOF
