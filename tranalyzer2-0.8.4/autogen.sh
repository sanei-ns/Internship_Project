#!/usr/bin/env bash
#
# This script builds Tranalyzer2 and the plugins. If it is executed with the
# option '-i', then the Tranalyzer binary is copied to '/usr/local/bin'.
#
# If no options are provided, builds a default set of plugins.
# If the '-a' option is used, builds all the plugins
# If the '-b' option is used, build the plugins listed in 'plugins.build'
# If the '-b file' option is used, build the plugins listed in 'file'
# Alternatively, a list of plugin names can be passed to the script

source "$(dirname "$0")/scripts/t2utils.sh"

usage() {
    echo
    echo "Usage:"
    echo "    $SNAME [OPTION...] [plugin...]"
    echo
    echo "Optional arguments:"
    echo "    -a            build all plugins"
    echo "    -b file       build plugins listed in 'file'"
    echo "    -I file       ignore plugins listed in 'file' (requires -a option)"
    echo "    -R            rebuild Tranalyzer and all the plugins in the plugin folder"
    echo
    echo "    plugin        a list of valid plugin names"
    echo
    echo "    -c            execute make clean and remove automatically generated files"
    echo "    -d            compile in debug mode"
    echo "    -P            compile in profile mode"
    echo "    -o level      gcc optimization level"
    echo "    -L            lazy mode (run make all instead of make clean all)"
    echo "    -r            force rebuild of makefiles"
    echo
    echo "    -u            unload/remove the plugin from the plugin folder"
    echo "    -e            empty the plugin folder and exit"
    echo "    -l            list all plugins in the plugin folder and exit"
    echo
    echo "    -k[Jjtz]      create one compressed archive per plugin"
    echo "    -K[Jjtz]      create one compressed archive with the requested plugins"
    echo "                  (J: tar.xz, j: tar.bz2, t: tar, z: tar.gz [default])"
    echo
    echo "    -f            force the copy of extra files"
    echo "    -1            do not parallelize the build process"
    echo
    echo "    -D            build the documentation for the plugin"
    echo "    -i            install Tranalyzer binary in /usr/local/bin"
    echo "    -p dir        plugin install directory [$PLUGIN_DIR]"
    echo
    echo "    -y            do not ask for confirmation before executing an action"
    echo
    echo "    -h, --help    Show help options and exit"
    echo
}

build_tranalyzer() {
    printinf "\n'Tranalyzer2'\n"
    cd "$T2HOME/tranalyzer2"
    ./autogen.sh $INSTALL $OPTS
}

build_plugin() {
    local plugin="$1"
    printinf "\nPlugin '$plugin'\n"
    cd "$T2PLHOME/$plugin"
    if [ $NCPUS -gt 1 ] && [ $POLLINT -gt 0 ] && [ ${#PLUGINS[@]} -gt 1 ]; then
        ./autogen.sh $OPTS &> /dev/null
    else
        ./autogen.sh $OPTS
    fi
    if [ $? -ne 0 ]; then
        echo "$plugin" >> "$FAILED_FILE"
    fi
}

list_plugins() {
    local plugins=$(ls "$PLUGIN_DIR/"[0-9][0-9][0-9]_*\.so 2> /dev/null | perl -lpe 's!^.*/\d{3}_(.*)\.so$!\1!' | sort)
    if [ -z "$plugins" ]; then
        printf "No plugins in '$PLUGIN_DIR'\n"
    else
        printf "$plugins\n"
    fi
}

package_setup() {
    # Force a clean before packaging
    OPTS="$OPTS -c"
    POLLINT=0
    # Options for packaging
    PKGVERSION="$($AWK -F, '/^AC_INIT\(\[/ { print $2 }' $T2HOME/tranalyzer2/configure.ac | tr -d '[][:blank:]')"
    PKGNAME="$(basename "$T2HOME")-${PKGVERSION}"
    PKG="${PKGNAME}${PKGEXT}"
    # Extra files to include in the package
    PKGEXTRA=(
        autogen.sh
        plugins/autogen.sh
        ChangeLog
        doc
        plugins/t2PSkel
        README.md
        scripts
        setup.sh
        tests
        tranalyzer2
        utils
    )
    TMPDIR="/tmp"
    PKGTMP="${TMPDIR}/${PKGNAME}"
}

new_package() {
    if [ -f "$PKG" ]; then
        rm -f "$PKG"
    fi
    if [ -d "$PKGTMP" ]; then
        rm -rf "$PKGTMP"
    fi
    mkdir -p "$PKGTMP/plugins"
    for extra in ${PKGEXTRA[@]}; do
        add_to_package "$extra"
    done
}

add_to_package() {
    local file="$1"
    # NOTE: this technique using symbolic links can be problematic if plugins contain
    # symbolic links which should NOT be dereferenced when creating the archive.
    # If this is the case in the future, a "cp -r" could replace the next line.
    ln -s "$T2HOME/$file" "$PKGTMP/$file"
    if [ $? -ne 0 ]; then
        printerr "\nFailed to add '$file' to '$PKG'\n"
        exit 1
    else
        printok "\nSuccessfully added '$file' to '$PKG'\n"
    fi
}

empty_plugin_folder() {
    if [ ! -d "$PLUGIN_DIR" ]; then
        printf "Plugin folder does not exist\n"
        exit 0
    fi

    printf "Are you sure you want to empty the plugin folder '$PLUGIN_DIR' (y/N)? "
    if [ -z "$YES" ]; then
        read ans
    else
        ans="yes"
        echo "$ans"
    fi
    case "$ans" in
        [yY]|[yY][eE][sS])
            rm -rf "$PLUGIN_DIR"
            printok "Plugin folder emptied"
            exit 0
            ;;
        *)
            printwrn "Plugin folder not emptied"
            exit 1
            ;;
    esac
}

_cleanup() {
    local ret=$1

    #echo "Cleaning temporary files"
    rm -f "$FAILED_FILE"

    if [ "$(pgrep -P $$ | wc -l)" -gt 1 ]; then
        printf "Killing all subprocesses...\n"
        kill -- -$$
    fi

    exit $ret
}

# Default values
POLLINT=1 # Poll interval

PLUGIN_DIR="$HOME/.tranalyzer/plugins"

# Plugins to build:
#   - d: default
#   - b: file [plugins.build] (-b [file])
#   - a: all (recursive) (-a)
#   - r: rebuild (-R)
BUILD="d"
PLUGINS_BUILD="$T2HOME/plugins.build"
PLUGINS_IGNORE="$T2HOME/plugins.ignore"
PLUGINS_DEFAULT=(
    basicFlow
    basicStats
    connStat
    icmpDecode
    macRecorder
    portClassifier
    protoStats
    tcpFlags
    tcpStates
    txtSink
)
PLUGINS_BLACKLIST=(
    t2PSkel
)

# Process args
while [ $# -gt 0 ]; do
    case "$1" in
        -i|--install) INSTALL="$1";;
        # what to build: default(d), all(a), or file(b)
        -a|--all) BUILD="a";;
        -R|--rebuild) BUILD="r";;
        -b|--build) BUILD="b"
            validate_next_file "$1" "$2"
            PLUGINS_BUILD="$2"
            #printf "\nBuilding plugins listed in '%s'\n" "$PLUGINS_BUILD"
            #$AWK '! /^#/ { i++; printf("\t%3d) %s\n", i, $0) }' "$PLUGINS_BUILD"
            shift
            ;;
        -I|--ignore)
            validate_next_file "$1" "$2"
            PLUGINS_IGNORE="$2"
            #printf "\nIgnoring plugins listed in '%s'\n" "$PLUGINS_IGNORE"
            #$AWK '! /^#/ { i++; printf("\t%3d) %s\n", i, $0) }' "$PLUGINS_IGNORE"
            shift
            ;;
        -r|--configure|-d|--debug|-P|--profile)
            POLLINT=1
            # pass those options as-is to autogen
            OPTS="$OPTS $1"
            ;;
        -f|--force|-D|--doc)
            # pass those options as-is to autogen
            OPTS="$OPTS $1"
            ;;
        -u|--unload|-L|--lazy)
            CHECK_T2=1
            POLLINT=0
            # pass those options as-is to autogen
            OPTS="$OPTS $1"
            ;;
        -k|-k[Jjtz]|--package|--package-*|-c|--clean)
            POLLINT=0
            # pass those options as-is to autogen
            OPTS="$OPTS $1"
            ;;
        -o)
            validate_next_num "$1" "$2"
            OPTS="$OPTS $1 $2"
            shift
            ;;
        -p|--plugin-dir)
            validate_next_arg "$1" "$2"
            OPTS="$OPTS $1 $2"
            PLUGIN_DIR="$2"
            shift
            ;;
        -KJ|--package-all-xz)
            PKGEXT=".tar.xz"
            PACKAGE=1
            ;;
        -Kj|--package-all-bz2)
            PKGEXT=".tar.bz2"
            PACKAGE=1
            ;;
        -Kt|--package-all-tar)
            PKGEXT=".tar"
            PACKAGE=1
            ;;
        -K|--package-all|-Kz|--package-all-gz)
            PKGEXT=".tar.gz"
            PACKAGE=1
            ;;
        -1)
            NCPUS=1
            OPTS="$OPTS $1"
            ;;
        -y|--yes) YES=1;;
        -e|--empty) EMPTY=1;;
        -l|--list) list_plugins; exit 0;;
        -\?|-h|--help) usage; exit 0;;
        -*) abort_option_unknown "$1";;
        *) PLUGINS+=("$($SED 's/\/$//' <<< "$1")");;
    esac
    shift
done

if [ $PACKAGE ]; then
    package_setup
fi

if [ $POLLINT -gt 0 -o -n "$CHECK_T2" ] && [ -n "$(pgrep tranalyzer)" ]; then
    printf "\n${ORANGE}Tranalyzer is currently running...${NOCOLOR}\n"
    printf "Proceed anyway (y/N)? "
    if [ -z "$YES" ]; then
        read ans
    else
        ans="yes"
        echo "$ans"
    fi
    case $ans in
        [yY]|[yY][eE][sS]);;
        *) printf "\n"; exit 1
    esac
fi

if [ $EMPTY ]; then
    empty_plugin_folder
fi

if [[ $EUID -eq 0 ]] && [[ -z $DOCKER_BUILD ]]; then
    printwrn "\nRunning autogen.sh as root is not recommended..."
    printf "Proceed anyway (y/N)? "
    if [ -z "$YES" ]; then
        read ans
    else
        ans="yes"
        echo "$ans"
    fi
    case $ans in
        [yY]|[yY][eE][sS]);;
        *) echo; exit 1;;
    esac
fi

if [ -z "$PLUGINS" ]; then
    PLUGINS=(tranalyzer2)
    case "$BUILD" in
        d) # default
            PLUGINS+=(${PLUGINS_DEFAULT[@]})
            ;;
        b) # plugins.build
            PLUGINS+=($($AWK '!/^#/' "$PLUGINS_BUILD" | perl -lpe 's!^\d{3}_(.*)\.so$!\1!'))
            ;;
        r) # rebuild
            if [ ! -d "$PLUGIN_DIR" ]; then
                printerr "\nPlugin directory '$PLUGIN_DIR' does not exist\n"
                exit 1
            fi
            PLUGINS+=($(ls "$PLUGIN_DIR/"[0-9][0-9][0-9]_*.so | perl -lpe 's!^.*/\d{3}_(.*)\.so$!\1!'))
            ;;
        a)
            [ -f "$PLUGINS_IGNORE" ] && PLUGINS_BLACKLIST+=($($AWK '!/^#/' "$PLUGINS_IGNORE" | perl -lpe 's!^\d{3}_(.*)\.so$!\1!'))
            for plugin in "$T2PLHOME/"*; do
                plugin_name="$(basename "$plugin")"
                BLACKLISTED=$(grep -w "$plugin_name" <<< "${PLUGINS_BLACKLIST[*]}")
                if [ -d "$plugin" ] && [ -f "$plugin/autogen.sh" ] && [ ! "$BLACKLISTED" ]; then
                    PLUGINS+=("$plugin_name")
                fi
            done
            ;;
        *)
            printerr "\nInvalid build target '$BUILD'\n"
            exit 1
            ;;
    esac
fi

if [ -z "$PLUGINS" ] || [ -n "$(grep -w "tranalyzer2" <<< "${PLUGINS[*]}")" ]; then
    build_tranalyzer
    if [ $? -ne 0 ]; then
        # if Tranalyzer could not be built, no point in trying to build the plugins
        exit 1
    fi
    # Remove tranalyzer2 from the list of plugins to build
    for i in ${!PLUGINS[@]}; do
        if [ ${PLUGINS[$i]} = 'tranalyzer2' ] ; then
            unset PLUGINS[$i]
            break
        fi
    done
fi

if [ $PACKAGE ]; then
    new_package
fi

FAILED_FILE="$(mktemp)"

trap "trap - SIGTERM && _cleanup 1" HUP INT QUIT TERM
trap "_cleanup \$?" EXIT

if [ -z "$NCPUS" ]; then
    NCPUS=$(get_nproc)
fi

for plugin in ${PLUGINS[@]}; do
    if [ ! -d "$T2PLHOME/$plugin" ]; then
        printerr "\nPlugin '$plugin' could not be found\n"
        echo "$plugin" >> "$FAILED_FILE"
    elif [ ! -f "$T2PLHOME/$plugin/autogen.sh" ]; then
        printerr "$plugin is not a valid Tranalyzer plugin: could not find autogen.sh"
        echo "$plugin" >> "$FAILED_FILE"
    else
        build_plugin "$plugin" &
        if [ $NCPUS -eq 1 ]; then
            wait
        elif [ $POLLINT -gt 0 ]; then
            # Wait for one CPU to be free
            NPROC=$(jobs -p | wc -l)
            while [ $NPROC -eq $NCPUS ]; do
                sleep $POLLINT
                NPROC=$(jobs -p | wc -l)
            done
        fi
        if [ $PACKAGE ]; then
            add_to_package "plugins/$plugin"
        fi
    fi
done

# Wait for all processes to finish
wait < <(jobs -p)

if [ $PACKAGE ] && [ -d "$PKGTMP" ]; then
    PKGFORMAT="a"
    if [ "$(uname)" = "Darwin" ]; then
        case "$PKGEXT" in
            *.tar.bz2) PKGFORMAT="j";;
            *.tar.gz) PKGFORMAT="z";;
            *.tar.xz) PKGFORMAT="J";;
            *.tar) PKGFORMAT="";;
            *)
                printerr "Unhandled archive format '$PKGEXT'"
                exit 1
                ;;
        esac
    fi
    if [ "$(uname)" != "Darwin" ]; then
        TAR_OPTS=(--exclude-vcs --exclude-vcs-ignore --exclude-backups --exclude-caches-under)
    fi
    TAR_CMD=(
        tar ${TAR_OPTS[@]} -C "$TMPDIR" -c${PKGFORMAT}f "$T2HOME/$PKG" -h "$PKGNAME"
    )
    "${TAR_CMD[@]}"
    rm -r "$PKGTMP"
fi

if [ -s "$FAILED_FILE" ]; then
    printerr "\nThe following plugins could not be built:"
    sort -o "$FAILED_FILE" "$FAILED_FILE"
    while read plugin; do
        printerr "    $plugin"
    done < "$FAILED_FILE"
    exit 1
fi

printok "\nBUILD SUCCESSFUL\n"
