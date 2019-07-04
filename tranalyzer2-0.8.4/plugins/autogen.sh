#!/usr/bin/env bash
#
# Master autogen.sh file for plugins.
#
# Look into t2PSkel/autogen.sh for detailed usage instructions.
#
# Default values for PLUGIN_DIR and GCCOPT are defined in this file,
# but can be overwritten if a plugin chooses to define them. If the '-p' or
# '-o' options are used, their value take precedence.
#
# Every plugin MUST define PLUGINNAME and PLUGINORDER.
# EXTRAFILES, CFLAGS and DEPS are optional.
#
# The following functions (documented in t2PSkel/autogen.sh) can be used:
#   - t2_clean
#   - t2_prebuild
#   - t2_preinst
#   - t2_inst
#   - t2_postinst
#
# Source this file from the plugins autogen.sh file.

if [ -z "$PLUGINNAME" ] || [ "$PLUGINNAME" != "tranalyzer2" -a -z "$PLUGINORDER" ]; then
    printf "\e[0;31mPLUGINNAME and PLUGINORDER MUST be defined\e[0m\n" >&2
    exit 1
fi

if [ "$PLUGINNAME" = "tranalyzer2" ]; then
    source "$(dirname "$0")/../scripts/t2utils.sh"
else
    source "$(dirname "$0")/../../scripts/t2utils.sh"
fi

# ----------------------------------------------------- #
# ----------------- DEFAULT OPTIONS ------------------- #
# ----------------------------------------------------- #

# Plugin installation directory (-p option)
[ -n "$PLUGIN_DIR" ] || PLUGIN_DIR="$HOME/.tranalyzer/plugins"

# GCC optimization level (-o option)
[ -n "$GCCOPT" ] || GCCOPT="2"

# format of the compressed archive (-k option)
[ -n "$PKGEXT" ] || PKGEXT=".tar.gz"

# ----------------------------------------------------- #
# -------------------- SCRIPT PART -------------------- #
# ----------------------------------------------------- #

# Folders where to look for header files
INCLUDE_DEFAULT="-I\"$T2HOME/utils/\" -I\"$T2HOME/tranalyzer2/src/\""

CFLAGS_DEFAULT="$CFLAGS -std=gnu99 -Wall -Wextra $INCLUDE_DEFAULT" # -Wconversion
if [ "$(uname)" = "Darwin" ]; then
    CFLAGS_DEFAULT="$CFLAGS_DEFAULT -D_DARWIN_C_SOURCE"
else
    CFLAGS_DEFAULT="$CFLAGS_DEFAULT -D_GNU_SOURCE"
fi

if [ -n "$PLUGINORDER" ]; then
    PLUGIN="plugin "  # better error report for Tranalyzer2 plugins
    CFLAGS_DEFAULT="$CFLAGS_DEFAULT -DPLUGIN_NUMBER=$PLUGINORDER"
fi

if [ "$CC" = "clang" ] || [ "$(uname)" = "Darwin" ]; then
    CFLAGS_DEBUG="$CFLAGS_DEFAULT -O0 -g"
    CFLAGS_PROFILE="$CFLAGS_DEBUG -p"
else
#elif [[ $(gcc -v 2>&1 | grep '^gcc version ' | $AWK '{ print $3 }') < 4.8 ]]; then
    CFLAGS_DEBUG="$CFLAGS_DEFAULT -O0 -g3 -ggdb3"
    CFLAGS_PROFILE="$CFLAGS_DEBUG -p -pg"
#else
#   CFLAGS_DEBUG="$CFLAGS_DEFAULT -Og -p -pg -g3 -ggdb3"
fi

usage() {
    echo "Usage:"
    echo "    $SNAME [OPTION...]"
    echo
    echo "Optional arguments:"
    echo "    -c        execute make clean and remove automatically generated files"
    echo "    -d        compile in debug mode"
    echo "    -P        compile in profile mode"
    echo "    -o level  gcc optimization level"
    echo "    -L        lazy mode (run make all instead of make clean all)"
    echo "    -r        force rebuild of makefiles"
    echo "    -f        force the copy of extra files"
    echo "    -1        do not parallelize the build process"
    echo
    if [ -n "$PLUGIN" ]; then
        echo "    -u        unload/remove the plugin from the plugin folder"
        echo
    fi
    echo "    -k[Jjtz]  create a compressed archive"
    echo "              (J: tar.xz, j: tar.bz2, t: tar, z: tar.gz [default])"
    echo
    if [ -z "$PLUGIN" ]; then
        echo "    -i        install Tranalyzer binary in /usr/local/bin"
    else
        echo "    -p dir    plugin installation directory"
    fi
    echo
    echo "    -D        build the documentation for the plugin"
    echo
    echo "    -y        do not ask for confirmation before executing an action"
    echo
    echo "    -h        Show help options and exit"
    echo
}

clean() {
    cd "$SHOME"

    if [ -f "doc/Makefile" ]; then
        make -C doc clean
    fi

    if [ -f "Makefile" ]; then
        make distclean
    fi

    rm -rf aclocal.m4 autom4te.cache/ build-aux/ compile config.* configure \
           depcomp INSTALL install-sh libtool m4/ Makefile Makefile.in \
           man/Makefile man/Makefile.in missing src/Makefile src/Makefile.in \
           src/deps/ src/.deps/ src/.libs stamp-h1

    rm -f "${PLUGINNAME}${PKGEXT}"

    type t2_clean &> /dev/null && t2_clean

    return 0
}

configure() {
    cd "$SHOME"

    if [ ! -d "m4" ]; then
        mkdir m4
    fi

    autoreconf --install --force

    CFLAGS="$CFLAGS" LIBS="$LIBS" ./configure --disable-dependency-tracking

    if [ $? -ne 0 ]; then
        printerr "\nFailed to configure $PLUGIN$PLUGINNAME"
        if [ -z "$DEPS" ]; then
            echo
        elif [ -z "$(grep ' ' <<< "$DEPS")" ]; then
            printinf "Missing dependency $DEPS?\n"
        else
            printinf "Missing dependencies $DEPS?\n"
        fi
        exit 1
    fi
}

build() {
    cd "$SHOME"

    if type t2_prebuild &> /dev/null; then
        t2_prebuild
        if [ $? -ne 0 ]; then
            printerr "\nt2_prebuild failed for $PLUGIN$PLUGINNAME\n"
            exit 1
        fi
    fi

    $MAKE_CLEAN  # XXX this should NOT be necessary
    make -j $NCPUS all

    if [ $? -ne 0 ]; then
        printerr "\nFailed to build $PLUGIN$PLUGINNAME\n"
        exit 1
    elif [ -z "$PLUGIN" ]; then
        local pname="$($SED 's/^./\U&/' <<< "$PLUGINNAME")"
        printok "\n$pname successfully built\n"
    fi
}

build_doc() {
    make -j $NCPUS -C "$SHOME/doc"

    if [ $? -ne 0 ]; then
        printerr "\nFailed to build $PLUGIN$PLUGINNAME documentation\n"
        exit 1
    elif [ -z "$PLUGIN" ]; then
        local pname="$($SED 's/^./\U&/' <<< "$PLUGINNAME")"
        printok "\n$pname documentation successfully built\n"
    fi
}

clean_doc() {
    make -j $NCPUS -C "$SHOME/doc" clean
}

install() {
    cd "$SHOME"

    if [ ! -d "$PLUGIN_DIR" ]; then
        mkdir -p "$PLUGIN_DIR"
    fi

    if [ -n "$PLUGIN" ]; then
        local parent="$(ps -ocommand= -p $PPID | awk -F/ '{print $NF}' | awk '{print $1}')"
        if [ "$parent" != "autogen.sh" ] && [ -f "$PLUGIN_DIR/${PLUGINORDER}_${PLUGINNAME}.so" ] && [ -n "$(pgrep tranalyzer)" ]; then
            printf "\n${ORANGE}Tranalyzer is currently running... Overwrite the $PLUGINNAME plugin anyway (y/N)? $NOCOLOR"
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

        case "$OSTYPE" in
            darwin*)
                cp "$T2PLHOME/$PLUGINNAME/src/.libs/lib${PLUGINNAME}.0.dylib" "$PLUGIN_DIR/${PLUGINORDER}_${PLUGINNAME}.so"
                ;;
            linux*)
                cp "$T2PLHOME/$PLUGINNAME/src/.libs/lib${PLUGINNAME}.so.0.0.0" "$PLUGIN_DIR/${PLUGINORDER}_${PLUGINNAME}.so"
                ;;
            *)
                false # OS is unknown, copy failed
                ;;
        esac

        if [ $? -ne 0 ]; then
            printerr "\nFailed to copy plugin $PLUGINNAME into $PLUGIN_DIR\n"
            exit 1
        fi

        printok "\nPlugin $PLUGINNAME copied into $PLUGIN_DIR\n"
    fi

    if type t2_preinst &> /dev/null; then
        t2_preinst
        if [ $? -ne 0 ]; then
            printerr "\nt2_preinst failed for plugin $PLUGINNAME\n"
            exit 1
        fi
    fi

    if [ ${#EXTRAFILES[@]} -ne 0 ]; then
        for i in ${EXTRAFILES[@]}; do
            if type t2_inst &> /dev/null; then
                t2_inst "$i"
                ret=$?
                if [ $ret -eq 0 ]; then
                    echo
                    continue
                elif [ $ret -ne 2 ]; then
                    printerr "\nt2_inst failed for file $i\n"
                    exit 1
                fi
            fi
            if [[ "$i" =~ \.gz$ ]]; then
                DEST="${i%.gz}"
            elif [[ "$i" =~ \.bz2$ ]]; then
                DEST="${i%.bz2}"
            else
                DEST="$i"
            fi
            if [ -e "$PLUGIN_DIR/$DEST" ] && [ "$FORCE" != 1 ]; then
                cmp -s "$PLUGIN_DIR/$DEST" "$DEST" &> /dev/null
                if  [ $? -eq 0 ]; then
                    printok "$DEST already exists in $PLUGIN_DIR"
                else
                    printwrn "A different version of $DEST already exists in $PLUGIN_DIR"
                    printinf "Run './autogen.sh -f' to overwrite it"
                fi
            else
                if [[ "$i" =~ \.gz$ ]]; then
                    gunzip -c "$i" > "$PLUGIN_DIR/$DEST"
                elif [[ "$i" =~ \.bz2$ ]]; then
                    bzcat "$i" > "$PLUGIN_DIR/$DEST"
                else
                    cp -r "$i" "$PLUGIN_DIR"
                fi
                if [ $? -ne 0 ]; then
                    printerr "\nFailed to copy $DEST into $PLUGIN_DIR\n"
                    exit 1
                else
                    printok "$DEST copied into $PLUGIN_DIR"
                fi
            fi
        done
        echo
    fi

    if type t2_postinst &> /dev/null; then
        t2_postinst
        if [ $? -ne 0 ]; then
            printerr "\nt2_postinst failed for $PLUGIN$PLUGINNAME\n"
            exit 1
        fi
    fi
}

unload() {
    if [ ! -d "$PLUGIN_DIR" ]; then
        # Nothing to do
        printwrn "Plugin folder '$PLUGIN_DIR' does no exist"
        return
    fi
    local suffix="_${PLUGINNAME}.so"
    if [ $(ls "$PLUGIN_DIR" | grep -E "^[0-9]{3}$suffix$" | wc -l) -ge 1 ]; then
        rm -f "$PLUGIN_DIR/"[0-9][0-9][0-9]"$suffix"
    fi
}

package() {
    cd "$SHOME"
    local destf="${PLUGINNAME}${PKGEXT}"
    local format="a"
    if [ "$(uname)" = "Darwin" ]; then
        case "$PKGEXT" in
            *.tar.bz2) format="j";;
            *.tar.gz) format="z";;
            *.tar.xz) format="J";;
            *.tar) format="";;
            *)
                printerr "Unhandled archive format '$PKGEXT'"
                exit 1
                ;;
        esac
    fi
    if [ "$(uname)" != "Darwin" ]; then
        local tar_opts=(--exclude-vcs --exclude-vcs-ignore --exclude-backups --exclude-caches-under)
    fi
    local tar_cmd=(
       tar --exclude=".*.swp" -C .. -c${format}f "../$destf" "$PLUGINNAME"
    )
    "${tar_cmd[@]}"
    # TODO Move the archive to the directory from which the command was run?
    #[ $? -eq 0 ] && mv "$destf" .
    if [ $? -ne 0 ]; then
        printerr "\nFailed to package $PLUGIN$PLUGINNAME\n"
        exit 1
    else
        printok "\nPackage '$destf' successfully created\n"
    fi
}

MAKE_CLEAN="make clean"

# Process args
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--clean) CLEAN=1;;
        -d|--debug) DEBUG=1;;
        -P|--profile) PROFILE=1;;
        -f|--force) FORCE=1;;
        -L|--lazy) unset MAKE_CLEAN;;
        -r|--configure) REBUILD=1;;
        -u|--unload) UNLOAD=1;;
        -D|--doc) DOC=1;;
        -y|--yes) YES=1;;
        -1) NCPUS=1;;
        -i|--install)
            if [ -z "$PLUGIN" ]; then
                INSTALL=1
            #else
            #   abort_option_unknown "$1"
            fi
            ;;
        -p|--plugin-dir)
            validate_next_arg "$1" "$2"
            PLUGIN_DIR="$2"
            shift
            ;;
        -o)
            validate_next_num "$1" "$2"
            GCCOPT=$2
            shift
            ;;
        -kJ|--package-xz)
            PKGEXT=".tar.xz"
            PACKAGE=1
            ;;
        -kj|--package-bz2)
            PKGEXT=".tar.bz2"
            PACKAGE=1
            ;;
        -kt|--package-tar)
            PKGEXT=".tar"
            PACKAGE=1
            ;;
        -kz|--package-gz)
            PKGEXT=".tar.gz"
            PACKAGE=1
            ;;
        -k|--package)
            PACKAGE=1
            ;;
        -\?|-h|--help)
            usage
            exit 0
            ;;
        *)
            abort_option_unknown "$1"
            ;;
    esac
    shift
done

# Make sure the script was run from the plugin root folder
cd "$SHOME"

if [ $DOC ]; then
    if [ $CLEAN ]; then
        clean_doc
    else
        build_doc
    fi
    exit 0
fi

if [ $CLEAN ]; then
    clean
    exit 0
fi

if [ $UNLOAD ]; then
    unload
    exit 0
fi

if [ $PACKAGE ]; then
    clean
    package
    exit 0
fi

# Set the CFLAGS
if [ $PROFILE ]; then
    printinf "\nCompiling in profile mode...\n"
    CFLAGS="$CFLAGS_PROFILE"
elif [ $DEBUG ]; then
    printinf "\nCompiling in debug mode...\n"
    CFLAGS="$CFLAGS_DEBUG"
else
    CFLAGS="$CFLAGS_DEFAULT -O$GCCOPT"
fi

# Make sure the makefiles are up to date
if [ "$REBUILD" != 1 ]; then
    if [ ! -f "Makefile" ]; then
        REBUILD=1
    elif [ -z "$(grep "^CFLAGS\s\+=\s\+$CFLAGS$" Makefile)" ] ||
         [ -z "$(grep "^LIBS\s\+=\s\+.*$LIBS.*$" Makefile)" ]
    then
        REBUILD=1
    elif [ "$(uname)" != "Darwin" ]; then
        make -q &> /dev/null
        if [ $? -eq 2 ]; then
            REBUILD=1
        fi
    fi
fi

if [ -z "$NCPUS" ]; then
    NCPUS=$(get_nproc)
fi

if [ $REBUILD ]; then
    clean
    configure
fi

build
install
