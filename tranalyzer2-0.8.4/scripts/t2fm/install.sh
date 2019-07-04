#!/usr/bin/env bash

source "$(dirname "$0")/../t2utils.sh"

T2FMDIR="$(dirname "$($READLINK -f "$0")")"
PKG_NAME="$(basename "$T2FMDIR")"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...] <target>\n\n"
    printf "Target:\n"
    printf "    deps       install dependencies (gawk pdflatex)\n"
    printf "    man        install the man page in /usr/local/man/man1\n"
    printf "    t2fm       install an alias for t2fm in ~/.bash_aliases\n"
    printf "    all        install deps, t2fm and man\n"
    printf "\nOptional arguments:\n"
    printf "    -u         uninstall instead of install (man pages only)\n"
    printf "    -y         do not ask for confirmation before executing an action\n"
    printf "    -h         display this help and exit\n"
}

setup_dirs() {
    local install_prefix="/usr/local"
    MANDIR="$install_prefix/man/man1"
}

install_deps() {
    local deps=()
    type gawk &> /dev/null || deps+=(gawk)
    if [ "$(uname)" = "Darwin" ]; then
        type greadlink &> /dev/null || deps+=(coreutils)
        type gsed &> /dev/null || deps+=(gnu-sed)
        type pdflatex &> /dev/null || deps+=(mactex)
    else
        type readlink &> /dev/null || deps+=(coreutils)
        type sed &> /dev/null || deps+=(sed)
        type pdflatex &> /dev/null || deps+=(texlive-latex-extra)
    fi

    if [ -n "$deps" ]; then
        local cmd
        if hash pacman 2> /dev/null; then
            cmd="sudo pacman -S"
            [ $YES ] && cmd="$cmd --noconfirm"
        elif hash emerge 2> /dev/null; then
            cmd="sudo emerge"
            # TODO yes???
        elif hash yum 2> /dev/null; then
            cmd="sudo yum install"
            [ $YES ] && cmd="$cmd -y"
        elif hash zypper 2> /dev/null; then
            cmd="sudo zypper install"
            [ $YES ] && cmd="$cmd -y"
        elif hash apt-get 2> /dev/null; then
            cmd="sudo apt-get install"
            [ $YES ] && cmd="$cmd -y"
        elif [ "$(uname)" = "Drwin" ]; then
            if ! hash brew 2> /dev/null; then
                printinf "Installing Homebrew..."
                /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
                # TODO make sure command was successful
            fi
            cmd="brew install"
            # TODO yes???
        else
            printerr "Failed to install dependencies: no package utility found"
            printinf "Required dependencies are: ${deps}"
            printf "You may use your package utility to install them\n"
            exit 1
        fi

        printinf "Installing dependencies..."
        if [ "$(uname)" != "Darwin" ]; then
            printinf "You may be prompted for your password."
        fi
        $cmd ${deps[*]}
        if [ $? -ne 0 ]; then
            exit 1
        fi
    fi

    printok "All dependencies installed"
}

install_man() {
    printinf "Installing '$PKG_NAME' man pages\n"

    local destf
    for i in "$PKG_NAME"; do
        destf="$MANDIR/${i}.1.gz"
        $SUDO sh -c "install -d \"$MANDIR\" && gzip -c ${T2FMDIR}/man/${i}.1 > \"$destf\" && chmod 755 \"$destf\""

        if [ $? -ne 0 ]; then
            printerr "Failed to install man page for '$i'"
            exit 1
        fi

        printok "Man page for '$i' successfully installed in '$MANDIR'\n"
    done
}

uninstall_man() {
    printinf "Uninstalling '$PKG_NAME' man pages\n"

    local destf
    for i in "$PKG_NAME"; do
        destf="$MANDIR/${i}.1.gz"
        $SUDO rm -f "$destf"
        if [ $? -ne 0 ]; then
            printerr "Failed to remove man page for '$i'"
            exit 1
        fi

        printok "Man page for '$i' successfully removed from '$MANDIR'\n"
    done
}

install_t2fm() {
    local target="$HOME/.bash_aliases"
    if [ -n "$(grep 'alias t2fm=' "$target")" ]; then
        printerr "Alias for '$PKG_NAME' already exists in '$target'"
        exit 1
    fi

    echo "alias t2fm=\"${T2FMDIR}/t2fm\"" >> $HOME/.bash_aliases
    if [ $? -ne 0 ]; then
        printerr "Failed to install alias for '$PKG_NAME'"
        exit 1
    fi

    printok "Alias for '$PKG_NAME' successfully installed in '$target'\n"
}

uninstall_t2fm() {
    local target="$HOME/.bash_aliases"
    if [ -n "$(grep 'alias t2fm=' "$target")" ]; then
        printwrn "Alias for '$PKG_NAME' still exists in '$target'"
        return 1
    fi
    return 0
}

test_sudo() {
    if [[ $EUID -ne 0 ]]; then
        printf "**************************************************\n"
        printf "* The 'install' option requires root privileges. *\n"
        printf "**************************************************\n\n"
        SUDO="$(which sudo)"
        if [ -z "$SUDO" ]; then
            printerr "Failed to install '$PKG_NAME': 'sudo' command not found"
            exit 1
        fi
    fi
}

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

TO_INSTALL=()
while [ $# -gt 0 ]; do
    case "$1" in
        deps) TO_INSTALL+=(deps);;
        man) TO_INSTALL+=(man);;
        t2fm) TO_INSTALL+=(t2fm);;
        all) TO_INSTALL+=(deps man t2fm);;
        -u|--uninstall) UNINSTALL=1;;
        -y|--yes) YES=1;;
        -\?|-h|--help) usage; exit;;
        *) abort_option_unknown "$1";;
    esac
    shift
done

if [ -z "$TO_INSTALL" ]; then
    printerr "At least one target must be specified"
    abort_with_help
fi

setup_dirs

for i in "${TO_INSTALL[@]}"; do
    case "$i" in
        deps) [ ! "$UNINSTALL" ] && install_deps;;
        man)
            test_sudo
            if [ "$UNINSTALL" ]; then
                uninstall_man
            else
                install_man
            fi
            ;;
        t2fm)
            if [ "$UNINSTALL" ]; then
                uninstall_t2fm
            else
                install_t2fm
            fi
            ;;
    esac
done