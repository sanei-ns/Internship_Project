#!/usr/bin/env bash

source "$(dirname "$0")/../t2utils.sh"

T2CONFDIR="$(dirname "$($READLINK -f "$0")")"
PKG_NAME="$(basename "$T2CONFDIR")"
[ "$EDITOR" ] || EDITOR="$(which vim)"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...] <target>\n\n"
    printf "Target:\n"
    printf "    deps       install dependencies (dialog)\n"
    printf "    man        install the man page in /usr/local/man/man1\n"
    printf "    t2conf     install an alias for t2conf in ~/.bash_aliases\n"
    printf "    t2confrc   install predefined settings in ~/.tranalyzer/plugins\n"
    printf "    all        install deps, t2conf, t2confrc and man\n"
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
    type dialog &> /dev/null || deps+=(dialog)
    [ -z "$EDITOR" ] && deps+=(vim)

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
        $SUDO sh -c "install -d \"$MANDIR\" && gzip -c ${T2CONFDIR}/man/${i}.1 > \"$destf\" && chmod 755 \"$destf\""

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

install_t2conf() {
    local target="$HOME/.bash_aliases"
    if [ -n "$(grep 'alias t2conf=' "$target")" ]; then
        printerr "Alias for '$PKG_NAME' already exists in '$target'"
        exit 1
    fi

    echo "alias t2conf=\"${T2CONFDIR}/t2conf\"" >> $HOME/.bash_aliases
    if [ $? -ne 0 ]; then
        printerr "Failed to install alias for '$PKG_NAME'"
        exit 1
    fi

    printok "Alias for '$PKG_NAME' successfully installed in '$target'\n"
}

uninstall_t2conf() {
    local target="$HOME/.bash_aliases"
    if [ -n "$(grep 'alias t2conf=' "$target")" ]; then
        printwrn "Alias for '$PKG_NAME' still exists in '$target'"
        return 1
    fi
    return 0
}

install_t2confrc() {
    local plugin_folder="$HOME/.tranalyzer/plugins"
    local file="t2confrc"

    if [ ! -d "$plugin_folder" ]; then
        mkdir -p "$plugin_folder"
        if [ $? -ne 0 ]; then
            printerr "Failed to create folder '$plugin_folder'"
            exit 1
        fi
    fi

    local srcfile="${T2CONFDIR}/$file"
    local dstfile="${plugin_folder}/$file"

    if [ -f "$dstfile" ]; then
        cmp -s "$srcfile" "$dstfile" &> /dev/null
        if  [ $? -eq 0 ]; then
            printok "'$file' already exists in '$plugin_folder'\n"
            return
        else
            printwrn "A different version of '$file' already exists in '$plugin_folder'..."
            printf "Overwrite it (y/N)? "
            local ans
            if [ -z "$YES" ]; then
                read ans
            else
                ans="yes"
                echo "$ans"
            fi
            case "$ans" in
                [yY]|[yY][eE][sS])
                    ;;
                *)
                    printinf "'$file' not copied to '$plugin_folder'\n"
                    return
                    ;;
            esac
        fi
    fi

    cp "$srcfile" "$dstfile"
    if [ $? -ne 0 ]; then
        printerr "Failed to copy '$file' to '$plugin_folder'"
        exit 1
    fi

    printok "'$file' successfully copied to '$plugin_folder'\n"
}

uninstall_t2confrc() {
    local plugin_folder="$HOME/.tranalyzer/plugins"
    local file="t2confrc"

    rm -f "$plugin_folder/$file"
    if [ $? -ne 0 ]; then
        printerr "Failed to remove '$file' from '$plugin_folder'"
        exit 1
    fi

    printok "'$file' successfully removed from '$plugin_folder'\n"
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
        t2conf) TO_INSTALL+=(t2conf);;
        t2confrc) TO_INSTALL+=(t2confrc);;
        all) TO_INSTALL+=(deps man t2conf t2confrc);;
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
        t2conf)
            if [ "$UNINSTALL" ]; then
                uninstall_t2conf
            else
                install_t2conf
            fi
            ;;
        t2confrc)
            if [ "$UNINSTALL" ]; then
                uninstall_t2confrc
            else
                install_t2confrc
            fi
            ;;
    esac
done
