#!/usr/bin/env bash

NO_DEPENDENCIES_CHECK=1
source "$(dirname "$0")/scripts/t2utils.sh"

# TODO
#    - only build tranalyzer2
#    - build all the plugins

usage() {
    echo "Usage:"
    echo "    $SNAME [OPTION...]"
    echo
    echo "Optional arguments:"
    echo "    -D, --no-deps     Do not install dependencies"
    echo "    -G, --no-gui      Do not install gui-dependencies"
    echo "    -T, --no-latex    Do not install LaTeX dependencies"
    echo "    -E, --no-empty    Do not empty the plugin folder"
    echo "    -B, --no-build    Do not build tranalyzer and the plugins"
    echo "    -M, --no-man      Do not install man pages"
    echo "    -A, --no-aliases  Do not install t2_aliases"
    echo
    echo "    -d, --deps        Only install the dependencies"
    echo "    -e, --empty       Only empty the plugin folder"
    echo "    -b, --build       Only build tranalyzer and the plugins"
    echo "    -m, --man         Only install the man pages"
    echo "    -a, --aliases     Only install the aliases"
    echo
    echo "    -i, --ask         Ask for confirmation before executing an action"
    #echo "    -y, --yes         Do not ask for confirmation before executing an action"
    echo
    echo "    -h, --help        Show this help, then exit"
}

get_rc_file() {
    local destrc
    if [ -n "$ZSH_VERSION" ] && [ -f "$HOME/.zshrc" ]; then
        destrc="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        destrc="$HOME/.bashrc"
    elif [ -f "$HOME/.cshrc" ]; then
        destrc="$HOME/.cshrc"
    elif [ -f "$HOME/.bash_profile" ] || [ "$(uname)" = "Darwin" ]; then
        destrc="$HOME/.bash_profile"
    fi
    echo $destrc
}

alias_msg() {
    local rcfile="$(get_rc_file)"
    [ -n "$rcfile" ] || rcfile="$HOME/.bashrc"
    printwrn "${BOLD}To access all aliases, open a new terminal or run: source $rcfile\n"
    printf "Run Tranalyzer as follows: t2 -r path/to/file.pcap\n"
    printf "For more details, run t2 --help or t2doc tranalyzer2\n"
}

noalias_msg() {
    local rcfile="$(get_rc_file)"
    [ -n "$rcfile" ] || rcfile="$HOME/.bashrc"
    printf "Tranalyzer can be run as follows:\n\n"
    printf "$T2HOME/tranalyzer2/src/tranalyzer -r path/to/file.pcap\n\n"
    printf "For more details, run $T2HOME/tranalyzer2/src/tranalyzer --help or refer to the documentation under $T2HOME/doc/documentation.pdf\n\n"
    printinf "To access all aliases, copy the following code into your shell startup file, e.g., $rcfile:\n"
    cat << EOF
if [ -f "$T2HOME/scripts/t2_aliases" ]; then
    . "$T2HOME/scripts/t2_aliases"
fi

EOF
    printinf "Then open a new terminal or run: source $rcfile\n"
}

install_deps() {
    # libpcap, texlive and zlib depend on distribution... (see below)
    local deps=(automake make coreutils dialog gawk libtool bzip2)
    if [ "$(uname)" = "Darwin" ]; then
        deps+=(gnu-sed)
        hash greadlink 2> /dev/null || deps+=(coreutils)
    else
        deps+=(sed)
        hash readlink 2> /dev/null || deps+=(coreutils)
    fi

    [ $NOGUI ] || deps+=(xdg-utils)

    local cmd
    if hash pacman 2> /dev/null; then
        cmd="sudo pacman -S"
        [ -n "$YES" ] && cmd="$cmd --noconfirm"
        deps+=(libpcap zlib)
        [ $NOLATEX ] || deps+=(texlive-most)
    elif hash emerge 2> /dev/null; then
        cmd="sudo emerge"
        # TODO yes???
        deps+=(libpcap zlib)
        [ $NOLATEX ] || deps+=(texlive-fontsrecommended texlive-latexextra)
    elif hash yum 2> /dev/null; then
        cmd="sudo yum install"
        [ -n "$YES" ] && cmd="$cmd -y"
        deps+=(libpcap-devel zlib-devel)
        [ $NOLATEX ] || deps+=(texlive-collection-fontsrecommended texlive-collection-latexextra)
    elif hash zypper 2> /dev/null; then
        cmd="sudo zypper install"
        [ -n "$YES" ] && cmd="$cmd -y"
        deps+=(gcc libpcap-devel zlib-devel)
        [ $NOLATEX ] || deps+=(texlive-collection-fontsrecommended texlive-collection-latexextra)
    elif hash apt-get 2> /dev/null; then
        cmd="sudo apt-get install"
        [ -n "$YES" ] && cmd="$cmd -y"
        deps+=(libpcap-dev zlib1g-dev)
        [ $NOLATEX ] || deps+=(texlive-fonts-recommended texlive-latex-extra)
    elif [ "$(uname)" = "Darwin" ]; then
        if ! hash brew 2> /dev/null; then
            printinf "Installing Homebrew..."
            /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
            # TODO make sure command was successful
        fi
        cmd="brew install"
        # TODO yes???
        local cmd_cask="brew cask install"
        [ $NOLATEX ] || local deps_cask=(mactex)
        deps+=(bash-completion libpcap pidof watch zlib)
    else
        printerr "\nFailed to install dependencies: no package utility found"
        printinf "Required dependencies are: ${deps}"
        printf "You may use your package utility to install them\n"
        exit 1
    fi

    if [ -n "$cmd" ]; then
        printinf "Installing dependencies..."
        if [ "$(uname)" = "Darwin" ]; then
            if [ "$deps_cask" ]; then
                $cmd_cask ${deps_cask[*]}
                if [ $? -ne 0 ]; then
                    printerr "Failed to install dependencies..."
                    printinf "Command was: $cmd_cask ${deps_cask[*]}"
                    exit 1
                fi
            fi
        else
            printinf "You may be prompted for your password."
        fi
        $cmd ${deps[*]}
        if [ $? -ne 0 ]; then
            printerr "Failed to install dependencies..."
            printinf "Command was: $cmd ${deps[*]}"
            exit 1
        fi
    fi

    if [ -z "$READLINK" ]; then
        # [g]readlink should exist now...
        # Make sure T2HOME is absolute!
        source "$(dirname "$0")/scripts/t2utils.sh"
    fi
}

empty_plugin_folder() {
    "$T2BUILD" -e $YES || exit 1
}

build_tranalyzer() {
    "$T2BUILD" -f $YES || exit 1
}

install_man() {
    "$T2HOME/scripts/t2conf/install.sh" man t2confrc
    "$T2HOME/scripts/t2fm/install.sh" man
    "$T2HOME/scripts/tawk/install.sh" man
    "$T2HOME/tranalyzer2/install.sh" man
}

install_aliases() {
    local destrc="$(get_rc_file)"
    if [ ! -f "$destrc" ]; then
        printerr "\nFailed to install t2_aliases: $HOME/{.bashrc,.cshrc,.zshrc,.bash_profile} not found.\n"
        noalias_msg
        printwrn "Setup incomplete.\n"
        exit 1
    fi

    if [ -f "$destrc" ] && [ -n "$(grep "^[^#]\s\+\.\s\+\"$T2HOME/scripts/t2_aliases\"" "$destrc")" ]; then
        printinf "\nt2_aliases already installed."
    elif [ -f "$destrc" ] && [ -n "$(grep "^[^#]\s\+\.\s\+\".*/t2_aliases\"" "$destrc")" ]; then
        local new_path="$T2HOME/scripts"
        local old_path="$(grep "^[^#]\s\+\.\s\+\".*/t2_aliases\"" "$destrc")"
        old_path="$(perl -pe "s|^[^#]\s+\.\s+\"(.*)/t2_aliases\"|\${1}|" <<< "$old_path")"
        printwrn "\nt2_aliases already installed from '$old_path'"
        printf "Replace with '$new_path' (y/N)? "
        local ans
        if [ -z "$YES" ]; then
            read ans
        else
            ans="yes"
            echo "$ans"
        fi
        case "$ans" in
            [yY]|[yY][eE][sS])
                perl -i -pe "s|(^if\s+\[\s+-f\s+\").*(/t2_aliases\"\s+\];\s+then)|\${1}$new_path\${2}|p" "$destrc"
                perl -i -pe "s|(^[^#]\s+\.\s+\").*(/t2_aliases\")|\${1}$new_path\${2}|p" "$destrc"
                printok "\n\nt2_aliases successfully updated in '$destrc'.\n"
                ;;
            *)
                noalias_msg
                printwrn "\nSetup incomplete.\n"
                exit 1
                ;;
        esac
    else
cat << EOF >> "$destrc"

    if [ -f "$T2HOME/scripts/t2_aliases" ]; then
        . "$T2HOME/scripts/t2_aliases"
    fi
EOF
        printok "\nt2_aliases successfully installed in '$destrc'.\n"
    fi
}

cleanup() {
    exit $1
}

trap "trap - SIGTERM && cleanup 1" HUP INT QUIT TERM
trap "cleanup \$?" EXIT

YES="-y"
ALL=(deps empty build man aliases)

ARGS="$@"

while [ $# -ne 0 ]; do
    case "$1" in

        -G|--no-gui)     NOGUI=1;;
        -T|--no-latex)   NOLATEX=1;;

        -D|--no-deps)    ALL=(${ALL[@]/deps/});;
        -E|--no-empty)   ALL=(${ALL[@]/empty/});;
        -B|--no-build)   ALL=(${ALL[@]/build/});;
        -M|--no-man)     ALL=(${ALL[@]/man/});;
        -A|--no-aliases) ALL=(${ALL[@]/aliases/});;

        -d|--deps)       ACTIONS+=(deps);;
        -e|--empty)      ACTIONS+=(empty);;
        -b|--build)      ACTIONS+=(build);;
        -m|--man)        ACTIONS+=(man);;
        -a|--aliases)    ACTIONS+=(aliases);;

        -i|--ask) unset YES;;
        #-y|--yes) YES="-y";;

        -h|-\?|--help)
            usage
            exit 0
            ;;

        *)
            abort_option_unknown "$1"
            ;;
    esac
    shift
done

if [ -z "$READLINK" ] && [ "$(dirname "$0")" != "." ]; then
    printerr "$SNAME MUST be run from Tranalyzer root folder"
    printinf "Go to Tranalyzer root folder and run ./$SNAME $ARGS"
    exit 1
fi

# Make sure all the commands are run from the root folder of Tranalyzer
cd "$T2HOME"

# Make sure the scripts are executable
if [ ! -x autogen.sh ]; then
    chmod +x autogen.sh */autogen.sh plugins/*/autogen.sh scripts\
             scripts/tawk/tawk scripts/t2fm/t2fm scripts/t2conf/t2*conf \
             plugins/basicFlow/utils/subconv plugins/basicFlow/tor/torldld \
             plugins/dnsDecode/utils/dmt plugins/macRecorder/utils/mconv \
             plugins/nDPI/clean.sh plugins/netflowSink/utils/ampls \
             scripts/*/install.sh tranalyzer2/install.sh
fi

if [ -z "$ACTIONS" ]; then
    ACTIONS="${ALL[@]}"
else
    ACTIONS="${ACTIONS[@]}"
fi

for action in ${ALL[@]}; do
    if [ -n "$(grep -Fw "$action" <<< "$ACTIONS")" ]; then
        case $action in
            deps)    install_deps;;
            empty)   empty_plugin_folder;;
            build)   build_tranalyzer;;
            man)     install_man;;
            aliases) install_aliases;;
        esac
    fi
done

printok "\n${BOLD}Setup complete.${NOCOLOR}\n"

if [ -z "$(grep -Fw "aliases" <<< "$ACTIONS")" ]; then
    noalias_msg
else
    alias_msg
fi
