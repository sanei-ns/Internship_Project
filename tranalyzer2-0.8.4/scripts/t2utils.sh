#!/usr/bin/env bash
#
# Collection of bash functions and variables:
#
#   Functions:
#       - printerr, printinf, printok, printwrn
#       - check_dependency, check_dependency_linux, check_dependency_osx
#       - has_define, get_define, set_define
#       - replace_suffix
#       - get_nproc
#       - arg_is_option
#       - validate_next_arg, validate_next_arg_exists,
#         validate_next_dir, validate_next_file, validate_next_pcap
#         validate_next_num, validate_next_int, validate_next_float,
#       - validate_ip, validate_pcap
#       - abort_missing_arg, abort_option_unknown, abort_required_file,
#         abort_with_help
#
#   Programs:
#       - AWK, AWKF, OPEN, READLINK, SED, T2, T2BUILD, T2CONF, TAWK
#
#   Folders:
#       - SHOME, T2HOME, T2PLHOME
#
#   Colors:
#       - BLUE, GREEN, ORANGE, RED
#       - BLUE_BOLD, GREEN_BOLD, ORANGE_BOLD, RED_BOLD,
#       - BOLD
#       - NOCOLOR
#
#   Variables:
#       - SNAME
#
# Usage:
#
#   source this file in your script as follows:
#
#      source "$(dirname "$0")/t2utils.sh"
#
#   Note that if your script is not in the scripts/ folder,
#   you will need to adapt the path to t2utils accordingly
#
#   [ZSH] If writing a script for ZSH, add the following line
#         BEFORE sourcing the script:
#
#           unsetopt function_argzero

# Colors
BLUE="\e[0;34m"
GREEN="\e[0;32m"
ORANGE="\e[0;33m"
RED="\e[0;31m"
BLUE_BOLD="\e[1;34m"
GREEN_BOLD="\e[1;32m"
ORANGE_BOLD="\e[1;33m"
RED_BOLD="\e[1;31m"
BOLD="\e[1m"
NOCOLOR="\e[0m"

# ---------------- #
# Public functions #
# ---------------- #

printerr() {
    printf "${RED}${1}${NOCOLOR}\n" >&2
}

printok() {
    printf "${GREEN}${1}${NOCOLOR}\n"
}

printwrn() {
    printf "${ORANGE}${1}${NOCOLOR}\n"
}

printinf() {
    printf "${BLUE}${1}${NOCOLOR}\n"
}

abort_with_help() {
    printf "Try '$SNAME --help' for more information.\n"
    exit 1
}

abort_required_file() {
    printerr "Input file is required"
    abort_with_help
}

# $1: name of the option
abort_missing_arg() {
    printerr "Option '$1' requires an argument"
    abort_with_help
}

# $1: name of the option
abort_option_unknown() {
    printerr "Unkown option '$1'"
    abort_with_help
}

# $1: argument to validate
arg_is_option() {
    if [ -n "$1" ] && [ "${1:0:1}" == "-" ]; then
        echo 0
    else
        echo 1
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_arg() {
    if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
        return 0
    else
        printerr "Option '$1' requires an argument"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_arg_exists() {
    if [ -n "$2" ]; then
        return 0
    else
        printerr "Option '$1' requires an argument"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_dir() {
    validate_next_arg "$1" "$2"
    if [ -d "$2" ]; then
        return 0
    else
        printerr "Invalid argument for option '$1': '$2' is not a directory"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_file() {
    validate_next_arg "$1" "$2"
    if [ -f "$2" ]; then
        return 0
    else
        printerr "Invalid argument for option '$1': '$2' is not a regular file"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_num() {
    validate_next_arg "$1" "$2"
    if [ -z "$(tr -d '0-9' <<< "$2")" ]; then
        return 0
    else
        printerr "Invalid argument for option '$1': expected number; found '$2'"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_float() {
    if [ -z "$2" ]; then
        printerr "Option '$1' requires an argument"
        abort_with_help
    fi
    if [ -n "$($AWK '/^-?[0-9]+(\.[0-9]*)?$/' <<< "$2")" ]; then
        return 0
    else
        printerr "Invalid argument for option '$1': expected float; found '$2'"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_int() {
    if [ -z "$2" ]; then
        printerr "Option '$1' requires an argument"
        abort_with_help
    fi
    if [ -n "$($AWK '/^-?[0-9]+$/' <<< "$2")" ]; then
        return 0
    else
        printerr "Invalid argument for option '$1': expected integer; found '$2'"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_pcap() {
    validate_next_file "$1" "$2"
    if [ -n "$(file -b "$2" | grep ' capture file ')" ]; then
        return 0
    else
        printerr "Invalid argument for option '$1': '$2' is not a valid PCAP file"
        abort_with_help
    fi
}

# $1: IP address to validate
validate_ip() {
    if [ -n "$1" ] && [ -n "$($AWK '/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/' <<< "$1")" ]; then
        return 0
    else
        printerr "'$1' is not a valid IPv4 address"
        return 1
    fi
}

# $1: PCAP file to validate
validate_pcap() {
    if [ -n "$1" ] && [ -f "$1" ] && [ -n "$(file -b "$1" | grep ' capture file ')" ]; then
        return 0
    else
        printerr "'$1' is not a valid PCAP file"
        return 1
    fi
}

# $1: name of the program
# $2: name of the package in which the program can be found (if omitted, use $1)
check_dependency_linux() {
    local cmd="$1"
    local deps="${2:-$1}"
    local pgrmname pgrmcmd
    type "$cmd" &> /dev/null || {
        if hash apt-get 2> /dev/null; then
            pgrmname="apt-get"
            pgrmcmd="apt-get install"
        elif hash pacman 2> /dev/null; then
            pgrmname="pacman"
            pgrmcmd="pacman -S"
        elif hash yum 2> /dev/null; then
            pgrmname="yum"
            pgrmcmd="yum install"
        else
            pgrmname="your package utility"
        fi
        [ -n "$pgrmcmd" ] && pgrmcmd=": $pgrmcmd $deps"
        printerr "Missing dependency: $deps"
        printinf "You may use $pgrmname to install it$pgrmcmd"
        exit 1
    }
}

# $1: name of the program
# $2: name of the package in which the program can be found (if omitted, use $1)
check_dependency_osx() {
    local cmd="$1"
    local deps="${2:-$1}"
    type "$cmd" &> /dev/null || {
        printerr "Missing dependency: $deps"
        printinf "You may use homebrew to install it: brew install $deps"
        exit 1
    }
}

# $1: name of the program
# $2: name of the package in which the program can be found (if omitted, use $1)
check_dependency() {
    if [ "$(uname)" = "Darwin" ]; then
        check_dependency_osx "$1" "$2"
    else
        check_dependency_linux "$1" "$2"
    fi
}

# $1: name of the file
# $2: name of the define
has_define() {
    local file="$1"
    local name="$2"
    if [ ! -f "$file" ]; then
        printerr "Invalid argument for function 'has_define()': '$file' is not a regular file"
        exit 1
    fi
    if [ -z "$(grep "^#define\s\+$name\s\+" "$file")" ]; then
        echo 1
    fi
    echo 0
}

# $1: name of the define
# $2: name of the file
get_define() {
    local name="$1"
    local file="$2"
    if [ $(has_define "$file" "$name") -eq 1 ]; then
        printerr "Invalid argument for function 'get_define()': macro '$name' does not exist in '$file'"
        exit 1
    fi
    perl -nle "print \$1 if /^#define\s+$name\s+([^\s]((?!\s*\/[\/\*]|\s*$).)*).*$/" "$file"
}

# $1: name of the define
# $2: value of the define
# $3: name of the file
set_define() {
    local name="$1"
    local value="$2"
    local file="$3"
    if [ $(has_define "$file" "$name") -eq 1 ]; then
        printerr "Invalid argument for function 'set_define()': macro '$name' does not exist in '$file'"
        exit 1
    fi
    if [ -z "$value" ]; then
        printerr "Invalid argument for function 'set_define()': cannot give an empty value to a define"
        exit 1
    fi
    # escape \, /, *, ", &, $ and . from $value
    local newval="$($SED 's/\([\\/*"&$.]\)/\\\1/g' <<< "$value")"
    perl -i -pe "s/(^#define\s+$name\s+)([^\s]((?!\s*\/[\/\*]|\s*$).)*)(.*$)/\${1}$newval\${4}/p" "$file"
}

# Replace the suffix of a filename
#   $1: filename
#   $2: old suffix to replace
#   $3: new suffix
replace_suffix() {
    local name="$1"
    local old_suffix="$2"
    local new_suffix="$3"
    local prefix="$($AWK -v suffix="$old_suffix" '{
        gsub(suffix "$", "")
        print
    }' <<< "$name")"
    if [ "$prefix" = "$name" ] && [ -z "$suffix" ]; then
        printerr "replace_suffix: Suffix '$old_suffix' not found in '$name' and new suffix is empty"
        exit 1
    fi
    echo "$prefix$new_suffix"
}

get_nproc() {
    if hash nproc 2> /dev/null; then
        nproc
    elif hash lscpu 2> /dev/null; then
        lscpu | grep "^CPU(s):" | $AWK '{ print $2 }'
    elif [ -f "/proc/cpuinfo" ]; then
        grep -c "^processor" /proc/cpuinfo
    elif [ "$(uname)" = "Darwin" ]; then
        sysctl -an hw.ncpu
    else
        echo 1
    fi
}

# ----------------- #
# Private functions #
# ----------------- #

_check_awk_version() {
    # Required for tawk
    local gver="$($AWK --version | $AWK '{ print $3; exit }')"
    if [[ $gver < 4.1 ]]; then
        printerr "Minimum gawk version required is 4.1, found '$gver'"
        exit 1
    fi

    # Required for tawk IPv6 functions
    if [ -z "$($AWK -h | grep "^\s\+-M\s\+--bignum$")" ]; then
        printwrn "Your gawk version does not support bignum: IPv6 handling may be buggy"
    fi
}

_check_dependencies_linux() {
    local cmds=(readlink gawk sed)
    local deps=(coreutils gawk sed)
    for i in ${!cmds[@]}; do
        check_dependency_linux "${cmds[i]}" "${deps[i]}"
    done

    AWK="$(which gawk)"
    READLINK="$(which readlink)"
    SED="$(which sed)"
    OPEN="$(which xdg-open)"
}

_check_dependencies_osx() {
    local cmds=(greadlink gawk gsed)
    local deps=(coreutils gawk gnu-sed)
    for i in ${!cmds[@]}; do
        check_dependency_osx "${cmds[i]}" "${deps[i]}"
    done

    AWK="$(which gawk)"
    READLINK="$(which greadlink)"
    SED="$(which gsed)"
    OPEN="$(which open)"
}

_check_dependencies() {
    if [ "$(uname)" = "Darwin" ]; then
        _check_dependencies_osx
    else
        _check_dependencies_linux
    fi
    # XXX This is only required for tawk... so let tawk do the testing
    # (Keep this commented out, so Ubuntu 14.04 can still use this script)
    #_check_awk_version
}

_t2utils_init() {
    # Check for required programs
    if [ -z "$NO_DEPENDENCIES_CHECK" ]; then
        _check_dependencies
    elif [ "$(uname)" = "Darwin" ]; then
        AWK="$(which gawk awk | head -1)"
        READLINK="$(which greadlink)"
    else
        AWK="$(which gawk awk | head -1)"
        READLINK="$(which readlink)"
    fi

    local readlink_f
    if [ -z "$READLINK" ]; then
        readlink_f="echo"
    else
        readlink_f="$READLINK -f"
    fi

    # Set script name and home
    SNAME="$(basename "$0")"
    SHOME="$($readlink_f "$(dirname "$0")")"

    # Set T2HOME
    if [ -n "$ZSH_VERSION" ]; then
        T2HOME="$(dirname "${(%):-%x}")/.."
    else
        T2HOME="$(dirname "$BASH_SOURCE")/.."
    fi
    T2HOME="$($readlink_f "$T2HOME")"
    T2PLHOME="$T2HOME/plugins"

    # Set path to programs
    AWKF=("$AWK" -F'\t' -v OFS='\t')
    TAWK="$T2HOME/scripts/tawk/tawk"
    T2="$T2HOME/tranalyzer2/src/tranalyzer"
    T2BUILD="$T2HOME/autogen.sh"
    T2CONF="$T2HOME/scripts/t2conf/t2conf"
}

# -------------- #
# Initialisation #
# -------------- #

_t2utils_init
