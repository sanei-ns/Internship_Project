Tranalyzer2 Installation Procedure
==================================

Getting the Latest Version
--------------------------

1. Download the latest version of Tranalyzer2 [here](https://tranalyzer.com/downloads)
2. Extract the content of the downloaded archive:
```
$ tar xzf tranalyzer2-0.8.4.tar.gz
```

Installation - The Easy Way
---------------------------

Go into tranalyzer2 root folder and run the `setup.sh` script:

```
$ cd tranalyzer2-0.8.4
$ ./setup.sh
```

Open a new terminal and you are now ready to use Tranalyzer!
Start learning how [here](https://tranalyzer.com/tutorial/basicanalysis).

Installation - The Detailed Way
-------------------------------

If you are a more advanced user, you can run the commands performed by the `setup.sh` script manually as follows:

### Dependencies
* **Ubuntu/Kali:**
```
$ sudo apt-get install automake libpcap-dev libtool make zlib1g-dev
```

* **Arch:**
```
$ sudo pacman -S automake make libpcap libtool zlib
```

* **Gentoo:**
```
$ sudo emerge automake libpcap libtool zlib
```

* **OpenSUSE:**
```
$ sudo zypper install automake gcc libpcap-devel libtool zlib-devel
```

* **Red Hat/Fedora/CentOS:**
```
$ sudo yum install automake libpcap-devel libtool zlib-devel bzip2
```

* **Mac OS X**  (using [Homebrew](https://brew.sh) package manager):
```
$ brew install autoconf automake libpcap libtool zlib
```

### Aliases
This step will give you access to all aliases (`t2`, `t2build`, ...) used in the tutorials.

1. Go to the root folder of Tranalyzer
```
cd tranalyzer2-0.8.4
```

2. Save this location in the variable `$T2HOME`:
```
$ T2HOME="$PWD"
$ echo $T2HOME
/home/user/tranalyzer2-0.8.4
```

3. The file `$T2HOME/scripts/t2_aliases` provides a set of aliases and functions which facilitate working with Tranalyzer. To access them, copy the code below. This will identify your terminal configuration file and then modify it.
```
TOADD="$(cat << EOF
if [ -f "$T2HOME/scripts/t2_aliases" ]; then
    . "$T2HOME/scripts/t2_aliases" # Note the leading '.'
fi
EOF
)"
if [ -f "$HOME/.bashrc" ]; then
    echo "$TOADD" >> "$HOME/.bashrc"
    source "$HOME/.bashrc"
    echo "Aliases installed in $HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then
    echo "$TOADD" >> "$HOME/.zshrc"
    source "$HOME/.zshrc"
    echo "Aliases installed in $HOME/.zshrc"
elif [ -f "$HOME/.bash_profile" ]; then
    echo "$TOADD" >> "$HOME/.bash_profile"
    source "$HOME/.bash_profile"
    echo "Aliases installed in $HOME/.bash_profile"
else
    echo "No standard terminal configuration file found."
fi
```

### Compilation (using aliases installed in step 2)

To build Tranalyzer2 and the plugins, run one of the following commands:

* Tranalyzer2 and a default set of plugins:
```
t2build
```

* Tranalyzer2 and all the plugins:
```
$ t2build -a
```

* Tranalyzer2 and a custom set of plugins (listed in `plugins.build`):
```
t2build -b
```

* Tranalyzer2 and a custom set of plugins (listed in `myplugins.txt`):
```
$ t2build -b myplugins.txt
```

To build a specific plugin, use `t2build pluginName` (note that completion is available, so if you type `t2build <tab>`, you will see a list of all the plugins and if you type `t2build http<tab>` it will automatically complete the command to `t2build httpSniffer`). Note that you can specify more than one plugin name, e.g., `t2build httpSniffer txtSink`
Run `t2build --help` for the full list of options accepted by the scripts.

`t2build -i` can be used to install Tranalyzer2 in `/usr/local/bin` and the man page in `/usr/local/man/man1`. Note that root rights are required for the installation.

### Compilation (without using aliases installed in step 2)

To build Tranalyzer2 and the plugins, run one of the following commands (make sure that `$T2HOME` points to the root folder of Tranalyzer, i.e., where the `README.md` and `ChangeLog` files are located):

* Tranalyzer2 and a default set of plugins:
```
$ cd $T2HOME
$ ./autogen.sh
```

* Tranalyzer2 and all the plugins:
```
$ cd $T2HOME
$ ./autogen.sh -a
```

* Tranalyzer2 and a custom set of plugins (listed in `plugins.build`):
```
$ cd $T2HOME
$ ./autogen.sh -b
```

* Tranalyzer2 and a custom set of plugins (listed in `myplugins.txt`):
```
$ cd $T2HOME
$ ./autogen.sh -b myplugins.txt
```

For finer control of which plugins to build, either run `./autogen.sh` from every folder you want to build, e.g., `cd "$T2HOME/plugins/httpSniffer" && ./autogen.sh` or run `./autogen.sh pluginName` from the root folder of Tranalyzer2. Note that you can specify more than one plugin name, e.g., `./autogen.sh httpSniffer txtSink`

Run `./autogen.sh --help` for the full list of options accepted by the scripts.

`./autogen.sh -i` can be used to install Tranalyzer2 in `/usr/local/bin` and the man page in `/usr/local/man/man1`. Note that root rights are required for the installation.

Documentation
-------------

Tranalyzer2 core and every plugin come with their own documentation found in the `doc/` subfolder, e.g., `tranalyzer2/doc/tranalyzer2.pdf`.
The full documentation of Tranalyzer2 and all the locally available plugins can be built by running `make` in `$T2HOME/doc` and accessed by running `evince doc/documentation.pdf` (Replace `evince` with your preferred PDF viewer). Note that if the `setup.sh` script was used or `t2_aliases` was installed, then the `t2doc` function can be used to access the documentation as follows:

* Full documentation:
```
$ t2doc
```

* Tranalyzer2 core documentation:
```
$ t2doc tranalyzer2
```

* Scripts documentation:
```
$ t2doc scripts
```

* Plugin documentation, e.g., basicFlow:
```
$ t2doc basicFlow
```

Copyright
---------

Copyright (c) 2008-2019 by Tranalyzer Development Team
