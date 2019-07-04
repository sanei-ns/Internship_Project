\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{t2doc}[2015/08/28 v0.1]

\LoadClass[10pt,a4paper,titlepage,twoside]{article}

\RequirePackage{amsmath}
\RequirePackage{amsfonts}
\RequirePackage{amssymb}
\RequirePackage[english]{babel}
\RequirePackage{booktabs}
\RequirePackage{color}
\RequirePackage[table]{xcolor}
\RequirePackage{currfile}
\RequirePackage{fancyhdr}
\RequirePackage{float}
\RequirePackage[T1]{fontenc}
\RequirePackage[a4paper,includeheadfoot,pdftex]{geometry}
\RequirePackage{graphicx}
\RequirePackage{hyperref}
\RequirePackage[utf8x]{inputenc}
\RequirePackage{longtable}
\RequirePackage{multicol}
\RequirePackage{multirow}
\RequirePackage{nicefrac}
\RequirePackage{pslatex}
\RequirePackage{subfigure}
\RequirePackage{tabularx}
\RequirePackage{verbatimbox}
\RequirePackage[sort&compress]{natbib}
%\RequirePackage{bytefield}

\definecolor{darkblue}{rgb}{0,0,.6}
\hypersetup{
    breaklinks = true,
    colorlinks = true,
    urlcolor   = blue,
    citecolor  = darkblue,
    filecolor  = darkblue,
    linkcolor  = darkblue,
}
\RequirePackage{footnotehyper}

% Listings
%\definecolor{grey}{rgb}{.96,.96,.96}
\RequirePackage{listings}
\renewcommand{\lstlistlistingname}{List of listings}
\lstset{
    %language         = {c},
    numbers          = {none},
    tabsize          = {4},
    frame            = {single},
    breaklines       = {true},
    showspaces       = {false},
    showstringspaces = {false},
    basicstyle       = {\footnotesize\ttfamily},
    commentstyle     = {\em\color{blue}},
    keywordstyle     = {\bf},
    numberstyle      = {\footnotesize\ttfamily},
    stringstyle      = {\em},
    framexleftmargin = {2.5mm},
    %backgroundcolor  = {\color{grey}},
    xleftmargin      = {4mm},
    captionpos       = {b},
}
\pagestyle{fancy}

\geometry{
    top      = 20mm,
    left     = 20mm,
    right    = 20mm,
    bottom   = 50mm,
    headsep  = 10mm,
    footskip = 10mm
}
\fancyhfoffset[R]{0mm}
\voffset-10mm
\topmargin0mm
\headsep10mm
\headheight20mm
\hbadness=10000
\vbadness=10000
\overfullrule=50pt

\newcommand{\HRule}[1]{\rule{\linewidth}{#1}}

\graphicspath{{./img/}}

\RequirePackage{caption}
\captionsetup{
   labelfont = bf,
   textfont  = it,
}

% References
\newcommand{\reff}[1]{Figure~\ref{#1}}
\newcommand{\refl}[1]{Listing~\ref{#1}}
\newcommand{\refs}[1]{Section~\ref{#1}}
\newcommand{\reft}[1]{Table~\ref{#1}}

% Alternate row color
%\newcommand\altrowcolor{gray!10}
%
% longtable
%\let\oldlongtable\longtable
%\let\endoldlongtable\endlongtable
%\renewenvironment{longtable}{%
%    \rowcolors{2}{white}{\altrowcolor}%
%    \oldlongtable%
%}{%
%    \endoldlongtable%
%    \global\rownum=0\relax%
%}
%% longtablex
%%\let\oldlongtablex\longtablex
%%\let\endoldlongtablex\endlongtablex
%%\renewenvironment{longtablex}{%
%%    \rowcolors{2}{white}{\altrowcolor}%
%%    \oldlongtablex%
%%}{%
%%    \endoldlongtablex%
%%    \global\rownum=0\relax%
%%}
%% tabular
%\let\oldtabular\tabular
%\let\endoldtabular\endtabular
%\renewenvironment{tabular}{%
%    \rowcolors{2}{white}{\altrowcolor}%
%    \oldtabular%
%}{%
%    \endoldtabular%
%    \global\rownum=0\relax%
%}
%% tabularx
%\let\oldtabularx\tabularx
%\let\endoldtabularx\endtabularx
%\renewenvironment{tabularx}{%
%    \rowcolors{2}{white}{\altrowcolor}%
%    \oldtabularx%
%}{%
%    \endoldtabularx%
%    \global\rownum=0\relax%
%}

% New page for each section
\let\stdsection\section
\renewcommand\section{\clearpage\stdsection}

\cfoot{%
    {\bf\thepage}\\%
    {\small Copyright \copyright\ 2008--2019 by Tranalyzer Development Team}}

\setcounter{tocdepth}{2}

\newcommand{\trantitle}[3]{%
    \ifnum\thepage<2
        \hypersetup{
            pdfauthor  = {#3},
            pdftitle   = {#1},
            pdfsubject = {#2},
        }
        \pagenumbering{alph}
        \author{#3}
        \title{%
            \HRule{0.5pt}\\[0.2cm]
            \Huge\textbf{Tranalyzer2}\\[0.2cm]
            \Large\textbf{#1}\\[0.2cm]
            \includegraphics[scale=0.15]{img/tarantula}\\
            \large #2\\
            \HRule{2pt}\\[3.0cm]
            \includegraphics[scale=1.4]{img/anteater.jpg}\\
        }
        \date{}
        \maketitle
        \tableofcontents
        \newpage
        \pagenumbering{arabic}
    %\else
    %    \subsection{Author}
    %        #3
    %    \subsection{Brief}
    %        #2
    \fi
}

\newcommand{\tranimg}[2][scale=1]{%
    \ifcurrfiledir{}
        {\includegraphics[#1]{#2}}
        {\includegraphics[#1]{\currfiledir/img/#2}}
}

\newcommand{\traninclude}[1]{%
    \ifcurrfiledir{}
        {\include{#1}}
        {\include{\currfiledir/#1}}
}

\newcommand{\traninput}[1]{%
    \ifcurrfiledir{}
        {\input{#1}}
        {\input{\currfiledir/#1}}
}

\DeclareUrlCommand\UScore{\urlstyle{tt}}

\newcommand{\tranrefpl}[1]{%
    \@ifundefined{r@s:#1}
        {\UScore{#1}}
        {\nameref{s:#1}}
}

\newcommand{\tranref}[1]{%
    \@ifundefined{r@#1}
        {\UScore{#1}}
        {\nameref{#1}}
}

\newcommand{\transubfile}[1]{%
    \IfFileExists{#1}
        {\subfile{#1}}
        {}
}

%\newcommand{\configflags}{%
%    \subsection{Configuration Flags}
%    The following flags can be used to control the output of the plugin:
%}
%
%\newcommand{\flowoutput}[1]{%
%    \subsection{Flow File Output}
%    The {\bf #1} plugin outputs the following columns:
%}
%
%\newcommand{\packetmode}[1]{%
%    \subsection{Packet File Output}
%    In packet mode ({\tt --s} option), the {\bf #1} plugin outputs the following columns:
%}

\endinput
