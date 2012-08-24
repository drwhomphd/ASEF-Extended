# Android Security Evaluation Framework Extended #

Original ASEF release by Parth Patel <https://code.google.com/p/asef/>

Modifications by Nathaniel "DrWhom" Husted <nhusted@gmail.com>

## Prequisites ##
* Ubuntu or Mac OSX
* Google's Android SDK Tools
* Google's Android SDK Platform-tools
* Any Android System Images (for use with the emulator) the user finds useful.
* Perl (5 revision 12 or higher)
* Perl Modules: 
  * Getopt::Std;
  * URI::Find;
  * URI::Encode
* Git
* Curl

Ubuntu prior to 12.04 does not have a URI::Encode package available. Mac Ports also does not have packages available. In both cases CPAN can be used to download the URI/Find.pm and URI/Encode.pm packages.

## Installation ##

1. Clone the ASEF Extended repository from Github
2. Add the Google Android SDK 'tools' and 'platform-tools' directories to your PATH environmental variables.
  * In MAC OSX you will edit ~/.profile
  * In Linux you can edit ~/.bash\_profile or ~/.bash\_rc
  * A guide on the PATH environmental variable: http://www.troubleshooters.com/linux/prepostpath.htm
2. Modify the configurator.txt file for your preferred settings
3. If using SPADE, a custom built AVD file is needed. Rough instructions can be found at:  http://cgi.cs.indiana.edu/~nhusted/dokuwiki/doku.php?id=development:customavd
4. Execute apkeval.pl

## Details ##

apkeval.pl is the core program of this framework

    $ ./apkeval.pl

     " Welcome to ApkEval ! "

     -h  Help
     -a "path of an APK file you want to scan"
     -p "path of a directory of APK files you want to scan"
     -d "scan an Android Device you have attached with the machine running ASEF"
     -s "select the scan device to be the device id listed in configurator file"
     -e "extensive scan mode where it will collect kernel logs, memory dump, running process at each stage"
     -n "use a pre-existing snapshot of an emulated virtual devices (disables SDCard creation on startup)"
     -r "collect data with the SPADE providence system. SPADE must be preinstalled into a snapshot enabled emulated virtual device. REQUIRES -n"

Please download Android SDK, install preferable API level and create an Android Virtual Device and provide it's name to Configurator.txt in order to run tests on it. If you are wanting to analyze the malware using the advanced features of SPADE, you will need to download a mini-Audit enabled AVD from http://cgi.cs.indiana.edu/~nhusted/dokuwiki/doku.php?id=projects:androids and follow the instructions on that web site.

If you want to take a route of running a tests on a physical android device, you may skip the above step of creating a virtual device and simply use this Framework as standalone.

Please create a Google Safe Browsing Key and provide it to Configurator to run a Safe Browsing Check on accessed servers.

Provide all the required details in Configurator.txt file in order for apkeval.pl to run all tests.

Run this framework, logged in as a user which has enough previlages to run tcpdump and all kill processes launched during tests as a session cleanup.

While selecting -d mode to test your android device, please enable 'USB debugging mode' before connecting.
