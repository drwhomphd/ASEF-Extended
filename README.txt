Please place this framework inside Android SDK only if you are going to use virtual device for running test, if not it will work from any path on a machine.
(e.g. path to place ASEF : /Users/someuser/Downloads/android-sdk-macosx/ASEF )

adb, aapt and emulator are available from Google's Android SDK and packaged along with this framework as standalone utilities.

This Framework is currently supported on OS X and Ubuntu.

apkeval.pl is the core program of this framework

$ ./apkeval.pl

 " Welcome to ApkEval ! "

 -h  Help
 -a "path of an APK file you want to scan"
 -p "path of a directory of APK files you want to scan"
 -d "scan an Android Device you have attached with the machine running ASEF"
 -s "select the scan device to be the device id listed in configurator file"
 -e "extensive scan mode where it will collect kernel logs, memory dump, running process at each stage"

It requires perl to be installed on the machine if it is not installed already. (preferably perl 5 version 12 or higher)
Along with that, it also uses following modules which may need to be installed if not present.
Getopt::Std;
URI::Find;
URI::Encode


Please download Android SDK, install preferable API level and create an Android Virtual Device and provide it's name to Configurator.txt in order to run tests on it.

If you want to take a route of running a tests on a physical android device, you may skip the above step of creating a virtual device and simply use this Framework as standalone.

Please create a Google Safe Browsing Key and provide it to Configurator to run a Safe Browsing Check on accessed servers.

Provide all the required details in Configurator.txt file in order for apkeval.pl to run all tests.

Run this framework, logged in as a user which has enough previlages to run tcpdump and all kill processes launched during tests as a session cleanup.

While selecting -d mode to test your android device, please enable 'USB debugging mode' before connecting.





 
