#!/usr/bin/perl 
#phoenix

# Copyright 2013 Parth Patel (Original Author)
# Copyright 2013 Nathaniel "DrWhom" Husted (Extended)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use strict;
use Getopt::Std;
use URI::Find;
use URI::Encode;


getopts('ha:p:dsenr');

our($opt_h, $opt_a, $opt_p, $opt_d, $opt_s, $opt_e, $opt_n, $opt_r);

our $SCANDEVICE = ""; # default device (virtual/phone) on which all the scans will run
our $SCANDRUN = ""; # found scan device to be attached
our $dAVD = ""; # default 'android virtual device' on which the scans will run if no scandevice attached
our $GAPI = ""; # Google Safe Browsing API to evaluate URLs being accessed by each app
our $ADBPORT = ""; # port number on which emulator is running (e.g 5554) 
our @ARRDEVICES = ""; # output of 'adb devices' command to scan the attached devices and/or detect if the launched emulator came to life
our @ADBSER = ""; # output of 'adb start-server' command to check if adb server started successfully
our $DEVICEID = ""; # device id of an android device connected to the machine, used to point adb commands to extract the .apk files from the device
our @ARRPKGLIST = ""; # list of installed packages on an android device
our @ALLFILES = ""; # list of all the .apk files for which we will be running a scan
our %HAPK = ""; # data structure to hold the values of .apk file name, application name, version code, version number, package name, launcher activity, timestamps of events..etc
our $SETPATHAPK = ""; # a path where the .apk files are located (can be the path given by the user or the local path in EXCTRACTED_TIMESTAMP directory where .apk files are extracted
our $PATHJOIN = ""; # a variable to add an extra / at the end of the path in case if user hasn't provided like that in the arguement
our $PID4BL = ""; # process id to launch adb logs in order to accurately track the boot process of an emulator
our $TIME4DIR = `date '+%m_%d_%y-%H:%M:%S'`; # time stamp of the moment when the scan has been launched
chomp $TIME4DIR; 
our $TESTDIR = "TEST_" . $TIME4DIR; # location of the test result directory with a time stamp of the moment when the scan was launched
our $PWD = `pwd`; # current path
chomp $PWD;
our $EXTRCTAPK = $PWD . "/EXTRACTEDAPKS_$TIME4DIR"; # name of the local directory where all the .apk files will be extracted from the android device
our $HOSTIP = ""; # ip address of the host machine
our $IFACE = ""; # interface on which you want to sniff the network traffic
our $TIMEADBSTART = ""; # time stamp of the event when you launch the adb log right at the start of test cycle
our $TIMEADBSTOP = ""; # time stamp of the event when you end the adb log right at the end of test cycle
our $TXTADBPKT = ""; # location of the adb log file and network traffic file
our @ARRLENGTH = ""; # array for holding packet lengths of network traffic capture while test cycle
our $APK = ""; # apk file being worked on
our $RGC = ""; # no of gestures to send to an app. more no gestures may trigger more behaviors but it can cause app to crash and even emulator. default no of gestures is 55.
our $Tm = ""; # merination time of an app. in other words, the amount of time delay between stages of test cycle. larger the Tm time, longer the app will spend in test cycle and more data will be collectedcw.it increases the idle time in the test cycle.



# Help function will be called if no arguments were given or if -h was provided as an arguemnt

sub help()
{
  print <<EOF;

 " Welcome to ApkEval ! "

 -h  Help
 -a "path of an APK file you want to scan"
 -p "path of a directory of APK files you want to scan"
 -d "scan an Android Device you have attached with the machine running ASEF"
 -s "select the scan device to be the device id listed in configurator file"
 -e "extensive scan mode where it will collect kernel logs, memory dump, running process at each stage"
 -n "use a pre-existing snapshot of an emulated virtual devices (disables SDCard creation on startup)"
 -r "collect data with the SPADE providence system. SPADE must be preinstalled into a snapshot enabled emulated virtual device. REQUIRES -n"

EOF
  exit;
}

if ($opt_h) { &help; }

# Must enable snapshots to enable SPADE because, currently, SPADE is not
# built-in to Android and must be installed in to a custom AVD with
# snapshots enabled (so that state can be saved between boots).
if ($opt_r && !$opt_n) { &help; } 

if ((!$opt_h) && (!$opt_a) && (!$opt_p) && (!$opt_d) && (!$opt_s) && (!$opt_e) && (!$opt_n)) { &help; }


# A S E F - Phase 1 : Passive
# Will try to configure and collect data required to run tests in this phase


# Initialization mode - Configurator module 
# Configurator function will take all the necessary parameters to configure this tool and will store is in configurator.txt file. once this file is properly configured, it won't prompt for these parameters.

sub configurator()
{

  print "\n\n\n\n ASEF ==> Running a configurator for ASEF ............. \n";

  open(FCONFIG, "configurator.txt") or die "Can't open configurator.txt file \n";

  while(<FCONFIG>)
  { 
    if($_ =~ m/(^Default AVD \=\s*)(.*)/) 
    {
      our $dAVD = $2; 

      chomp $dAVD; 

      print "\n Using default AVD = $dAVD \n"; 
    }

    if($_ =~ m/(^Google Safe Browsing API \=\s*)(.*)/) 
    {
      our $GAPI = $2; 

      chomp $GAPI; 

      print "\n Using Google Safe Browsing API key = $GAPI \n"; 
    }

    if($_ =~ m/(^Host IP \=\s*)(.*)/)
    {
      our $HOSTIP = $2;

      chomp $HOSTIP;
    }

    if($_ =~ m/(^interface \=\s*)(.*)/)
    {
      our $IFACE = $2;

      chomp $IFACE;

      print "\n Using packet capturing tool 'tcpdump' on $HOSTIP at interface $IFACE \n";
    }

    if($_ =~ m/(^AD \=\s*)(.*)/)
    {
      if ($opt_s) 
      {
        our $SCANDEVICE = $2;

        chomp $SCANDEVICE;

        print "\n Found an android scan device listed in the configurator file :- $SCANDEVICE \n";
      }
    } 

    if($_ =~ m/(^RGC \=\s*)(.*)/)
    {
      our $RGC = $2;

      chomp $RGC;

      if ($RGC == "") { $RGC = 55; } # if no of gestures are not give, it's default value will be taken which is 55

      print "\n Will send $RGC number of gestures to each app inside the activity mode of a test cycle \n";
    }

    if($_ =~ m/(^Tm \=\s*)(.*)/)
    {
      our $Tm = $2;

      chomp $Tm;

      if ($Tm == "") { $Tm = 5; } # if test cycle time duration is not tuned through Tm, it's default value will be taken which is 60 seconds 

      print "\n Tm is set to be $Tm seconds \n";
    }

  }

}

&configurator;


# Initialization mode : adb refresh 
# adb refresh is a recursive function which will start adb server and assure it have lauched successfully

sub adbrefresh()

{

#  print "\n Killing adb server.......... \n";
  `adb kill-server`;

#  print "\n Starting adb server.......... \n";
  @ADBSER = `adb start-server`;

  if (!@ADBSER) { &adbrefresh(); } # this is a recursive function because at times adb server fails to start and in that case this will take care of it until it successfully starts...

#  print @ADBSER;

}

# Initialization mode : Device Detect 
# devicescanner function will be called if -d option was provided as an argument. It will scan the attached device and report it to $DEVICEID. In case if no device was found, it will exit the program and will ask user to attach a device to the machine. Also the device should have the 'USB Debugging Mode' enabled before connecting to the machine running A S E F.

sub devicescanner()

{

  print "\n Starting the adb server........ \n\n";

  &adbrefresh(); 

#  print @ADBSER;

  foreach (@ADBSER) 
  {
    if ($_ =~ m/(\* daemon not running. starting it now on port )(\d+)(\s\*)/) 
    { $ADBPORT = $2; } 

    if ($_ =~ m/daemon started successfully/)
    { print "\n adb server started successfully on port :- $ADBPORT\n"; }
  }

  if($ADBPORT == "") { print "\nadb server failed to start....... please run the tool again !\n"; exit; }


  print "\n ASEF ==> Device Scanner is scanning for attached Android Device........... \n";

  @ARRDEVICES = `adb devices`;

#  print @ARRDEVICES;

  my $TMPCK = 0;

  foreach(@ARRDEVICES)
  {

    if ($_ =~ m/List of devices attached/)
    {  
      $TMPCK++;
    }

    if ($TMPCK == 1 )
    {
      if ($_ !~ m/device/ && $_ !~ m/emulator/)  
      {
        print "\n No devices found...\n Please attach an android device and run this tool again........ please enable \"USB debugging mode\" in Android Device to be detected \n";
        exit;
      }
    }

    if ($_ =~ m/(.*?)(\s*device)/ )
    { 
      if ($1 !~ m/List/ && $1 !~ m/emulator/ && $1 !~ m/$SCANDEVICE/) 
      { 
        print "\n Found a connected device :- $1 \n\n\n"; 
        $DEVICEID = $1; 
        $TMPCK = 0;
      }

    }
  }

}


# Normalization mode : Extractor module
# extractor will extract all the .apk files from the attached android device and will store it on a local directory named EXTRACTOR_TIMESTAMP

sub extractor()

{

  print "\n ASEF ==> Extractor is running on..... Device ID :- $DEVICEID ...........\n\n"; 

  print "\n Extracting all the files to the local directory :- $EXTRCTAPK \n";

  `mkdir $EXTRCTAPK`;

  @ARRPKGLIST = `adb -s $DEVICEID shell pm list packages`;

#  print @ARRPKGLIST; 

  my $APKPATH = "";
  my $APKCNT = 0;
  my $BKAPKPATH = "";

  foreach (@ARRPKGLIST)
  {

    if ($APKCNT == 5) { last; } # if you have 50+ applications installed, you can just use this counter to only do it for 5 if you are only interested in it'd demo...

    $_ =~ s/package\://g;

    #print $_;

    $APKPATH = `adb -s $DEVICEID shell pm path $_`;

    if ($APKPATH !~ m/package\:\/system/)

    { 
      chomp ($APKPATH);

      $BKAPKPATH = $APKPATH;

      $BKAPKPATH =~ s/package\://g; 

      $APKCNT++;

      $APKPATH =~ s/package\:\/.*\///g;

      print "\n Found apk file $APKCNT :- $APKPATH \n";

      print " ......Extracting apk file to the local directory :- ";

      `adb -s $DEVICEID pull $BKAPKPATH $EXTRCTAPK`;
    }

  } 

  print "\n Total number of Applications extracted :- $APKCNT \n\n";

}


if($opt_d)
{
  &devicescanner;

  &extractor;

  if($EXTRCTAPK !~ m/.*\/$/)
  {
    $PATHJOIN = "/";
  }

  $SETPATHAPK = $EXTRCTAPK . $PATHJOIN ;

  opendir (EDIR, $EXTRCTAPK);

  my @ALLTMPFILES = "";

  @ALLTMPFILES = readdir(EDIR);

  my $COUNT = 0;

  foreach (@ALLTMPFILES)
  {
    if ($_ =~ m/.*\.apk$/)
    {
      $ALLFILES[$COUNT] = $_ ;

      $COUNT++;

      print "\n";

      print $COUNT.") ";

      print $_;

    }
  }

  closedir EDIR;

# print @ALLFILES;

}

if($opt_a)
{

  chomp $opt_a;

# print $opt_a;

  if($opt_a =~ m/(\/.*\/)(.*\.apk)/)
  {
    $SETPATHAPK = $1;

    @ALLFILES = $2;
  }

  if($opt_a =~ m/.*\.apk/ && $opt_a !~ m/\//g)
  {
    $SETPATHAPK = $PWD;

    @ALLFILES = $opt_a;
  }

  if($opt_a !~ m/.*\.apk$/)
  {
    print "\n Please only give .apk files to scan...... \n";

    exit;
  }

  print "\n Application to scan :- @ALLFILES \n\n";

}


if($opt_p)
{

  my @ALLTMPFILES = "";

  chomp $opt_p;

  if($opt_p !~ m/.*\/$/)
  {
    $PATHJOIN = "/";
  }

  $SETPATHAPK = $opt_p . $PATHJOIN ;

  print "\n\n Location of the Directory :- $opt_p \n\n";

  opendir (PDIR, $opt_p);

  @ALLTMPFILES = readdir(PDIR);

  my $COUNT = 0;

  foreach (@ALLTMPFILES)
  {
    if ($_ =~ m/.*\.apk$/)
    { 
      $ALLFILES[$COUNT] = $_ ;

      $COUNT++;

      print "\n";

      print $COUNT.") ";

      print $_;

    }
  }

# print @ALLFILES;

  print "\n\n Total number of apk files found = $COUNT\n\n";

}     


# Organization mode : converter module
# converter module converts the matadata associated with .apk files and populates the hash table where they are better organized. It increases the accessebility of the information associated with applications.

sub converter()
{

  print "\n Inside converter module \n\n";

#  print @ALLFILES;

  my $apk = "";
  my $FULLPATH = "";
  my $PKGNM = "";
  my $LAUNCHACT = "";
  my @AAPTDUMP = "";
  my $DUMP = "";
  my $VERCODE = "";
  my $VERNAME = "";
  my $APPLABLE = "";

  foreach $apk (@ALLFILES)
  {

    print "\n Print local path for $apk :- $SETPATHAPK \n"; 

    $FULLPATH = $SETPATHAPK . "\"" . $apk . "\"";

    @AAPTDUMP = `aapt dump badging $FULLPATH`;

    foreach $DUMP (@AAPTDUMP)
    {
      if($DUMP =~ m/(^package\: name\=)('.*?')( versionCode\=)(.*?)( versionName\=)(.*)/)
      {
        $PKGNM = $2;
        $VERCODE = $4;
        $VERNAME = $6;
      } 

      if($DUMP =~ m/(^launchable\-activity\: name\=)('.*?')(\s*.*)/)
      {
        $LAUNCHACT = $2;
      }

      if($DUMP =~ m/(^application\-label\:)('.*')/)
      {
        $APPLABLE = $2;
      }

    }

    %HAPK->{$apk} = ( { pkgnm => $PKGNM , launchact => $LAUNCHACT , vercode => $VERCODE , vername => $VERNAME , applable => $APPLABLE , adbstart => "" , adbstop => ""}, );

  }


  foreach $apk ( keys %HAPK )
  {

    if($apk !~ m/.*\.apk/)
    { next ;}

    sleep(1);

    print "\n\n application name :- $apk";

    print "\n packagename :- ";
    print $HAPK{$apk} -> {pkgnm} ;

    print "\n launcher activity :- ";
    print $HAPK{$apk} -> {launchact} ;

    print "\n version code :- ";
    print $HAPK{$apk} -> {vercode} ;

    print "\n version name :- ";
    print $HAPK{$apk} -> {vername} ;

    print "\n app lable :- ";
    print $HAPK{$apk} -> {applable} ;

  }

}

if(@ALLFILES)
{
  print "\n Calling a converter module :- \n";

  &converter();

}

else
{
  print "\n No APK files to work on \n";

  exit;

}


# Organizer mode : Test Hierarchy module 
# organizer will create a TEST DIRECTORY with a TIME STAMP in it's name. It will also create the sub-directory hierarchy for each application in order to store the results associated with each application

sub organizer()
{

  sleep(1);

  print "\nInside Organizer \n";

#  print @_;

  print "\n\n ---- Creating the master TEST RESULT DIRECTORY :- $TESTDIR ----\n\n";

  `mkdir $TESTDIR`;

  my $TMPAPKFILE = "";
  my $APKTESTDIR = "";
  my $i = 0;

  foreach (@ALLFILES)
  {

    $i++;

    $TMPAPKFILE = "\"" . $_ . "\"";

    my $APKTESTDIR = $TESTDIR ."/" . $TMPAPKFILE ;

    sleep(1); 
    print "\n$i) $APKTESTDIR";

    `mkdir $APKTESTDIR`;


  }



}

print "\n\n Calling Organizer module to organize test results \n\n";

&organizer();

print "\n Done creating the Test result hierarchy ....... \n\n";



# A S E F : Active Phase
# Launch mode : virtual device launcher module
# avdlauncher will be called to check if the default device (virtual/phone) is running. If it's found running, it will proceed with the test cycle. If it's not found running then it will be launched.

my $CMD4AVDLAUNCH = "";
my $PID4AVDLAUNCH = "";

sub avdlauncher()
{

  @ARRDEVICES = `adb devices`;

  print @ARRDEVICES;

  foreach (@ARRDEVICES)
  {
    if($_ =~ m/(emulator.*?)(\s*device)/)
    {
      print "\n\n Found default AVD to be running......... \n\n";

      $SCANDEVICE = $1;

      print $SCANDEVICE;
    }
  }

  if(!$SCANDEVICE)
  {

    print "\n\n Going to launch default AVD :- $dAVD \n\n";

    # We're starting without a pre-created snapshot so set the partition size
    if(!$opt_n) {
      $CMD4AVDLAUNCH = "emulator -avd $dAVD -partition-size 1024";
      print "\n Starting the emulator for AVD $dAVD with 1GB Internal Storage & 1 GB SD Card :-  \n\n";
    }
    else {
      $CMD4AVDLAUNCH = "emulator -avd $dAVD -no-snapshot-save";
      print "\n Starting the emulator for AVD $dAVD with pre-created, default, snapshot:-  \n\n";
    }



    my $PID4AVDLAUNCH = fork();
    if (defined($PID4AVDLAUNCH) && $PID4AVDLAUNCH==0)
    {
      # running AVD in background process
      exec("$CMD4AVDLAUNCH &");
    }


  }

  my $FLAG = 0;
  my $FOUNDEMU = "";
  my $PSEMU = "";

  while(!$SCANDEVICE)
  {

    @ARRDEVICES = `adb devices`;

    my $FOUNDEMU = `adb devices |grep emulator`;

    chomp $FOUNDEMU;

    my $PSEMU = `ps -a |grep emulator |grep -v grep |awk '{print \$1}'`;

    foreach (@ARRDEVICES)
    {

      if($_ =~ m/emulator.*offline/ && $FLAG == 0)
      {
        print "\n Default AVD $dAVD has been lauched in background... but it is still in 'offline' mode... waiting for $dAVD to come to 'online' state.........";
        $FLAG = 1;
      }

      if($_ =~ m/emulator.*offline/ && $FLAG == 1)
      {
        sleep(1);
        print ".";
      }

      if($_ =~ m/(emulator.*?)(\s*device)/)
      {
        print "\n\n $dAVD came to life.... and now it's in online mode ..... \n\n";

        $SCANDEVICE = $1;

        $PID4BL = `./execadblogcat.sh $SCANDEVICE bootlog.txt`;

        print "\n Waiting for $dAVD to complete the boot process....";
      }

      if($PSEMU && !$FOUNDEMU)
      {
        #print "\n ADB server has failed to recognize emulator device...... \n";

        #print "\n Going to run adbrefresh ....... \n";

        &adbrefresh();
      }

    }

  }  

  if($PID4BL)
  {
    if(!$opt_n) {
      while(!`cat bootlog.txt |grep "SurfaceFlinger.*Boot is finished"`)
      { 
        sleep(1); 
        print "."; 
      }
    }
    else {
      # When the emulator starts up an image with a snapshot, there is no
      # guarantee that the bootlog will contain any messages about the
      # Boot being finished. In this case we just look for the first
      # actual logcat entry because at this point we know the snapshot 
      # is up and running.
      while(!`cat bootlog.txt |grep " [A-Z]/[A-Za-z]*\(.*\): "`)
      { 
        sleep(1);
        print ".";
      }
    }

    print "\n\n Boot Completed !!";

    chomp $PID4BL;

    `./killproc.sh $PID4BL`;

#   print "\n Invisible swipe coming in 15 seconds............";

    my $CNT = 0;

    while($CNT <= 15) 
    { 
      $CNT++; 
      print "."; 
      sleep(1); 
    }

    `adb -s $SCANDEVICE shell input keyevent 82`;

    print "\n AVD unlocked !\n";

  }

  if($opt_r) {
    # Startup the SPADE kernel by manually running the dalvikvm on the
    # android-spade jar file.
    print "\n Starting SPADE. \n";

    `adb -s $SCANDEVICE shell "cd /sdcard/spade/android-build/bin && dalvikvm -cp 'android-spade.jar:../../android-lib/h2-dex.jar' spade.core.Kernel &"`;
  }


}


# call virtual device launcher module only if the -s option is not selected. if user wants to run all the tests on physical android device, -s can be selected and virtual device boot process will be bypassed....

if (!$opt_s)
{

  print "\n\n Calling AVD LAUNCHER module ...... \n\n";

  &avdlauncher();
}

if ($opt_s)
{
  @ARRDEVICES = `adb devices`;

  foreach(@ARRDEVICES)
  {
    if($_ =~ m/$SCANDEVICE\s*device/)
    {
      print "\n Found the scanning devices $SCANDEVICE to be connected ..... \n";

      $SCANDRUN = "RUNNING";
    }
  }

  if (!$SCANDRUN)
  {
    print "\n scanning device not found / couldn't detect ... going to exit now... please reconnect the scanning device and start the tool again... \n";

    exit;
  }

}


# Test Cycle : test cycle module

sub avdtestcycle()
{

  print "\n Inside AVD test cycle module ..... \n";

  my $APKFULLPATH = "";
  my $APKRESULTPATH = "";
  my $ADBLOG4APK = "";
  my $TCPDUMP4APK = "";
  my $PID4ADBLOG = "";
  my $PID4TCPDUMP = "";
  my $LAUNCHAPK = "";
  my $PACKAGENAME = "";
  my @PSADB = "";
  my @PSTCPDUMP = "";
  my $PS = "";


# following block is commented out and only used if processes are not cleaned proper after each test cycle. this may kill all relevent processes before beginning.

#   @PSADB = `ps -a |grep adb.*logcat.*time |awk '{print $1}'`;
#   foreach $PS (@PSADB)
#   {
#    chomp $PS;
#    `./killproc.sh $PS`;
#   }
#   `killall -v tcpdump`;

  my $TESTROUND = 0;

  foreach (@ALLFILES)
  {

# Use this $TESTROUND if you want to just see this tool as a demo purpose only and you can restrict it to run it only for few test cycles (e.g. 4 apps in here)
    $TESTROUND++;
    if ($TESTROUND == 4) { last; }


    $APKFULLPATH = $SETPATHAPK . "\"" . $_ . "\""; 

    $APKRESULTPATH = $PWD . "\/" . $TESTDIR . "\/" .  "\"" . $_ . "\"";

    print "\n Going to flush adb messages from the device $SCANDEVICE ...... ";

    `adb -s $SCANDEVICE logcat -c`; # this will flush all the adb log message history from the device. not performing this step can cause False Postives and overlaps on various app results. If the message history is suppose to be preserved, in that case this can be replaced by another technique where it will collect all the adb log data without flushing it and later chop it based on time stamps.

    sleep(1);

    $ADBLOG4APK = $APKRESULTPATH . "\/" . "adb_log.txt";

    print "\n Starting to capture all logevents for the application $_ at location :- $ADBLOG4APK \n";

    $TIMEADBSTART  = `date '+%m-%d %H:%M:%S'`;

    $HAPK{$_} -> {adbstart} = $TIMEADBSTART;

    print "\n adb logcat started at this time stamp $TIMEADBSTART \n";

    $PID4ADBLOG = `./execadblogcat.sh $SCANDEVICE $ADBLOG4APK`;

    sleep(1);

    $TCPDUMP4APK = $APKRESULTPATH . "\/" . "network_traffic.txt";

    print "\n Starting to capture all network traffic for the application $_ at location :- $TCPDUMP4APK \n";

    $PID4TCPDUMP = `./pktcap.sh $IFACE $HOSTIP $TCPDUMP4APK`;

    sleep(1);

    print "\n\n Getting ready to install Application $_ from the location ..........$APKFULLPATH";

    print "\n\n Installing $_ now :- \n";

    system("adb -s $SCANDEVICE install $APKFULLPATH");

    sleep($Tm);

    $LAUNCHAPK = $HAPK{$_} -> {pkgnm}  . "/" . $HAPK{$_} -> {launchact} ;  

    print " \n Going to launch $_ using the launcher activity $LAUNCHAPK \n";

    system("adb -s $SCANDEVICE shell am start -n $LAUNCHAPK");

    sleep($Tm);

    $PACKAGENAME = $HAPK{$_} -> {pkgnm};

    print "\n Sending random gestures ... \n";

    system("adb -s $SCANDEVICE shell monkey -p $PACKAGENAME $RGC");

    sleep($Tm);

    print "\n Done testing... uninstalling now .... \n";

    system("adb -s $SCANDEVICE uninstall $PACKAGENAME");

    sleep(1);

    `./killproc.sh $PID4ADBLOG`;

    $TIMEADBSTOP = `date '+%m-%d %H:%M:%S'`;

    $HAPK{$_} -> {adbstop} = $TIMEADBSTOP;

    print "\n adb logcat stopped at this time stamp $TIMEADBSTOP \n";

    `./killproc.sh $PID4TCPDUMP`; #make sure logged in user on a machine has right permission to kill processes, orelse it will be an overlap  

    `killall -v tcpdump` ; #user can also run 'cat sudo_password |killall -v tcpdump' if the logged in user doesn't have enough previlages, however this technique inside the script is not recommended for many reasons

    if($opt_r) {
      # Shutdown SPADE
      
      print "\n Shutting down SPADE \n";
      `adb -s $SCANDEVICE shell "cd /sdcard/spade/android-build/bin && dalvikvm -cp 'android-spade.jar:../../android-lib/h2-dex.jar' spade.client.AndroidShutdown"`;

      print "\n Saving SPADE grpah data to $APKRESULTPATH/graph.dot \n";
      # Pull dot file off from AVD with name the same as the current malware.
      `adb -s $SCANDEVICE pull /sdcard/spade/output/graph.dot $APKRESULTPATH/graph.dot`;

      # Delete dot file on the device
      `adb -s $SCANDEVICE shell rm /sdcard/spade/output/graph.dot`;
    }
  }

}

&avdtestcycle();



# A S E F : Interpret Phase
#=================================== PARSERS ====================================================


foreach (@ALLFILES)
{
  $APK = $_;

#   my @ARRLENGTH = "";
#   $TESTDIR = "TEST_05_08_12-17:11:32"; # there can be an extra option to cover this case where you have already ran tests using A S E F and collected the data but just want to parse it again, so by poining it to the right test directory, parser will parse those files instead ....

  $TXTADBPKT = $PWD . "\/" . $TESTDIR . "\/" . "\"" . $_ . "\"" . "\/" . "\*\.txt";

  print "\n inside parser module ...... \n";

  print "\n Time when adb log started for the app $_ :- ";

  print $HAPK{$_} -> {adbstart};

  print "\n Time when adb log ended for the app $_ :- ";

  print $HAPK{$_} -> {adbstop};


# Google's Safe Browsing module for accessed URLs ===============================

  sub urlaccessed()
  {
    my $URIFIND = "";
    my $ACCURL = "";
    my @ALLURLS = "";
    my $ENCODEDURL = "";
    my $URI = URI::Encode->new();
    my $MALWARE = "";

    $URIFIND = `which urifind`;

    chomp $URIFIND;

    if(!$URIFIND)
    {
      "\n Can't parse accessed URLs from log files as URI::Find module is not installed in perl ... skipping this module .... please install it and run the tool again ...\n";

      return;
    }

#   @ALLURLS = `$URIFIND -n $TXTADBPKT`;

    sub gsb()
    {
      chomp @_;

      foreach $ACCURL (@_)
      {
        chomp $ACCURL;

        if(!$ACCURL) { next ; }

        if($ACCURL =~ m/file\:\/\//)
        { next; }

#     print "\n $_ :- Accessed URL :- $ACCURL \n";

        my $ENCODEDURL = $URI->encode($ACCURL,1);

        chomp $ENCODEDURL;

#     print "\n $_ :- utf8 encoded URL :- $ENCODEDURL";

#     print "\n Running it through Google's Safe Browsing API ........ ";

        $MALWARE = `curl -s "https://sb-ssl.google.com/safebrowsing/api/lookup?client=demo-app&apikey=$GAPI&appver=1.5.2&pver=3.0&url=$ENCODEDURL"`;

        if($MALWARE)
        {
          print "\n ! $_ accessed --> \" $ACCURL \" and it is - $MALWARE\n";
        }         

        if(!$MALWARE)
        {
          print "\n $_ accessed --> \" $ACCURL \" \n"; 
        }        

      }
    }


    @ALLURLS = `$URIFIND -n $TXTADBPKT`;

#   print @ALLURLS;

    &gsb(@ALLURLS);

    @ALLURLS = `./destipurl.sh $TXTADBPKT`;

    chomp @ALLURLS;

#   print @ALLURLS;

    &gsb(@ALLURLS);    


  }

  &urlaccessed();

  sub datausage()
  {

    my $TEMP0 = 0;
    my $LEN = "";

#   my $TXTADBPKT = $PWD . "\/" . $TESTDIR . "\/" . "\"" . $_ . "\"" . "\/" . "\*\.txt";

    @ARRLENGTH = `./datausage.sh $TXTADBPKT`;

#   print @ARRLENGTH;  

    foreach $LEN (@ARRLENGTH)
    {
      $TEMP0 = $TEMP0 + $LEN;
    }

    print "\n\n Total number of data exchanged during the test cycle by an app $_ is -------------> $TEMP0 bytes \n\n";

  }


  &datausage();

  sub vulns()
  {
    my %HVULN = ""; 
    my $PKG = "";
    my $OS = "";
    my $HVV = "";
    my $HPV = "";
    my $LVV = "";
    my $INFO = "";
    my $SEV = "";
    my $CVE = "";
    my $NOI = "";
    my $ENTRY = "";

    my $TXTSIG = $PWD . "\/" . "vuln2.txt";

    open(FSIG, $TXTSIG) or die "\n Can't open signature.txt file \n\n";

    while(<FSIG>)
    {

      if($_ =~ m/(.*?)( pkg\:)('.*?')( os\:)('.*?')( hvv\:)('.*?')( hpv\:)('.*?')( lvv\:)('.*?')( info\:)('.*?')( sev\:)('.*?')( cve\:)('.*?')( noi\:)('.*?')/)
      {

        $ENTRY = $1;
        $PKG = $3;
        $OS = $5;
        $HVV = $7;
        $HPV = $9;
        $LVV = $11;
        $INFO = $13;
        $SEV = $15;
        $CVE = $17;
        $NOI = $19;

        %HVULN->{$ENTRY} = ( { pkg => $PKG , os => $OS , hvv => $HVV , hpv => $HPV , lvv => $LVV , info => $INFO , sev => $SEV , cve => $CVE , noi => $NOI }, );
      }

    }

    my $ent = "";
    my $VULNERABLE = "";
    my $HPV = "";
    my $HVV = "";
    my $LVV = "";
    my $APKVER = "";
    my @ARRHPV = "";
    my @ARRHVV = "";
    my @ARRLVV = "";
    my @ARRAPKVER = "";
    my $i = 0;
    my $SIZE = "";

    foreach $ent ( keys %HVULN )
    {

      $VULNERABLE = "";

      if ($HVULN{$ent} -> {pkg} eq $HAPK{$APK} -> {pkgnm})
      {

#    print "\n\n ############## Found a MATCH #################### $HVULN{$ent}{pkg} <--matched--> $HAPK{$APK}{pkgnm}  \n\n";
#    print $HVULN{$ent} -> {hvv};
#    print $HAPK{$APK} -> {vername};

        if ($HAPK{$APK} -> {vername})
        {

          if ($HAPK{$APK} -> {vername} eq $HVULN{$ent} -> {hvv} || $HAPK{$APK} -> {vername} eq $HVULN{$ent} -> {lvv})
          {
            #print "it's vulnerable";
            $VULNERABLE = "YES"; print "\n Either app version $HAPK{$APK}{vername} matched to hvv $HVULN{$ent}{hvv} or lvv $HVULN{$ent}{lvv}\n\n";
          }

          my $HPV = $HVULN{$ent} -> {hpv}; 
          my $HVV = $HVULN{$ent} -> {hvv};
          my $LVV = $HVULN{$ent} -> {lvv};
          my $APKVER = $HAPK{$APK} -> {vername};

          $HPV =~ s/\'//g;
          $HVV =~ s/\'//g;
          $LVV =~ s/\'//g;
          $APKVER =~ s/\'//g;

          my @ARRHPV = split ('\.' , $HPV);
          my @ARRHVV = split ('\.' , $HVV);
          my @ARRLVV = split ('\.' , $LVV);
          my @ARRAPKVER = split ('\.' , $APKVER);

          if(@ARRHPV > @ARRAPKVER)
          {
            $SIZE = @ARRHPV;
          }

          if(@ARRHVV > @ARRAPKVER)
          {
            $SIZE = @ARRHVV;
          }

          $SIZE = @ARRAPKVER;

          for($i=0 ; $i<=$SIZE; $i++)
          {
            if(!$VULNERABLE)
            {
              if($ARRAPKVER[$i] < $ARRHVV[$i] && $ARRAPKVER[$i] > $ARRLVV[$i])
              {
                #print "it's vulnerable";
                $VULNERABLE = "YES";  print "\n app version was in between hvv and lvv :- flagged at appversion = $ARRAPKVER[$i] , hvv = $ARRHVV[$i] , lvv = $ARRLVV[$i] \n";
              }
            }
          }

          for($i=0 ; $i<=$SIZE; $i++)
          {
            if(!$VULNERABLE)
            {
              if($ARRAPKVER[$i] < $ARRHPV[$i] && $ARRAPKVER[$i] > $ARRLVV[$i])
              {
                #print "it's vulnerable";
                $VULNERABLE = "YES";  print "\n app version was in between hpv and lvv :- flagged at appversion = $ARRAPKVER[$i] , hvv = $ARRHVV[$i] , lvv = $ARRLVV[$i] \n";
              }
            }
          }

          # print @ARRHVV;

          # print @ARRAPKVER;
        }

        if($VULNERABLE)
        {
          print "\n Found $HAPK{$APK}{pkgnm} to be vulnerable for version $HAPK{$APK}{vername} and from advisory hvv = $HVULN{$ent}{hvv} , hpv = $HVULN{$ent}{hpv} , lvv = $HVULN{$ent}{lvv} , cve = $HVULN{$ent}{cve} , info = $HVULN{$ent}{info} , sev = $HVULN{$ent}{sev} , noi = $HVULN{$ent}{noi} \n";
        }
      }

#   print "\n\n application name :- $ent";
#   print "\n packagename :- ";
#   print $HVULN{$ent} -> {pkg} ;
#   print "\n launcher activity :- ";
#   print $HVULN{$ent} -> {os} ;
#   print "\n version code :- ";
#   print $HVULN{$ent} -> {hvv} ;
#   print "\n version name :- ";
#   print $HVULN{$ent} -> {hpv} ;
#   print "\n app lable :- ";
#   print $HVULN{$ent} -> {lvv} ;
#   print $HAPK{$apk} -> {pkgnm};
    }


  }

  &vulns();


}

=for

# extensive scan which collects kernel log, memory dump and running services requires very high processing power and memory usage. It is currently disabled as we haven't written any interpreter which parses that data. Once done, it will be integrated inside the test cycle but for now not present in the alpha release. However if a user wants to give it try, please use the following sample code which collects this data before install and before app launches. 

foreach (@APKFILES)
{

 my $APKFULLPATH = $ARGV[0] . "\"" . $_ . "\"";
 my $APKRESPATH = $PWD . "\/" . $APKTESTDIR[$j] . "\/" ; $j++;
 my $APKINSTLOG = $APKRESPATH . "install_log.txt";
 my $APKPKTCAP = $APKRESPATH . "tcpdump_capture.txt";
 my $APKKERNLOGBI = $APKRESPATH . "before_install_kernel_log.txt";
 my $APKKERNLOGAI = $APKRESPATH . "after_install_kernel_log.txt";
 my $APKDUMPSYSBI = $APKRESPATH . "before_install_dumpsys.txt";
 my $APKDUMPSYSAI = $APKRESPATH . "after_install_dumpsys.txt";
 my $APKPSBI = $APKRESPATH . "before_install_running_processes.txt";
 my $APKPSAI = $APKRESPATH . "after_install_running_processes.txt";
 my $APKKERNLOGBL = $APKRESPATH . "before_launch_kernel_log.txt";
 my $APKKERNLOGAL = $APKRESPATH . "after_launch_kernel_log.txt";
 my $APKDUMPSYSBL = $APKRESPATH . "before_launch_dumpsys.txt";
 my $APKDUMPSYSAL = $APKRESPATH . "after_launch_dumpsys.txt";
 my $APKPSBL = $APKRESPATH . "before_launch_running_processes.txt";
 my $APKPSAL = $APKRESPATH . "after_launch_running_processes.txt";
 my $APKKERNLOGBS = $APKRESPATH . "before_stress_kernel_log.txt";
 my $APKKERNLOGAS = $APKRESPATH . "after_stress_kernel_log.txt";
 my $APKDUMPSYSBS = $APKRESPATH . "before_stress_dumpsys.txt";
 my $APKDUMPSYSAS = $APKRESPATH . "after_stress_dumpsys.txt";
 my $APKPSBS = $APKRESPATH . "before_stress_running_processes.txt";
 my $APKPSAS = $APKRESPATH . "after_stress_running_processes.txt";

 sleep(1);
 print "\n Starting to capture all logevents for the application $_ at location :- $APKINSTLOG\n";

 my $PID4APKI = `./execadblogcat.sh $APKINSTLOG`;

 sleep(1);
 print "\n Starting to capture all network traffic for the application $_ at location :- $APKPKTCAP\n";

 my $PID4APKPC = `./pktcap.sh $APKPKTCAP`;

 sleep(1);
 print "\n\n Getting ready to install Application $_ from the location ..........$APKFULLPATH";


 my $CNT1 = 0;
 while($CNT1 <= 4) { $CNT1++; print "."; sleep(1); }


 my $PID4APKKERNLOGBI = "";
 print "\n\nSnapshot :- Taking a snapshot of kernel log before install and storing at $APKKERNLOGBI\n";
 $PID4APKKERNLOGBI = `./execdmesg.sh $APKKERNLOGBI`;
 while(`./pidexist.sh $PID4APKKERNLOGBI`) { print "."; }

 my $PID4APKDUMPSYSBL = "";
 print "\n\nSnapshot :- Taking a snapshot of dump of running services before install and storing at $APKDUMPSYSBL\n";
 $PID4APKDUMPSYSBL = `./execdumpsys.sh $APKDUMPSYSBL`;
 while(`./pidexist.sh $PID4APKDUMPSYSBL`) { print "."; }

 my $PID4APKPSBI = "";
 print "\n\nSnapshot :- Taking a snapshot of running processes before install and storing at $APKPSBI\n";
 $PID4APKPSBI = `./execps.sh $APKPSBI`;
 while(`./pidexist.sh $PID4APKPSBI`) { print "."; }


 print "\n\n Installing $_ now :- \n";

 system("adb install -s $APKFULLPATH");


 my $PID4APKKERNLOGAI = "";
 print "\n\nSnapshot :- Taking a snapshot of kernel log after install and storing at $APKKERNLOGBI\n";
 $PID4APKKERNLOGAI = `./execdmesg.sh $APKKERNLOGAI`;
 while(`./pidexist.sh $PID4APKKERNLOGAI`) { print "."; }

 my $PID4APKDUMPSYSAL = "";
 print "\n\nSnapshot :- Taking a snapshot of dump of running services after install and storing at $APKDUMPSYSAL\n";
 $PID4APKDUMPSYSAL = `./execdumpsys.sh $APKDUMPSYSAL`;
 while(`./pidexist.sh $PID4APKDUMPSYSAL`) { print "."; }

 my $PID4APKPSAI = "";
 print "\n\nSnapshot :- Taking a snapshot of running processes before install and storing at $APKPSAI\n";
 $PID4APKPSAI = `./execps.sh $APKPSAI`;
 while(`./pidexist.sh $PID4APKPSAI`) { print "."; }

=cut
