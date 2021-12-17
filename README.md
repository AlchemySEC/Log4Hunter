# Log4Hunter
This project is used to maintain the powershell based Log4Hunter script, developed to identify vulnerable JAR libraries within a Windows environment.

Log4Hunter can simply be launched from the command line and performs the following actions.

Note: The 'JARVERSION' refers to the version of the inspected .JAR library and unless the inspected file is a native log4j file this does not corrospond to the log4j version embedded within the library.


  
    1. Identify all local hard disks.
    2. searches all disks for *.jar files 
    3. examines each file for the presence of the vulnerable 'JndiLookup.Class'
    4. examines the identified library for the presence of the patched code in the 'JmsAppender$Builder.class'.
    5. Outputs the result to disk (Defaults to C:\) for review and clearly marks the jar files that are vulnerable to Log4Shell/Log4Jam.
    
#Configuration
There is little configuration based into the  script, however you can control the log/working directory by modifying the variable '$logFolder' to a directory of your choosing. 
   
#Limitations

While this script will find embedded versions of log4j, it will not find .JAR files within .JAR files (yet).
A native log4j .jar file will be identified vulnerable based on its version, however an embedded library is identified by identifying if the mitigation patch has been applied to the appropriate class. Because versioning is not available, embedded versinos of log4 prior to 2.16 will always be marked as vulnerable.


#References

https://github.com/sp4ir/incidentresponse/blob/main/Get-Log4shellVuln.ps1

https://github.com/1lann/log4shelldetect/blob/master/main.go
