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
A native log4j .jar file will be identified vulnerable based on its version, however an embedded library is identified by identifying if the mitigation patch has been applied to the appropriate class. Because versioning is not available, embedded versions of log4 prior to 2.16 will always be marked as vulnerable.


#References

https://github.com/sp4ir/incidentresponse/blob/main/Get-Log4shellVuln.ps1

https://github.com/1lann/log4shelldetect/blob/master/main.go

#FAQ

Q: Why does this script detect old version of Log4j? Eg; 1.X.X

A: This script is developed to identify all instances of Log4j, as 1.X.X is no longer supported we recommend upgrading where possible.

Q: Why does the script show a list of all .JAR files on the system?

A: The script not only identified native log4 libraries (log4j-*.jar), but also identified embedded log4j libraries. In order to identify embedded instances we need to inspect all .jar files on the system. Eg; an application has been packaged with an embedded log4j library that contains the vulnerable class which contains the log4shell vulnerability. 

Q: Will the script work if the version of Log4j is not recorded in the .JAR manifest file?

A: Yes, the script will look to identify vulnerable log4j instances in their native form such as log4j-*.jar. However it also will search for the presence of the vulnerable class and the patched class within the jar file to confirm if the log4j instance is vulnerable or not.
