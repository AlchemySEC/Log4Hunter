# Log4Hunter
This project is used to maintain the powershell based Log4Hunter script, developed to identify vulnerable JAR libraries within a Windows environment.

Log4Hunter can simply be launched from the command line and performs the following actions.
  
    1. Identify all local hard disks.
    2. searches all disks for *.jar files 
    3. examines each file for the presence of the vulnerable 'JndiLookup.Class'
    4. examines the identified library for the presence of the patched code in the 'JmsAppender$Builder.class'.
    5. Outputs the result to disk (Defaults to C:\) for review and clearly marks the jar files that are vulnerable to Log4Shell/Log4Jam.
    
#Configuration
There is little configuration based into the  script, however you can control the log/working directory by modifying the variable '$logFolder' to a directory of your choosing. 
   
#Limitations
While this script will find embedded versions of log4j, it will not find .JAR files within .JAR files (yet).

#References

https://github.com/sp4ir/incidentresponse/blob/main/Get-Log4shellVuln.ps1

https://github.com/1lann/log4shelldetect/blob/master/main.go
