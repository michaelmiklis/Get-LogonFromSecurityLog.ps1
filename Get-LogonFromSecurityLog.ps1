######################################################################
## (C) 2017 Michael Miklis (michaelmiklis.de)
##
##
## Filename:      Get-LogonFromSecurityLog.ps1
##
## Version:       1.1
##
## Release:       Final
##
## Requirements:  -none-
##
## Description:   Parses the security eventlog for logons of a
##                specific account.
##
## This script is provided 'AS-IS'.  The author does not provide
## any guarantee or warranty, stated or implied.  Use at your own
## risk. You are free to reproduce, copy & modify the code, but
## please give the author credit.
##
####################################################################
Set-PSDebug -Strict
Set-StrictMode -Version latest
   
  
function Get-LogonFromSecurityLog {
    <#
    .SYNOPSIS
    Parses the security eventlog for logons of a specific account
   
    .DESCRIPTION
    The Get-LogonFromSecurityLog CMDlet parses all security eventlog
    messages for specific logon events. It returns the client IP and
    source port from where the logon event was triggered.
   
    .PARAMETER LastHours
    Only parse events not older than X Hours
   
    .PARAMETER Username
    Username to search for
   
    .EXAMPLE
    Get-LogonFromSecurityLog -Username "Administrator" -LastHours 2
  
    #>
       
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Username,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]$LastHours = 0
    )
  
 
    if ($LastHours -gt 0)
    {
        $StartTime = (Get-Date).AddHours(-$LastHours)
        $events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4624'; StartTime=$StartTime}
    }
 
    else
    {
        $events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4624'; StartTime=$StartTime}
    }


  
    # loop through each found event
    foreach($event in $events)
    {

        If ($event.message.Contains($Username))
        {

           # Create XML structure of eventlog entry
           [XML]$eventXML = $event.ToXml()
       
           # IpAddress
           $ip = $eventXML.Event.EventData.Data[18].'#text'

           # IpPort
           $port = $eventXML.Event.EventData.Data[19].'#text'

           # Date
           $date = $event.TimeCreated.ToString("dd.MM.yyyy HH:mm:ss")
 
           # print source ip and port to console
           "$date;$Username;$ip;$port";
        }
    }
  
}
 
Get-LogonFromSecurityLog -Username "Administrator" -LastHours 2