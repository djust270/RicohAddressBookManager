<#
.SYNOPSIS
    Converts string to Base64 text.

.DESCRIPTION
    Converts string to Base64 text.

.PARAMETER String
    String to convert to Base64
#>
function ConvertTo-Base64 {

    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string[]]
        $String
    )

    process {

        ForEach-Object -InputObject $String {
        
            # handle empty strings
            if ( [string]::IsNullOrEmpty($_) ) { return $_ }
            
            # convert non-empty strings to base64
            [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($_))

        }

    }

}


<#
.SYNOPSIS
    Reads a SOAP XML template.

.DESCRIPTION
    Reads a SOAP XML template, optionally replacing key value pairs.

.PARAMETER Path
    Path to the template file.

.PARAMETER Replacements
    Hashtable of key value pairs to replace. Keys should be stored in the file with double brackets (ex: [[KeyName]]).
#>
function Get-SoapTemplate {

    param(
    
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [System.IO.FileInfo]
        $Path,

        [hashtable]
        $Replacements

    )

    process {
    
        $Content = Get-Content -Raw -Path $Path -ErrorAction Stop

        foreach ( $Key in $Replacements.Keys ) {
        
            $Content = $Content -ireplace [regex]::Escape("[[$Key]]"), $Replacements[$Key]
            
        }

        [xml]$Content
    
    }

}



<#
.SYNOPSIS
    Connects to a RICOH copier.

.DESCRIPTION
    Connects to a RICOH copier.

.PARAMETER Hostname
    Hostname or IP Address of the copier to connect to.

.PARAMETER UseSSL
    Use SSL to connect to the copier.

.PARAMETER Credential
    The credential to use to connect to the copier.

.PARAMETER UserName
    The user name to use to connect to the copier. Defaults to 'admin'.

.PARAMETER Password
    The password to use to connect to the copier. Defaults to an empty string.
#>
function Connect-Copier {

    [CmdletBinding(DefaultParameterSetName='UsingUserNameAndPassword')]
    param(
    
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [switch]
        $UseSSL,
    
        [Parameter(ParameterSetName='UsingCredential')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $UserName = 'admin',

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $Password = ''
    
    )

    process {

        # parse user name and password from credential object
        if ( $PSCmdlet.ParameterSetName -eq 'UsingCredential' ) {

            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        
                $CredentialSplat['Credential'] = $Credential

                $UserName = $Credential.GetNetworkCredential().UserName

                $Password = $Credential.GetNetworkCredential().Password
        
            }

        }

        # build the URI
        $Uri            = ('http','https')[$UseSSL.IsPresent] + '://' + $Hostname + '/DH/udirectory'

        # set the authentication scheme
        $Authentication = ConvertTo-Base64 -String 'BASIC'

        # convert the user name and password to Base64
        $UserName       = ConvertTo-Base64 -String $UserName
        $Password       = ConvertTo-Base64 -String $Password

        # get the login XML
        $LoginXml       = Get-SoapTemplate -Path "$PSScriptRoot\SoapTemplates\Connect.xml"

        # add the authentication to the XML
        $LoginXml.Envelope.Body.startSession.stringIn = `
                        "SCHEME=$Authentication;UID:UserName=$UserName;PWD:Password=$Password;PES:Encoding=gwpwes003"
        
        # build the webrequest
        $WebRequest     = @{
            Uri         = $Uri
            Method      = 'Post'
            ContentType = 'text/xml'
            Headers     = @{SOAPAction = 'http://www.ricoh.co.jp/xmlns/soap/rdh/udirectory#startSession'}
            Body        = $LoginXml
        
        }
        [xml]$ResponseXML = Invoke-WebRequest @WebRequest -ErrorAction SilentlyContinue

        if ($ResponseXML.Envelope.Body.Fault.detail.rdhError.errorCode -eq 'COMMON_SYSTEM_BUSY') {
        
            Write-Error "Copier at $Hostname is busy, try again later." -ErrorAction Stop

        }

        if($ResponseXML.Envelope.Body.startSessionResponse.returnValue -eq 'OK') {
    
            $Script:Session = $ResponseXML.Envelope.Body.startSessionResponse.stringOut

            Write-Verbose "Connected to $Hostname with session '$($Script:Session)'."
        
        }

    }

}


<#
.SYNOPSIS
    Disconnects from a RICOH copier.

.DESCRIPTION
    Disconnects from a RICOH copier.

.PARAMETER Hostname
    Hostname or IP Address of the copier to connect to.

.PARAMETER UseSSL
    Use SSL to connect to the copier.
#>
function Disconnect-Copier {

    [CmdletBinding()]
    param(
    
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [switch]
        $UseSSL

    )

    process {

        # check for active session
        if ( -not $Script:Session ) {
        
            Write-Warning "There is no active copier session."
            return
            
        }

        # build the URI
        $Uri            = ('http','https')[$UseSSL.IsPresent] + '://' + $Hostname + '/DH/udirectory'

        # get the logout XML
        $LogoutXml       = Get-SoapTemplate -Path "$PSScriptRoot\SoapTemplates\Disconnect.xml"

        # set the session to logout into the XML
        $LogoutXml.Envelope.Body.terminateSession.sessionId = $Script:Session

        # build the webrequest
        $WebRequest      = @{
            Uri          = $Uri
            Method       = 'Post'
            ContentType  = 'text/xml'
            Headers      = @{SOAPAction="http://www.ricoh.co.jp/xmlns/soap/rdh/udirectory#terminateSession"}
            Body         = $LogoutXml
        }
        Invoke-WebRequest @WebRequest > $null

        Write-Verbose "Disconnected from $Hostname with session '$($Script:Session)'."

        # remove the session variable
        Remove-Variable -Name 'Session' -Scope 'Script'

    }

}


<#
.SYNOPSIS
    Fetches EntryIds from a Ricoh copier.

.DESCRIPTION
    Fetches EntryIds from a Ricoh copier.

.PARAMETER Hostname
    Hostname or IP Address of the copier to connect to.

.PARAMETER UseSSL
    Use SSL to connect to the copier.

.PARAMETER Credential
    The credential to use to connect to the copier.

.PARAMETER UserName
    The user name to use to connect to the copier. Defaults to 'admin'.

.PARAMETER Password
    The password to use to connect to the copier. Defaults to an empty string.
#>
function Search-EntryIds {

    [CmdletBinding(DefaultParameterSetName='UsingUserNameAndPassword')]
    param(
    
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [switch]
        $UseSSL,
    
        [Parameter(ParameterSetName='UsingCredential')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $UserName = 'admin',

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $Password = ''
    
    )

    begin {

        # should we disconnect when done?
        # set only if connected inside the cmdlet
        $DisconnectWhenFinished = $false

        # check for connection parameters, try to connect if present
        if ( -not($Script:Session) ) {
        
            Connect-Copier @PSBoundParameters

            $DisconnectWhenFinished = $true
        
        }
    
    }

    process {

        # build the URI
        $Uri            = ('http','https')[$UseSSL.IsPresent] + '://' + $Hostname + '/DH/udirectory'

        # get the search XML
        $SearchXml      = Get-SoapTemplate -Path "$PSScriptRoot\SoapTemplates\Search.xml"

        # set the session into the XML
        $SearchXml.Envelope.Body.searchObjects.sessionId = $Script:Session

        # build the webrequest
        $WebRequest      = @{
            Uri          = $Uri
            Method       = 'Post'
            ContentType  = 'text/xml'
            Headers      = @{SOAPAction="http://www.ricoh.co.jp/xmlns/soap/rdh/udirectory#searchObjects"}
            Body         = $SearchXml
        }
        [xml]$Result = Invoke-WebRequest @WebRequest

        # get the search results
        $Result.SelectNodes("//rowList/item") |
            ForEach-Object { $_.item.propVal } |
            Where-Object { $_.length -lt "10" } |
            ForEach-Object { [int]$_ } |
            Sort-Object
        
    }

    end {
    
        # disconnect if connected in this cmdlet
        if ( $DisconnectWhenFinished ) {
        
            Disconnect-Copier -Hostname $Hostname -UseSSL:$UseSSL.IsPresent
        
        }
    
    }

}


<#
.SYNOPSIS
    Get Address Book Entries from a Ricoh copier.

.DESCRIPTION
    Get Address Book Entries from a Ricoh copier.

.PARAMETER Hostname
    Hostname or IP Address of the copier to connect to.

.PARAMETER UseSSL
    Use SSL to connect to the copier.

.PARAMETER Credential
    The credential to use to connect to the copier.

.PARAMETER UserName
    The user name to use to connect to the copier. Defaults to 'admin'.

.PARAMETER Password
    The password to use to connect to the copier. Defaults to an empty string.
#>
function Get-Entries {

    [CmdletBinding(DefaultParameterSetName='UsingUserNameAndPassword')]
    param(
    
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [switch]
        $UseSSL,
    
        [Parameter(ParameterSetName='UsingCredential')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $UserName = 'admin',

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $Password = ''
    
    )

    begin {

        # should we disconnect when done?
        # set only if connected inside the cmdlet
        $DisconnectWhenFinished = $false

        # check for connection parameters, try to connect if present
        if ( -not($Script:Session) ) {
        
            Connect-Copier @PSBoundParameters

            $DisconnectWhenFinished = $true
        
        }
    
    }

    process {

        # build the URI
        $Uri            = ('http','https')[$UseSSL.IsPresent] + '://' + $Hostname + '/DH/udirectory'

        # get the request XML
        $RequestXml     = Get-SoapTemplate -Path "$PSScriptRoot\SoapTemplates\Get.xml"

        # set the session into the XML
        $RequestXml.Envelope.Body.getObjectsProps.sessionId = $Script:Session

        # fetch the address book entry ids
        Search-EntryIds -Hostname $Hostname -UseSSL:$UseSSL.IsPresent | ForEach-Object {
    
            $RequestItem = $RequestXml.CreateElement("item")
    
            $RequestItem.set_InnerText("entry:$_")
    
            $RequestXml.Envelope.Body.getObjectsProps.objectIdList.AppendChild($RequestItem) > $null
    
        }
    
        # add the number of entries to return to the request
        $RequestXml.Envelope.Body.getObjectsProps.objectIdList.arrayType = "itt:string[$($RequestXml.Envelope.Body.getObjectsProps.objectIdList.item.count)]"

        # build the webrequest
        $WebRequest      = @{
            Uri          = $Uri
            Method       = 'Post'
            ContentType  = 'text/xml'
            Headers      = @{SOAPAction="http://www.ricoh.co.jp/xmlns/soap/rdh/udirectory#getObjectsProps"}
            Body         = $RequestXml
        }
        [xml]$ResultXml = Invoke-WebRequest @WebRequest

        # process the results
        $ResultXml.SelectNodes("//returnValue/item") | ForEach-Object {
            
            New-Object PSObject -Property @{
                EntryType =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'entryType'    } ).propVal
                ID        = [int]( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'id'           } ).propVal
                Index     = [int]( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'index'        } ).propVal
                Name      =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'name'         } ).propVal
                LongName  =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'longname'     } ).propVal
                UserCode  =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'auth:name'    } ).propVal
                Mail      =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'mail:address' } ).propVal
                FaxNumber =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'fax:number'   } ).propVal
                Title1     =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'tagId'        } ).propVal
                <#Folder    = New-Object -TypeName psobject -Property @{
                    Type      =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'remoteFolder:type' } ).propVal
                    Server    =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'remoteFolder:serverName' } ).propVal
                    Path      =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'remoteFolder:path' } ).propVal
                    UserName  =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'remoteFolder:accountName' } ).propVal
                    Password  =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'remoteFolder:password' } ).propVal
                    Port      =      ( ForEach-Object { $_.item } | Where-Object { $_.propName -eq 'remoteFolder:port' } ).propVal
                }#>

            }

        }
        
    }

    end {
    
        # disconnect if connected in this cmdlet
        if ( $DisconnectWhenFinished ) {
        
            Disconnect-Copier -Hostname $Hostname -UseSSL:$UseSSL.IsPresent
        
        }
    
    }
}


<#
.SYNOPSIS
    Create a new Address Book Entry on a Ricoh copier.

.DESCRIPTION
    Create a new Address Book Entry on a Ricoh copier.

.PARAMETER Name
    Name of the entry to add.

.PARAMETER LongName
    Long name of the entry to add. Defaults to Name.

.PARAMETER UserCode
    Code user enters to access machine functions.

.PARAMETER Destination
    Entry is a destination. Default is $true.

.PARAMETER Sender
    Entry is a sender. Default is $false.

.PARAMETER EmailAddress
    Email address for entry.

.PARAMETER FaxNumber
    Fax Number of entry.
    
.PARAMETER Title1
    Title 1 of entry - value of 1-11 corresponding to the list of values in the admin interface.

.PARAMETER Hostname
    Hostname or IP Address of the copier to connect to.

.PARAMETER UseSSL
    Use SSL to connect to the copier.

.PARAMETER Credential
    The credential to use to connect to the copier.

.PARAMETER UserName
    The user name to use to connect to the copier. Defaults to 'admin'.

.PARAMETER Password
    The password to use to connect to the copier. Defaults to an empty string.
#>
function New-Entry {

    [CmdletBinding(DefaultParameterSetName='UsingUserNameAndPassword')]
    param(

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,

        [ValidateNotNullOrEmpty()]
        [string]
        $LongName,

        [System.Nullable[int32]]
        $UserCode,

        [bool]
        $Destination = $true,

        [bool]
        $Sender = $false,

        [ValidatePattern('^.+@.+\..+$')]
        [ValidateNotNullOrEmpty()]
        [string]
        $EmailAddress,

        [ValidatePattern('^\+?\d+$')]
        [ValidateNotNullOrEmpty()]
        [string]
        $FaxNumber,
        
        [ValidateNotNullOrEmpty()]
        [string]
        $Title1,

        [ValidatePattern('^\\\\|^ftp://')]
        [ValidateNotNullOrEmpty()]
        [string]
        $RemoteFolder,

        [ValidateNotNullOrEmpty()]
        [string]
        $RemoteFolderUserName,

        [ValidateNotNullOrEmpty()]
        [string]
        $RemoteFolderPassword,
    
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [switch]
        $UseSSL,
    
        [Parameter(ParameterSetName='UsingCredential')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $UserName = 'admin',

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $Password = ''
    
    )

    begin {

        # should we disconnect when done?
        # set only if connected inside the cmdlet
        $DisconnectWhenFinished = $false

        # check for connection parameters, try to connect if present
        if ( -not($Script:Session) ) {

            $ConnectSplat = @{}
            $PSBoundParameters.Keys | Where-Object { $_ -in @('Hostname', 'UseSSL', 'Credential', 'UserName', 'Password') } | ForEach-Object { $ConnectSplat[$_] = $PSBoundParameters[$_] }
        
            Connect-Copier @ConnectSplat

            $DisconnectWhenFinished = $true
        
        }
    
    }

    process {

        # build the URI
        $Uri            = ('http','https')[$UseSSL.IsPresent] + '://' + $Hostname + '/DH/udirectory'

        # get the request XML
        $NewXml         = Get-SoapTemplate -Path "$PSScriptRoot\SoapTemplates\New.xml"

        # set the session into the XML
        $NewXml.Envelope.Body.putObjects.sessionId = $Script:Session

        # set the entry type
        $NewXml.Envelope.Body.putObjects.propListList.item.item[0].propVal = 'user'

        # if there is an index we create an index property
        if ( $null -ne $Index ) {

            $ItemElement = $NewXml.CreateElement("item")
            $ItemElement.set_InnerText("")
            
            $PropNameElement = $NewXml.CreateElement("propName")
            $PropNameElement.set_InnerText("index")
            
            $PropValueElement = $NewXml.CreateElement("propVal")
            $PropValueElement.set_InnerText($Index)
            
            $ItemElement.AppendChild($PropNameElement) > $null
            $ItemElement.AppendChild($PropValueElement) > $null
            
            $NewXml.Envelope.Body.putObjects.propListList.item.AppendChild($ItemElement) > $null

        }

        # set the name
        $NewXml.Envelope.Body.putObjects.propListList.item.item[1].propVal = $Name

        # set the long name
        if ( -not $LongName ) { $LongName = $Name }
        $NewXml.Envelope.Body.putObjects.propListList.item.item[2].propVal = $LongName


        # set the user login code/id
        if ( $null -ne $UserCode ) {

            $ItemElement = $NewXml.CreateElement("item")
            $ItemElement.set_InnerText('')

            $PropNameElement = $NewXml.CreateElement("propName")
            $PropNameElement.set_InnerText("auth:name")
            
            $PropValueElement = $NewXml.CreateElement("propVal")
            $PropValueElement.set_InnerText($UserCode)
            
            $ItemElement.AppendChild($PropNameElement) > $null
            $ItemElement.AppendChild($PropValueElement) > $null

            $NewXml.Envelope.Body.putObjects.propListList.item.AppendChild($ItemElement) > $null
        
        }
        
        # set the isDestination value
        $NewXml.Envelope.Body.putObjects.propListList.item.item[3].propVal = ('false', 'true')[$Destination]

        # set the isSender value
        $NewXml.Envelope.Body.putObjects.propListList.item.item[4].propVal = ('false', 'true')[$Sender]

        # set the 'mail:' value 
        $NewXml.Envelope.Body.putObjects.propListList.item.item[5].propVal = ('false', 'true')[-not([string]::IsNullOrEmpty($EmailAddress))]

        # set the MailAddress value
        $NewXml.Envelope.Body.putObjects.propListList.item.item[6].propVal = $EmailAddress

        # set the 'fax:' value 
        $NewXml.Envelope.Body.putObjects.propListList.item.item[7].propVal = ('false', 'true')[-not([string]::IsNullOrEmpty($FaxNumber))]

        # set the FaxNumber value
        $NewXml.Envelope.Body.putObjects.propListList.item.item[8].propVal = $FaxNumber

        if ( -not([string]::IsNullOrEmpty($RemoteFolder)) ) {

            # set the 'remoteFolder:' value 
            $NewXml.Envelope.Body.putObjects.propListList.item.item[9].propVal = 'true'

            # parse and set options for FTP server
            if ( $RemoteFolder -match '^ftp:' ) {

                # get server string
                $RemoteFolderServerName, $RemoteFolderPath = $RemoteFolder.Replace('ftp://','').Split('/',2)

                # parse out the port if specified
                $RemoteFolderServerName, [int]$RemoteFolderPort = $RemoteFolderServerName.Split(':',2)
                if ( $RemoteFolderPort -eq 0 ) { $RemoteFolderPort = 21 }

                # set the 'remoteFolder:type' value
                $NewXml.Envelope.Body.putObjects.propListList.item.item[10].propVal = 'ftp'

                # set the 'remoteFolder:serverName' value
                $NewXml.Envelope.Body.putObjects.propListList.item.item[11].propVal = $RemoteFolderServerName

                # set the 'remoteFolder:port' value
                $NewXml.Envelope.Body.putObjects.propListList.item.item[12].propVal = $RemoteFolderPort

                # set the 'remoteFolder:path' value
                $NewXml.Envelope.Body.putObjects.propListList.item.item[13].propVal = $RemoteFolderPath

                # set the 'remoteFolder:accountName' value
                $NewXml.Envelope.Body.putObjects.propListList.item.item[14].propVal = $RemoteFolderUserName

                if ( -not([string]::IsNullOrEmpty($RemoteFolderPassword)) ) {

                    # set the 'remoteFolder:password' value
                    $NewXml.Envelope.Body.putObjects.propListList.item.item[15].propVal = ConvertTo-Base64 -String $RemoteFolderPassword

                    # set the 'remoteFolder:passwordEncoding' value
                    $NewXml.Envelope.Body.putObjects.propListList.item.item[16].propVal = 'gwpwes003'

                }


            # parse and set options for SMB server
            } else {

                # set the 'remoteFolder:type' value
                $NewXml.Envelope.Body.putObjects.propListList.item.item[10].propVal = 'smb'

                # set the 'remoteFolder:path' value
                $NewXml.Envelope.Body.putObjects.propListList.item.item[13].propVal = $RemoteFolder

                # set the 'remoteFolder:accountName' value
                $NewXml.Envelope.Body.putObjects.propListList.item.item[14].propVal = $RemoteFolderUserName

                if ( -not([string]::IsNullOrEmpty($RemoteFolderPassword)) ) {

                    # set the 'remoteFolder:password' value
                    $NewXml.Envelope.Body.putObjects.propListList.item.item[15].propVal = ConvertTo-Base64 -String $RemoteFolderPassword

                    # set the 'remoteFolder:passwordEncoding' value
                    $NewXml.Envelope.Body.putObjects.propListList.item.item[16].propVal = 'gwpwes003'

                }
            
            }

        } else {

            # set the 'remoteFolder:' value 
            $NewXml.Envelope.Body.putObjects.propListList.item.item[9].propVal = 'false'
            
        }
        
        # set the tagId value
        $NewXml.Envelope.Body.putObjects.propListList.item.item[17].propVal = $Title1
        
        # create the property count
        $NewXml.Envelope.Body.putObjects.propListList.arrayType = "itt:string[][$($NewXml.Envelope.Body.putObjects.propListList.item.item.count)]"

        # build the webrequest
        $WebRequest      = @{
            Uri          = $Uri
            Method       = 'Post'
            ContentType  = 'text/xml'
            Headers      = @{SOAPAction="http://www.ricoh.co.jp/xmlns/soap/rdh/udirectory#putObjects"}
            Body         = $NewXml
        }
        [xml]$ResultXml = Invoke-WebRequest @WebRequest
        
    }

    end {
    
        # disconnect if connected in this cmdlet
        if ( $DisconnectWhenFinished ) {
        
            Disconnect-Copier -Hostname $Hostname -UseSSL:$UseSSL.IsPresent
        
        }
    
    }

}


function Remove-Entry {

    [CmdletBinding(DefaultParameterSetName='UsingUserNameAndPassword')]
    param(

        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [int32[]]
        $ID,
    
        [Parameter(Mandatory)]
        [string]
        $Hostname,

        [switch]
        $UseSSL,
    
        [Parameter(ParameterSetName='UsingCredential')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $UserName = 'admin',

        [Parameter(ParameterSetName='UsingUserNameAndPassword')]
        [ValidateNotNull()]
        [string]
        $Password = ''
    
    )

    begin {

        # should we disconnect when done?
        # set only if connected inside the cmdlet
        $DisconnectWhenFinished = $false

        # check for connection parameters, try to connect if present
        if ( -not($Script:Session) ) {

            $ConnectSplat = @{}
            $PSBoundParameters.Keys | Where-Object { $_ -in @('Hostname', 'UseSSL', 'Credential', 'UserName', 'Password') } | ForEach-Object { $ConnectSplat[$_] = $PSBoundParameters[$_] }
        
            Connect-Copier @ConnectSplat

            $DisconnectWhenFinished = $true
        
        }
    
    }

    process {

        # build the URI
        $Uri            = ('http','https')[$UseSSL.IsPresent] + '://' + $Hostname + '/DH/udirectory'

        # get the request XML
        $RemoveXml      = Get-SoapTemplate -Path "$PSScriptRoot\SoapTemplates\Remove.xml"

        # set the session into the XML
        $RemoveXml.Envelope.Body.deleteObjects.sessionId = $Script:Session

        # build the remove request
        ForEach-Object -InputObject $ID -Process {

            $ItemElement = $RemoveXml.CreateElement('item')
            $ItemElement.set_InnerText("entry:$_")

            $RemoveXml.Envelope.Body.deleteObjects.objectIdList.AppendChild($ItemElement) > $null

        }

        # add count
        $RemoveXml.Envelope.Body.deleteObjects.objectIdList.arrayType = "itt:string[$($RemoveXml.Envelope.Body.deleteObjects.objectIdList.item.count)]"


        # build the webrequest
        $WebRequest      = @{
            Uri          = $Uri
            Method       = 'Post'
            ContentType  = 'text/xml'
            Headers      = @{SOAPAction="http://www.ricoh.co.jp/xmlns/soap/rdh/udirectory#deleteObjects"}
            Body         = $RemoveXml
        }
        [xml]$ResultXml = Invoke-WebRequest @WebRequest
        
    }

    end {
    
        # disconnect if connected in this cmdlet
        if ( $DisconnectWhenFinished ) {
        
            Disconnect-Copier -Hostname $Hostname -UseSSL:$UseSSL.IsPresent
        
        }
    
    }

}
