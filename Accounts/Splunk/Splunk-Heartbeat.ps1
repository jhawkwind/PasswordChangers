# Set initial status to fail until proven to succeed.
$exit_status = -1

# Transfer variables from call.
$MACHINE = $Args[0]
$USERNAME = $Args[1]
$PASSWORD = $Args[2]
$PORT = 8089

try {
    # Use DNS resolution to ensure a valid domain name was entered, fastest and easiest way to check.
    $DNSOutput = Resolve-DnsName -Name ${MACHINE} -DnsOnly
    if(${DNSOutput}.Name.GetType().FullName -match "System.String") {
        $ResolvedName = ${DNSOutput}.Name
    }
    else {
        $ResolvedName = ${DNSOutput}.Name[0]
    }
}
catch {
    Write-Error "FATAL: Cannot resolve the domain name, please check the domain name parameter. $($PSItem.Execption.GetType())"
    $PSItem.Exception | Get-Member | Write-Debug
    throw $PSItem
}

if(-not ($PORT -gt 0 -and $PORT -le 65535)) {
    throw [System.ArgumentOutOfRangeException]::new("Port number not in valid range between 1 and 65535 inclusive.",'PORT')
}

try {
    #Sanitize all inputs via URL Encoding.
    $CodedUsername = [System.Web.HttpUtility]::UrlEncode(${USERNAME})
    $CodedPassword = [System.Web.HttpUtility]::UrlEncode(${PASSWORD})
}
catch [System.Management.Automation.RuntimeException] { # Handle this exception on servers that do not have the module loaded on PowerShell.
    try {
        # Reference: https://stackoverflow.com/questions/38408729/unable-to-find-type-system-web-httputility-in-powershell
        Add-Type -AssemblyName System.Web
        $CodedUsername = [System.Web.HttpUtility]::UrlEncode(${USERNAME})
        $CodedPassword = [System.Web.HttpUtility]::UrlEncode(${PASSWORD})
    }
    catch {
        Write-Error "FATAL: Cannot load URLEncoding library. Unhandled Exception Type of $($PSItem.Exception.GetType())"
        Write-Error $PSItem.ToString()
        $PSItem.Exception | Get-Member | Write-Debug
        throw $PSItem
    }
}
catch {
    Write-Error "Double FATAL: Unhandled Exception Type of $($PSItem.Exception.GetType())"
    Write-Error $PSItem.ToString()
    $PSItem.Exception | Get-Member | Write-Debug
    throw $PSItem
}

# Set system configuration for secure communications.
# Uncomment below line to NOT Validate SSL Cert to trust store. (For Self Signed certs and testing only)
# [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }

# Uncomment below line to enforce TLS 1.2
# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$auth= @"
username={0}&password={1}
"@ -f $CodedUsername,$CodedPassword

# Compile the URL
$URL = "https://${ResolvedName}:${PORT}/services/auth/login"

try {
    $output = Invoke-RestMethod -Uri ${URL} -Method Post -Body ${auth} -UserAgent 'ThycoticSecretServerPowerhsell'
}
catch [System.Net.WebException] {
    # Determine why login failed, make it a bit more user friendly and still provide detailed messages.
    if ( $PSItem.Exception.Response.StatusCode -match "BadRequest" ) {
        throw [System.Net.WebException]::new("Failure: API or target account credentials are invalid or locked out.", $PSItem.Exception)
    }
    elseif ( $PSItem.Exception.Response.StatusCode -match "InternalServerError" ) {
        throw [System.Net.WebException]::new("Error: An Internal Server Error has occurred.", $PSItem.Exception)
    }
    elseif ( $PSItem.Exception.Response.StatusCode -match "Unauthorized" ) {
        throw [System.Net.WebException]::new("Failure: API Credentials invalid.", $PSItem.Exception)
    }
    elseif ( $PSItem.Exception.Response.StatusCode -match "Forbidden" ) {
        throw [System.Net.WebException]::new("Failure: Old Password incorrect.", $PSItem.Exception)
    }

    # Uncaught and unhandled and unknown exceptions get extra dump treatment.
    $PSitem.Exception.GetType() | Format-List * | Write-Debug
    Write-Error "Unable to retrieve session token: $($PSItem.ToString())"
    Write-Error "FATAL: Unknown API Exception Encountred $($PSItem.Exception.GetType())"
    $innerException = $PSItem.Exception.InnerExceptionMessage
    Write-Error "Inner Exception: $innerException"
        $e = $_.Exception
        $msg = $e.Message
        while ($e.InnerException) {
          $e = $e.InnerException
          $msg += "`n" + $e.Message
        }
        Write-Error $msg
    $PSItem.Exception | Get-Member | Write-Debug
    
    throw $PSItem
}
catch {
    Write-Error "Double FATAL: Unhandled Exception Type of $($PSItem.Exception.GetType())"
    Write-Error $PSItem.ToString()
    $PSItem.Exception | Get-Member | Write-Debug
    throw $PSItem
}
finally {
    # Uncomment below line to clean up if you enabled SSL Bypass above.
    # [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}


$stateToken = ${output}.response.sessionKey

if(-not ([string]::IsNullOrEmpty($stateToken))) {
    $return_status = @{ "Status" = "Success"; "stateToken" = "${stateToken}" }
    Write-Output ${return_status}
    $exit_status = 0
}
else {
    Write-Output @{ "Status" = "Failure"; "SessionToken" = "" }
    # Any other status, count it as soft bad.
    # throw [System.ApplicationException]::new("Cannot parse authorization token.",$PSItem)
    $exit_status = 1;
}

exit $exit_status;