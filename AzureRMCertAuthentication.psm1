<# 
 .Synopsis
  This Module Create or Remove a service principal using self-signed certificate to avoid password prompts on Powershell.

 .Description
  This Modulo will Create an service principal and associate a Self-Signed Certificate.
  The intention is to avoid multiple password prompts each time you open Powershell.
  An additional function will be exported to the current user profile to be used to connect to AzureRM without password prompt.

  Example of a Function that will be exported:

    ##################### Function Connect-AzureRM #####################
    Function Connect-AzureRM{ 
        $TenantID = "' + $SessionContext.Tenant.Id + '"
        $thumb = "' + $SelfSignedCertificate.thumb + '" 
        $ApplicationID = [GUID]"' + $azureAdApplication.ApplicationId.Guid + '" 
        Add-AzureRmAccount -TenantId $TenantID -ServicePrincipal -CertificateThumbprint $thumb -ApplicationId $ApplicationID
        if($host.ui.RawUI.WindowTitle -eq "Windows PowerShell"){
            $host.ui.RawUI.WindowTitle = "Connected to: AzureRM"
        }
        elseif($host.ui.RawUI.WindowTitle.contains("Connected")){
            $host.ui.RawUI.WindowTitle = ($host.ui.RawUI.WindowTitle + " & AzureRM")
        }
    }
    ####################################################################
  
  One the service principal is created you just have to type Connect-<FunctionName> each time you open the Powershell.
  The funcion will use the Self-Signed certificate created and associated with a service principal to authenticate with no password.

 .Example
   # Creating AzureRMCertAuthentication 
   New-AzureRMCertAuthentication -FunctionName AzureRMVMSubscription1
   This Example will create a function named: "Connect-AzureRMVMSubscription1"

 .Example
   # In case you have two Azure Account (Subscritpions) you create a different function name for each Subscription.
   New-AzureRMCertAuthentication -FunctionName AzureRMVMSubscription2
   This Example will create a function named: "Connect-AzureRMVMSubscription2"

 .Example
   # Removing the exported function, service principal and exported funcion.
   Remove-AzureRMCertAuthentication -Function AzureRMVMSubscription1

# A URL to the main website for this project.
ProjectUri = 'https://github.com/welasco/AzureRMCertAuthentication'
Resource = https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-authenticate-service-principal
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
param()

# Function used to check the current Azure login session
Function CheckAzureSession{
    $Check = (Get-AzureRmContext).Account
    If($Check){
        return $true
    }
    else {
        return $false
    }
}

# Function used to create the Self-Signed certificated
Function CreateSelfSignedCertificate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
    Param(
        [Parameter(Mandatory=$true)]
        [PsObject]$FunctionName
    )    
    $currentDate = Get-Date
    $endDate = $currentDate.AddYears(1)
    $notAfter = $endDate.AddYears(1)
    $pwdStr = ([guid]::NewGuid()).guid.tostring().replace("-","")
    $dnsName = ($FunctionName + ".AzurePowershell.local")
    $certPath = Split-Path $profile.CurrentUserAllHosts
    $dstPath = Join-Path -Path $certPath -ChildPath ($dnsName + ".pfx")
    $thumb = (New-SelfSignedCertificate -CertStoreLocation cert:\CurrentUser\my -DnsName $dnsName -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
    $pwd = ConvertTo-SecureString -String $pwdStr -Force -AsPlainText
    Export-PfxCertificate -cert "cert:\CurrentUser\my\$thumb" -FilePath $dstPath -Password $pwd
    $return = New-Object PsObject @{
        currentDate=$currentDate
        endDate=$endDate
        pwd=$pwd
        dstPath=$dstPath
        thumb=$thumb
        dnsName=$dnsName
        certPath=$certPath
    }
    return $return
}

# Function load the the Self-Signed certificate and export the KeyCredential
Function CreateKeyCredential{
    Param(
        [Parameter(Mandatory=$true)]
        [PsObject]$SelfSignedCertificate,
        [PsObject]$AzureADApplication
    )
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($SelfSignedCertificate.dstPath, $SelfSignedCertificate.pwd)
    $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
    $keyId = [guid]::NewGuid()
    #Import-Module AzureRM.Resources
    #$keyCredential = New-Object  Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADKeyCredential
    #$keyCredential = New-Object  Microsoft.Azure.Graph.RBAC.Version1_6.ActiveDirectory.PSADCredential <-- new place
    #$keyCredential.StartDate = $SelfSignedCertificate.currentDate
    #$keyCredential.EndDate= $SelfSignedCertificate.endDate
    #$keyCredential.KeyId = $keyId
    #$keyCredential.CertValue = $keyValue

    try {
        New-AzureRmADAppCredential -CertValue $keyvalue -StartDate $SelfSignedCertificate.currentDate -EndDate $SelfSignedCertificate.endDate -ApplicationId $AzureADApplication.ApplicationId.ToString()
    }
    catch {
        Write-Output ("Failed to change the AzureAdApplicationCredential: " )
    }
    #New-AzureRmADAppCredential -CertValue $keyvalue -StartDate $SelfSignedCertificate.currentDate -EndDate $SelfSignedCertificate.endDate -ApplicationId a6d3e1c2-dcba-4d13-bcc8-9a691fb4ae8c

    return $keyCredential
}

# Function to Remove the Exported Profile Function
Function RemoveProfileFunction{
    Param(
        [Parameter(Mandatory=$true)]
        [PsObject]$FunctionName
    ) 
    $profileFile = Get-Content $profile.CurrentUserAllHosts
    $currentDateTime = (Get-Date).Month.ToString() + (Get-Date).Day.ToString() + (Get-Date).Year.ToString() + (Get-Date).Hour.ToString() + (Get-Date).Minute.ToString() + (Get-Date).Second.ToString()
    $tempFile = ($profile.CurrentUserAllHosts | Split-Path) | Join-Path -ChildPath ("tempProfile" + $currentDateTime + ".txt")
    $bkpFile = ($profile.CurrentUserAllHosts.Replace(".ps1", ("-bkp-" + $currentDateTime + ".ps1")))
    $funcString = ("##################### Function Connect-" + $FunctionName + " #####################")

    Copy-Item $profile.CurrentUserAllHosts $bkpFile

    $dstLinePosition = $null
    foreach($line in $profileFile){
        if ($line -eq $funcString) {
            $dstLinePosition = $line.ReadCount + 13
        }
        if ($dstLinePosition -ne $null) {
            if ($line.ReadCount -le $dstLinePosition) {
                # Don't copy the line
            }
            else {
                $line | Out-File $tempFile -Append
            }
        }
        else {
            $line | Out-File $tempFile -Append
        }
    }

    Copy-Item $tempFile $profile.CurrentUserAllHosts -Force
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

# Function to double check if should create the Service Principal using the current loging session or not
Function MenuYesNo{
    $title = ("You are currently using the Subscription: "+ (Get-AzureRmContext).Subscription.Name)
    $message = "Do you want to crate a new AzureRMCertAuthentication using this subscription?"

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
        "A new AzureRMCertAuthentication will be created using the current Subscription."

    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
        "Stop creation process of a new AzureRMCertAuthentication."

    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $result = $host.ui.PromptForChoice($title, $message, $options, 1) 

    switch ($result)
        {
            0 {return $True}
            1 {return $False}
        }    
}

# ### Exported Module Function ###
# This Function will create an AzureRMADApplication and associate with AzureRMADServicePrincipal
# The Self-Signed certificated will be associated with AzureRMADApplication
Function New-AzureRMCertAuthentication{
    <# 
    .Synopsis
    This Module Create or Remove a service principal using self-signed certificate to avoid password prompts on Powershell.

    .Description
    This Modulo will Create an service principal and associate a Self-Signed Certificate.
    The intention is to avoid multiple password prompts each time you open Powershell.
    An additional function will be exported to the current user profile to be used to connect to AzureRM without password prompt.

    Example of a Function that will be exported:

        ##################### Function Connect-AzureRM #####################
        Function Connect-AzureRM{ 
            $TenantID = "' + $SessionContext.Tenant.Id + '"
            $thumb = "' + $SelfSignedCertificate.thumb + '" 
            $ApplicationID = [GUID]"' + $azureAdApplication.ApplicationId.Guid + '" 
            Add-AzureRmAccount -TenantId $TenantID -ServicePrincipal -CertificateThumbprint $thumb -ApplicationId $ApplicationID
            if($host.ui.RawUI.WindowTitle -eq "Windows PowerShell"){
                $host.ui.RawUI.WindowTitle = "Connected to: AzureRM"
            }
            elseif($host.ui.RawUI.WindowTitle.contains("Connected")){
                $host.ui.RawUI.WindowTitle = ($host.ui.RawUI.WindowTitle + " & AzureRM")
            }
        }
        ####################################################################
    
    One the service principal is created you just have to type Connect-<FunctionName> each time you open the Powershell.
    The funcion will use the Self-Signed certificate created and associated with a service principal to authenticate with no password.

    .Example
    # Creating AzureRMCertAuthentication 
    New-AzureRMCertAuthentication -FunctionName AzureRMVMSubscription1
    This Example will create a function named: "Connect-AzureRMVMSubscription1"

    .Example
    # In case you have two Azure Account (Subscritpions) you create a different function name for each Subscription.
    New-AzureRMCertAuthentication -FunctionName AzureRMVMSubscription2
    This Example will create a function named: "Connect-AzureRMVMSubscription2"

    .Example
    # Removing the exported function, service principal and exported funcion.
    Remove-AzureRMCertAuthentication -Function AzureRMVMSubscription1

    # A URL to the main website for this project.
    ProjectUri = 'https://github.com/welasco/AzureRMCertAuthentication'
    Resource = https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-authenticate-service-principal
    #>    
    Param(
        [Parameter(Mandatory=$true)]
        [PsObject]$FunctionName
    )    
    $isSession = CheckAzureSession

    # Checking current session
    if ($isSession -eq $false) {
        Add-AzureRmAccount -ErrorAction Stop
    }
    else {
        $resultMenu = MenuYesNo
        if($resultMenu -eq $false){
            break
        }
    }

    #Checking if the ADApplication already exist
    $chkADApplications = Get-AzureRmADApplication -DisplayNameStartWith $FunctionName
    foreach($chkADApplication in $chkADApplications){
        $appFullFuncName = ($FunctionName + "-AzurePowershell-CertAuth")
        # DisplayName             : AzureRM-AzurePowershell-CertAuth
        if ($chkADApplication.DisplayName -eq $appFullFuncName) {
            Write-Output ("A previous AzureRMADApplication found with Name: " + $FunctionName)
            Write-OutPut ("Please run Remove-AzureRMCertAuthentication -FunctionName " + $FunctionName + " to remove it first.")
            break
        }
    }
    # Creating the Self-Signed certificate
    $SelfSignedCertificate = CreateSelfSignedCertificate -FunctionName $FunctionName

    # Create the Azure Active Directory Application
    $azureAdApplication = New-AzureRmADApplication -DisplayName ($FunctionName + "-AzurePowershell-CertAuth") -HomePage ("https://" + $SelfSignedCertificate.dnsName) -IdentifierUris ("https://" + $SelfSignedCertificate.dnsName)

    # Creating KeyCredential based on Self-Signed certificate
    $PSADKeyCredential = CreateKeyCredential -SelfSignedCertificate $SelfSignedCertificate -AzureADApplication $azureAdApplication

    # Create the Service Principal and connect it to the Application
    New-AzureRmADServicePrincipal -ApplicationId $azureAdApplication.ApplicationId

    # We must sleep 20 seconds waiting Service Principal be created on AzureRM
    Start-Sleep -Seconds 20

    # Give the Service Principal Owner access to the current subscription
    New-AzureRmRoleAssignment -RoleDefinitionName Owner -ServicePrincipalName $azureAdApplication.ApplicationId

    $SessionContext = Get-AzureRmContext

    # Preparing Connect-<FunctionName> to be exported
    $ExportFunction = '
##################### Function Connect-' + $FunctionName + ' #####################
Function Connect-' + $FunctionName + '{ 
    $TenantID = "' + $SessionContext.Tenant.Id + '"
    $thumb = "' + $SelfSignedCertificate.thumb + '" 
    $ApplicationID = [GUID]"' + $azureAdApplication.ApplicationId.Guid + '" 
    Add-AzureRmAccount -TenantId $TenantID -ServicePrincipal -CertificateThumbprint $thumb -ApplicationId $ApplicationID
    if($host.ui.RawUI.WindowTitle -eq "Windows PowerShell"){
        $host.ui.RawUI.WindowTitle = "Connected to: ' + $FunctionName + '"
    }
    elseif($host.ui.RawUI.WindowTitle.contains("Connected")){
        $host.ui.RawUI.WindowTitle = ($host.ui.RawUI.WindowTitle + " & ' + $FunctionName + '")
    }
}
####################################################################'
    
    # Exporting Connect-<FunctionName>
    if (Test-Path $profile.CurrentUserAllHosts) {
        $profileFile = Get-Content $profile.CurrentUserAllHosts
    }
    $profileFile += $ExportFunction
    $profileFile | Out-File $profile.CurrentUserAllHosts -Force        



    Write-Output ("Now re-open Powershell and run Connect-" + $FunctionName +" to connect!")
}

# ### Exported Module Function ###
# This Function will remove an AzureRMADApplication, AzureRMADServicePrincipal, Self-Signed Certificate and Exported Function
Function Remove-AzureRMCertAuthentication{
    <# 
    .Synopsis
    This Module Create or Remove a service principal using self-signed certificate to avoid password prompts on Powershell.

    .Description
    This Modulo will Create an service principal and associate a Self-Signed Certificate.
    The intention is to avoid multiple password prompts each time you open Powershell.
    An additional function will be exported to the current user profile to be used to connect to AzureRM without password prompt.

    Example of a Function that will be exported:

        ##################### Function Connect-AzureRM #####################
        Function Connect-AzureRM{ 
            $TenantID = "' + $SessionContext.Tenant.Id + '"
            $thumb = "' + $SelfSignedCertificate.thumb + '" 
            $ApplicationID = [GUID]"' + $azureAdApplication.ApplicationId.Guid + '" 
            Add-AzureRmAccount -TenantId $TenantID -ServicePrincipal -CertificateThumbprint $thumb -ApplicationId $ApplicationID
            if($host.ui.RawUI.WindowTitle -eq "Windows PowerShell"){
                $host.ui.RawUI.WindowTitle = "Connected to: AzureRM"
            }
            elseif($host.ui.RawUI.WindowTitle.contains("Connected")){
                $host.ui.RawUI.WindowTitle = ($host.ui.RawUI.WindowTitle + " & AzureRM")
            }
        }
        ####################################################################
    
    One the service principal is created you just have to type Connect-<FunctionName> each time you open the Powershell.
    The funcion will use the Self-Signed certificate created and associated with a service principal to authenticate with no password.

    .Example
    # Creating AzureRMCertAuthentication 
    New-AzureRMCertAuthentication -FunctionName AzureRMVMSubscription1
    This Example will create a function named: "Connect-AzureRMVMSubscription1"

    .Example
    # In case you have two Azure Account (Subscritpions) you create a different function name for each Subscription.
    New-AzureRMCertAuthentication -FunctionName AzureRMVMSubscription2
    This Example will create a function named: "Connect-AzureRMVMSubscription2"

    .Example
    # Removing the exported function, service principal and exported funcion.
    Remove-AzureRMCertAuthentication -Function AzureRMVMSubscription1

    # A URL to the main website for this project.
    ProjectUri = 'https://github.com/welasco/AzureRMCertAuthentication'
    Resource = https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-authenticate-service-principal
    #>      
    Param(
        [Parameter(Mandatory=$true)]
        [PsObject]$FunctionName
    )     
    try{
        $AzureRMADApps = Get-AzureRmADApplication -DisplayNameStartWith $FunctionName
        foreach($AzureRMADApp in $AzureRMADApps){
            $appFullFuncName = ($FunctionName + "-AzurePowershell-CertAuth")
            if($AzureRMADApp.DisplayName -eq $appFullFuncName){
                Remove-AzureRmADApplication -ObjectId $AzureRMADApp.ObjectId
                try {
                    Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq ("CN=" + $FunctionName + ".AzurePowershell.local") } | Remove-Item -Force
                    if(Test-Path($profile.CurrentUserAllHosts)){
                        RemoveProfileFunction -FunctionName $FunctionName
                    }
                    Remove-Item ($profile.CurrentUserAllHosts | Split-Path | Join-Path -ChildPath ($FunctionName + ".AzurePowershell.local.pfx")) -ErrorAction SilentlyContinue -Force
                }
                catch {
                    Write-Output ("Failed to remove Self-Signed certificate: " + ("CN=" + $FunctionName + ".AzurePowershell.local"))
                }
                Write-Output "Sucessfully removed AzureRMCertAuthentication"
            }
            else{
                Write-Output "Azure AD Application not found."
            }
        }
    }
    catch{
        Write-Output "To remove the a AzureRMCertAuthentication you must login again. Please type Login-AzureRmAccount"
    }

}

# Exporting Powershell Functions from this Module
Export-ModuleMember -Function New-AzureRMCertAuthentication, Remove-AzureRMCertAuthentication

