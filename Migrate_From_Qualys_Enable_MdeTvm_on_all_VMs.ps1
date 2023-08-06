#Requires -Version 5.0
<#
    .SYNOPSIS
    
    Scope - using Azure ARG
    This script will start by defining the targetting by enumerating Azure subs from Azure ARG.
    Then exclusions will be made covering subs, resource groups, resources in multiple ways
    It is possible to scope which servers is part of the scope, before moving forward to main program

    Main program - using REST api
    This script will remove existing Qualys enablement using REST api. It is not enough to remove the Qualys extension
    This script will also enable MdeTvm using REST api

    .MORE INFORMATION
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management

    .NOTES
    VERSION: 2212

    .COPYRIGHT
    @mortenknudsendk on Twitter
    Blog: https://mortenknudsen.net
    
    .LICENSE
    Licensed under the MIT license.

    .WARRANTY
    Use at your own risk, no warranty given!
#>


#------------------------------------------------------------------------------------------------------------
# Functions
#------------------------------------------------------------------------------------------------------------
Function AZ_Find_Subscriptions_in_Tenant_With_Subscription_Exclusions
{
    Write-Output ""
    Write-Output "Finding all subscriptions in scope .... please Wait !"

    $global:Query_Exclude = @()
    $Subscriptions_in_Scope = @()
    $pageSize = 1000
    $iteration = 0

    ForEach ($Sub in $global:Exclude_Subscriptions)
        {
            $global:Query_Exclude    += "| where (subscriptionId !~ `"$Sub`")"
        }

    $searchParams = @{
                        Query = "ResourceContainers `
                                | where type =~ 'microsoft.resources/subscriptions' `
                                | extend status = properties.state `
                                $global:Query_Exclude
                                | project id, subscriptionId, name, status | order by id, subscriptionId desc" 
                        First = $pageSize
                        }

    $results = do {
        $iteration += 1
        $pageResults = Search-AzGraph -ManagementGroup $Global:ManagementGroupScope @searchParams
        $searchParams.Skip += $pageResults.Count
        $Subscriptions_in_Scope += $pageResults
    } while ($pageResults.Count -eq $pageSize)

    $Global:Subscriptions_in_Scope = $Subscriptions_in_Scope

    # Output
    $Global:Subscriptions_in_Scope
}

Function AZ_Find_All_Hybrid_VM_Resources
{
    # Build Exclude string
    AZ_Graph_Query_Build_Exclude_String

    Write-Output ""
    # Find all Azure ARC (Hybrid) VM Resources 
    Write-Output "Finding all Azure ARC (hybrid) VM Resources .... please Wait !"
    $QueryString = @()

    # Query string (begin)
        $QueryString = 
            "Resources `
            | where type == `"microsoft.hybridcompute/machines`" `
            "
    # Add Exlusions to Query string
        ForEach ($Line in $global:Query_Exclude)
            {
                $QueryString += $Line + " `n "
            }

    # Query string (end)
        $QueryString += 
            "| extend ostype = properties.osType `
            | extend provisioningState = properties.provisioningState `
            | extend licensetype = properties.licensetype `
            | extend displayname = properties.displayName `
            | extend status = properties.status `
            | extend computerName = properties.osprofile.computerName `
            | extend osVersion = properties.osVersion `
            | extend osName = properties.osName `
            | extend manufacturer = properties.detectedProperties.manufacturer `
            | extend model = properties.detectedProperties.model `
            | extend lastStatusChange = properties.lastStatusChange `
            | extend agentVersion = properties.agentVersion `
            | extend machineFqdn = properties.machineFqdn `
            | extend domainName = properties.domainName `
            | extend dnsFqdn = properties.dnsFqdn `
            | extend adFqdn = properties.adFqdn `
            | extend osSku = properties.osSku `
            | order by id, resourceGroup desc"

    $VMsInScope_All = @()
    $pageSize = 1000
    $iteration = 0
    $searchParams = @{
                        Query = $QueryString
                        First = $pageSize
                        }

    $results = do {
        $iteration += 1
        $pageResults = Search-AzGraph -ManagementGroup $Global:ManagementGroupScope @searchParams
        $searchParams.Skip += $pageResults.Count
        $VMsInScope_All += $pageResults
    } while ($pageResults.Count -eq $pageSize)

    # Results
        $Global:HybridVMsInScope_All = $VMsInScope_All
}

Function AZ_Find_All_Native_VM_Resources
{
    # Build Exclude string
    AZ_Graph_Query_Build_Exclude_String
    
    Write-Output ""
    # Find all Azure (native) VM Resources 
    Write-Output "Finding all Azure (native) VM Resources .... please Wait !"

    $QueryString = @()

    # Query string (begin)
        $QueryString = 
            "Resources `
            | where type == `"microsoft.compute/virtualmachines`" `
            "
    # Add Exlusions to Query string
        ForEach ($Line in $global:Query_Exclude)
            {
                $QueryString += $Line + " `n "
            }

    # Query string (end)
        $QueryString += 
            "| extend osType = properties.storageProfile.osDisk.osType `
            | extend osVersion = properties.extended.instanceView.osVersion `
            | extend osName = properties.extended.instanceView.osName `
            | extend vmName = properties.osProfile.computerName `
            | extend licenseType = properties.licenseType `
            | extend PowerState = properties.extended.instanceView.powerState.displayStatus `
            | order by id, resourceGroup desc"

    $VMsInScope_All = @()
    $pageSize = 1000
    $iteration = 0
    $searchParams = @{
                        Query = $QueryString
                        First = $pageSize
                        }

    $results = do {
        $iteration += 1
        $pageResults = Search-AzGraph -ManagementGroup $Global:ManagementGroupScope @searchParams
        $searchParams.Skip += $pageResults.Count
        $VMsInScope_All += $pageResults
    } while ($pageResults.Count -eq $pageSize)

    # Results
        $Global:NativeVMsInScope_All = $VMsInScope_All
}

Function AZ_Graph_Query_Build_Exclude_String
{
    $global:Query_Exclude = @()

    # Subscription
    ForEach ($Sub in $global:Exclude_Subscriptions)
        {
            $global:Query_Exclude    += "| where (subscriptionId !~ `"$Sub`")"
        }
    # ResourceGroup
    ForEach ($RessGrp in $global:Exclude_ResourceGroups)
        {
            $global:Query_Exclude    += "| where (resourceGroup !~ `"$RessGrp`")"
        }
    # Resource
    ForEach ($RessourceName in $global:Exclude_Resource)
        {
            $global:Query_Exclude    += "| where (name !~ `"$RessourceName`")"
        }
    # Resource_contains
    ForEach ($RessourceName in $global:Exclude_Resource_contains)
        {
            $global:Query_Exclude    += "| where (name !contains `"$RessourceName`")"
        }

    # Resource_startwith
    ForEach ($RessourceName in $global:Exclude_Resource_startswith)
        {
            $global:Query_Exclude    += "| where (name !startswith `"$RessourceName`")"
        }
    # Resource_endwith
    ForEach ($RessourceName in $global:Exclude_Resource_endswith)
        {
            $global:Query_Exclude    += "| where (name !endswith `"$RessourceName`")"
        }
}

Function Build_Computer_Array_InScope
{
    Write-Output ""
    Write-Output "Building list with information about computers in scope ... Please Wait !"
    # Default variables
    $Global:Scope_ComputerName            = ""
    $Global:Scope_Id                      = ""
    $Global:Scope_ResourceGroup           = ""
    $Global:Scope_Subscription            = ""
    $Global:Scope_Location                = ""
    $Global:Scope_ComputerPlatform        = ""
    $global:Scope_Type                    = ""
    $global:Scope_Tags                    = ""
    $global:Scope_OsOffer                 = ""
    $global:Scope_OsSku                   = ""
    $global:Scope_OsName                  = ""
    $global:Scope_OSType                  = ""
    $global:Scope_OSVersion               = ""
    $global:Scope_Tags                    = ""
    $global:Scope_hostName                = ""
    $global:Scope_adFqdn                  = ""
    $global:Scope_DomainName              = ""
    $global:Scope_MachineFqdn             = ""
    $global:Scope_Model                   = ""
    $global:Scope_Manufacturer            = ""
    $global:Scope_ProvisioningState       = ""
    $global:Scope_LicenseType             = ""
    $global:Scope_Status                  = ""

    $Global:Scope_Computer_Array = @()

    # Enum all native VMs properties - building array

            ForEach ($VMInfo in $Global:NativeVMsInScope_All)
            {
                $Global:Scope_ComputerName            = $VMInfo.name
                $Global:Scope_Id                      = $VMInfo.id
                $Global:Scope_ResourceGroup           = $VMInfo.resourceGroup
                $Global:Scope_Subscription            = $VMinfo.subscriptionId
                $Global:Scope_Location                = $VMInfo.location
                $Global:Scope_ComputerPlatform        = "Native"
                $global:Scope_Type                    = $VMInfo.type      
                $global:Scope_OsOffer                 = $VMInfo.osVersion 
                $global:Scope_OsSku                   = $VMInfo.osVersion 
                $global:Scope_OsName                  = $VMInfo.osName    
                $global:Scope_OSType                  = $VMInfo.osType    
                $global:Scope_OSVersion               = $VMInfo.osVersion 
                $global:Scope_Tags                    = $VMInfo.tags
                $global:Scope_Model                   = $VMInfo.properties.hardwareprofile.vmSize
                $global:Scope_Manufacturer            = "Microsoft"
                $global:Scope_ProvisioningState       = $VMInfo.properties.provisioningState
                $global:Scope_LicenseType             = $VMInfo.licensetype
                $global:Scope_Status                  = $VMInfo.PowerState

                $ComputerInfo = New-Object PSObject
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Global:Scope_ComputerName -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Id -Value $Global:Scope_Id -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $Global:Scope_ResourceGroup -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Subscription -Value $Global:Scope_Subscription -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Location -Value $Global:Scope_Location -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name ComputerPlatform -Value $Global:Scope_ComputerPlatform -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Type -Value $global:Scope_Type -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsOffer -Value $global:Scope_OsOffer -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsSku -Value $global:Scope_OsSku -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsName -Value $global:Scope_OsName -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsType -Value $global:Scope_OSType -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsVersion -Value $global:Scope_OSVersion -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Tags -Value $global:Scope_Tags -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name AdFqdn -Value $global:Scope_AdFqdn -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name DomainName -Value $global:Scope_DomainName -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Model -Value $global:Scope_Model -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Manufacturer -Value $global:Scope_Manufacturer -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name ProvisioningState -Value $global:Scope_ProvisioningState -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name LicenseType -Value $global:Scope_LicenseType -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Status -Value $global:Scope_Status -Force

                # Adding to array
                $Global:Scope_Computer_Array += $ComputerInfo
            }

    # Enum all Hybrid Computer properties - building array
        ForEach ($VMInfo in $Global:HybridVMsInScope_All)
            {
                $Global:Scope_ComputerName            = $VMInfo.name
                $Global:Scope_Id                      = $VMInfo.id
                $Global:Scope_ResourceGroup           = $VMInfo.resourceGroup
                $Global:Scope_Subscription            = $VMinfo.subscriptionId
                $Global:Scope_Location                = $VMInfo.location
                $Global:Scope_ComputerPlatform        = "Hybrid"
                $global:Scope_Type                    = $VMInfo.type      
                $global:Scope_OsOffer                 = $VMInfo.osOffer   
                $global:Scope_OsSku                   = $VMInfo.osSku     
                $global:Scope_OsName                  = $VMInfo.osSku     
                $global:Scope_OSType                  = $VMInfo.osType    
                $global:Scope_OSVersion               = $VMInfo.osVersion 
                $global:Scope_Tags                    = $VMInfo.tags
                $global:Scope_AdFqdn                  = $VMInfo.adFqdn
                $global:Scope_DomainName              = $VMInfo.domainName
                $global:Scope_Model                   = $VMInfo.model
                $global:Scope_Manufacturer            = $VMInfo.manufacturer
                $global:Scope_ProvisioningState       = $VMInfo.provisioningState
                $global:Scope_LicenseType             = $VMInfo.licensetype
                $global:Scope_Status                  = $VMInfo.Status

                $ComputerInfo = New-Object PSObject
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Global:Scope_ComputerName -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Id -Value $Global:Scope_Id -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $Global:Scope_ResourceGroup -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Subscription -Value $Global:Scope_Subscription -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Location -Value $Global:Scope_Location -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name ComputerPlatform -Value $Global:Scope_ComputerPlatform -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Type -Value $global:Scope_Type -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsOffer -Value $global:Scope_OsOffer -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsSku -Value $global:Scope_OsSku -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsName -Value $global:Scope_OsName -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsType -Value $global:Scope_OSType -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name OsVersion -Value $global:Scope_OSVersion -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Tags -Value $global:Scope_Tags -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name AdFqdn -Value $global:Scope_AdFqdn -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name DomainName -Value $global:Scope_DomainName -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Model -Value $global:Scope_Model -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Manufacturer -Value $global:Scope_Manufacturer -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name ProvisioningState -Value $global:Scope_ProvisioningState -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name LicenseType -Value $global:Scope_LicenseType -Force
                $ComputerInfo | Add-Member -MemberType NoteProperty -Name Status -Value $global:Scope_Status -Force

                # Adding to array
                $Global:Scope_Computer_Array += $ComputerInfo
            }
}


#------------------------------------------------------------------------------------------------------------
# Connect to Azure
#------------------------------------------------------------------------------------------------------------
Connect-AzAccount

#---------------------------------------------------------
# Get Access Token for REST api
#---------------------------------------------------------
$AccessToken = Get-AzAccessToken -ResourceUrl https://management.azure.com/
$AccessToken = $AccessToken.Token

$Header = @{
                "Authorization"="Bearer $($AccessToken)"
            }


#------------------------------------------------------------------------------------------------------------
# Variables
#------------------------------------------------------------------------------------------------------------

# Scope (MG) | You can define the scope for the targetting, supporting management groups or tenant root id (all subs)
$Global:ManagementGroupScope                                = "xxxx" # can mg e.g. mg-company or AAD Id (=Tenant Root Id)

# Exclude list | You can exclude certain subs, resource groups, resources, if you don't want to have them as part of the scope
$global:Exclude_Subscriptions                               = @("xxxxxxxxxxxxxxxxxxxxxx") # for example platform-connectivity
$global:Exclude_ResourceGroups                              = @()
$global:Exclude_Resource                                    = @()
$global:Exclude_Resource_Contains                           = @()
$global:Exclude_Resource_Startswith                         = @("PCTXRDS","RCTXRDS")
$global:Exclude_Resource_Endswith                           = @()


#--------------------------------------------------------------------------------------------------------
# Scope - subscriptions - where to look for Azure VMs and Azure Arc servers
#--------------------------------------------------------------------------------------------------------

# Retrieving data using Azure ARG
AZ_Find_Subscriptions_in_Tenant_With_Subscription_Exclusions

# Filter - only lists ENABLED subscriptions
$Global:Subscriptions_in_Scope = $Global:Subscriptions_in_Scope | Where-Object {$_.status -eq "Enabled"}

Write-Output "Scope (target)"

$Global:Subscriptions_in_Scope


#--------------------------------------------------------------------------------------------------------
# Get list of VMs and detect VMs - excluding any resources defined in variables (sub/rg/resources)
#--------------------------------------------------------------------------------------------------------

# Retrieving data using Azure ARG
write-output ""
Write-output "Getting list of VMs ... Please Wait !"
write-output ""

# Get list of all VMs
AZ_Find_All_Hybrid_VM_Resources
AZ_Find_All_Native_VM_Resources
Build_Computer_Array_InScope

# Scope (servers)
$Global:Scope_Computer_Array

#-----------------------------------------------------------------------------------
# Main Program
#-----------------------------------------------------------------------------------

    $MdeTvmArray = @()
    $QualysArray = @()

    ForEach ($VM in $Global:Scope_Computer_Array)
        {
                Write-Output ""
                Write-Output "Checking $($Vm.ComputerName) for vulnerability assessment solution ... Please Wait !"

                    $Uri = "https://management.azure.com$($VM.Id)/providers/Microsoft.Security/serverVulnerabilityAssessments?api-version=2015-06-01-preview"
                    $VA_Status = Invoke-RestMethod $uri -Method GET -Headers $Header -ContentType "application/json" -ErrorAction SilentlyContinue


                # Check if VM has been enabled with Qualys as Server Vulnerability Assessment solution
                    $Uri = "https://management.azure.com$($VM.Id)/providers/Microsoft.Security/serverVulnerabilityAssessments/default?api-version=2015-06-01-preview"
                    $StatusQualys = $null
                    Try
                        {
                            $StatusQualys = Invoke-RestMethod $uri -Method GET -Headers $Header -ContentType "application/json" -ErrorAction SilentlyContinue
                        }
                    Catch
                        {
                        }

                    $QualysArray += $StatusQualys

                    If ($StatusQualys.properties.provisioningState -eq "Succeeded")
                        {
                            Write-Output "  Deprovisioning Qualys Vulnerability Assessment on resource $($VM.ComputerName)"
                            $Uri = "https://management.azure.com$($VM.Id)/providers/Microsoft.Security/serverVulnerabilityAssessments/default?api-version=2015-06-01-preview"

                            $Delete = Invoke-RestMethod $uri -Method DELETE -Headers $Header -ContentType "application/json" -ErrorAction SilentlyContinue
                        }
                                        

                # Check if VM has been enabled for MdeTvm as Server Vulnerability Assessment solution
                    $Uri = "https://management.azure.com$($VM.Id)/providers/Microsoft.Security/serverVulnerabilityAssessments/mdetvm?api-version=2015-06-01-preview"

                    Try
                        {
                            $StatusMdeTvm = Invoke-RestMethod $uri -Method GET -Headers $Header -ContentType "application/json" -ErrorAction SilentlyContinue
                        }
                    Catch
                        {
                            Write-Output "  Enabling MdeTvm Vulnerability Assessment on $($VM.ComputerName)"
                            $Uri = "https://management.azure.com$($VM.Id)/providers/Microsoft.Security/serverVulnerabilityAssessments/mdetvm?api-version=2015-06-01-preview"

                            $Update = Invoke-RestMethod $uri -Method PUT -Headers $Header -ContentType "application/json"
                        }

                    $MdeTvmArray += $StatusMdeTvm

                    If ( ($StatusMdeTvm.properties.provisioningState -eq "Succeeded") -and ($StatusMdeTvm.name -eq "MdeTvm") )
                        {
                            Write-Output "  MdeTvm Vulnerability Assessment solution already enabled on resource $($VM.ComputerName) ... skipping !"
                        }
                    Elseif ( (!$StatusQualys) -and (!$StatusMdeTvm) )
                        {
                            Write-Output ""
                            Write-Output "  Enabling MdeTvm Vulnerability Assessment on $($VM.ComputerName)"
                            $Uri = "https://management.azure.com$($VM.Id)/providers/Microsoft.Security/serverVulnerabilityAssessments/mdetvm?api-version=2015-06-01-preview"

                            $Update = Invoke-RestMethod $uri -Method PUT -Headers $Header -ContentType "application/json"
                        }
        }
