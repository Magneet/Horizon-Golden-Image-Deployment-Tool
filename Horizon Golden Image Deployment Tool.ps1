[cmdletbinding()]
param()

$Global:ProgressPreference = 'SilentlyContinue'
$global:WarningPreference = 'SilentlyContinue'

#region XAML_to_PS
function Add-ControlVariables {
    New-Variable -Name 'config_save_config_button' -Value $window.FindName('config_save_config_button') -Scope 1 -Force	
    New-Variable -Name 'config_reset_config_button' -Value $window.FindName('config_reset_config_button') -Scope 1 -Force	
    New-Variable -Name 'config_test_credential_button' -Value $window.FindName('config_test_credential_button') -Scope 1 -Force	
    New-Variable -Name 'config_pod_combobox' -Value $window.FindName('config_pod_combobox') -Scope 1 -Force
    New-Variable -Name 'config_credential_label' -Value $window.FindName('config_credential_label') -Scope 1 -Force
    New-Variable -Name 'config_conserver_textbox' -Value $window.FindName('config_conserver_textbox') -Scope 1 -Force
    New-Variable -Name 'config_username_textbox' -Value $window.FindName('config_username_textbox') -Scope 1 -Force
    New-Variable -Name 'config_domain_textbox' -Value $window.FindName('config_domain_textbox') -Scope 1 -Force
    New-Variable -Name 'config_passwordbox' -Value $window.FindName('config_passwordbox') -Scope 1 -Force
    New-Variable -Name 'config_conserver_combobox' -Value $window.FindName('config_conserver_combobox') -Scope 1 -Force
    New-Variable -Name 'config_ignore_cert_errors_checkbox' -Value $window.FindName('config_ignore_cert_errors_checkbox') -Scope 1 -Force
    New-Variable -Name 'VDI_Connect_Button' -Value $window.FindName('VDI_Connect_Button') -Scope 1 -Force
    New-Variable -Name 'VDI_Statusbox_Label' -Value $window.FindName('VDI_Statusbox_Label') -Scope 1 -Force
    New-Variable -Name 'VDI_DesktopPool_Combobox' -Value $window.FindName('VDI_DesktopPool_Combobox') -Scope 1 -Force
    New-Variable -Name 'VDI_Golden_Image_Combobox' -Value $window.FindName('VDI_Golden_Image_Combobox') -Scope 1 -Force
    New-Variable -Name 'VDI_Snapshot_Combobox' -Value $window.FindName('VDI_Snapshot_Combobox') -Scope 1 -Force
    New-Variable -Name 'VDI_secondaryimage_checkbox' -Value $window.FindName('VDI_secondaryimage_checkbox') -Scope 1 -Force
    New-Variable -Name 'VDI_Apply_Golden_Image_button' -Value $window.FindName('VDI_Apply_Golden_Image_button') -Scope 1 -Force
    New-Variable -Name 'VDI_Cancel_Secondary_Image_button' -Value $window.FindName('VDI_Cancel_Secondary_Image_button') -Scope 1 -Force
    New-Variable -Name 'VDI_Promote_Secondary_Image_button' -Value $window.FindName('VDI_Promote_Secondary_Image_button') -Scope 1 -Force
    New-Variable -Name 'VDI_vtpm_checkbox' -Value $window.FindName('VDI_vtpm_checkbox') -Scope 1 -Force
    New-Variable -Name 'VDI_StopOnError_checkbox' -Value $window.FindName('VDI_StopOnError_checkbox') -Scope 1 -Force
    New-Variable -Name 'VDI_LofOffPolicy_Combobox' -Value $window.FindName('VDI_LofOffPolicy_Combobox') -Scope 1 -Force
    New-Variable -Name 'VDI_Resize_checkbox' -Value $window.FindName('VDI_Resize_checkbox') -Scope 1 -Force
    New-Variable -Name 'VDI_Memory_ComboBox' -Value $window.FindName('VDI_Memory_ComboBox') -Scope 1 -Force 
    New-Variable -Name 'VDI_CPUCount_ComboBox' -Value $window.FindName('VDI_CPUCount_ComboBox') -Scope 1 -Force
    New-Variable -Name 'VDI_CoresPerSocket_ComboBox' -Value $window.FindName('VDI_CoresPerSocket_ComboBox') -Scope 1 -Force
    New-Variable -Name 'VDI_Enable_datetimepicker_checkbox' -Value $window.FindName('VDI_Enable_datetimepicker_checkbox') -Scope 1 -Force
    New-Variable -Name 'VDI_datepicker' -Value $window.FindName('VDI_datepicker') -Scope 1 -Force
    New-Variable -Name 'VDI_timepicker_hour_combobox' -Value $window.FindName('VDI_timepicker_hour_combobox') -Scope 1 -Force
    New-Variable -Name 'VDI_timepicker_minute_combobox' -Value $window.FindName('VDI_timepicker_minute_combobox') -Scope 1 -Force
    New-Variable -Name 'VDI_Status_Textblock' -Value $window.FindName('VDI_Status_Textblock') -Scope 1 -Force
    New-Variable -Name 'VDI_Machines_ListBox' -Value $window.FindName('VDI_Machines_ListBox') -Scope 1 -Force
    New-Variable -Name 'VDI_Apply_Secondary_Image_button' -Value $window.FindName('VDI_Apply_Secondary_Image_button') -Scope 1 -Force
    New-Variable -Name 'RDS_Connect_Button' -Value $window.FindName('RDS_Connect_Button') -Scope 1 -Force
    New-Variable -Name 'RDS_Statusbox_Label' -Value $window.FindName('RDS_Statusbox_Label') -Scope 1 -Force
    New-Variable -Name 'RDS_Farm_Combobox' -Value $window.FindName('RDS_Farm_Combobox') -Scope 1 -Force
    New-Variable -Name 'RDS_Golden_Image_Combobox' -Value $window.FindName('RDS_Golden_Image_Combobox') -Scope 1 -Force
    New-Variable -Name 'RDS_Snapshot_Combobox' -Value $window.FindName('RDS_Snapshot_Combobox') -Scope 1 -Force
    New-Variable -Name 'RDS_secondaryimage_checkbox' -Value $window.FindName('RDS_secondaryimage_checkbox') -Scope 1 -Force
    New-Variable -Name 'RDS_Apply_Golden_Image_button' -Value $window.FindName('RDS_Apply_Golden_Image_button') -Scope 1 -Force
    New-Variable -Name 'RDS_Cancel_Secondary_Image_button' -Value $window.FindName('RDS_Cancel_Secondary_Image_button') -Scope 1 -Force
    New-Variable -Name 'RDS_Promote_Secondary_Image_button' -Value $window.FindName('RDS_Promote_Secondary_Image_button') -Scope 1 -Force
    New-Variable -Name 'RDS_StopOnError_checkbox' -Value $window.FindName('RDS_StopOnError_checkbox') -Scope 1 -Force
    New-Variable -Name 'RDS_LofOffPolicy_Combobox' -Value $window.FindName('RDS_LofOffPolicy_Combobox') -Scope 1 -Force
    New-Variable -Name 'RDS_Resize_checkbox' -Value $window.FindName('RDS_Resize_checkbox') -Scope 1 -Force
    New-Variable -Name 'RDS_Memory_ComboBox' -Value $window.FindName('RDS_Memory_ComboBox') -Scope 1 -Force
    New-Variable -Name 'RDS_CPUCount_ComboBox' -Value $window.FindName('RDS_CPUCount_ComboBox') -Scope 1 -Force
    New-Variable -Name 'RDS_CoresPerSocket_ComboBox' -Value $window.FindName('RDS_CoresPerSocket_ComboBox') -Scope 1 -Force
    New-Variable -Name 'RDS_Enable_datetimepicker_checkbox' -Value $window.FindName('RDS_Enable_datetimepicker_checkbox') -Scope 1 -Force
    New-Variable -Name 'RDS_datepicker' -Value $window.FindName('RDS_datepicker') -Scope 1 -Force
    New-Variable -Name 'RDS_timepicker_hour_combobox' -Value $window.FindName('RDS_timepicker_hour_combobox') -Scope 1 -Force
    New-Variable -Name 'RDS_timepicker_minute_combobox' -Value $window.FindName('RDS_timepicker_minute_combobox') -Scope 1 -Force
    New-Variable -Name 'RDS_Status_Textblock' -Value $window.FindName('RDS_Status_Textblock') -Scope 1 -Force
    New-Variable -Name 'RDS_Apply_Secondary_Image_button' -Value $window.FindName('RDS_Apply_Secondary_Image_button') -Scope 1 -Force
    New-Variable -Name 'RDS_Machines_ListBox' -Value $window.FindName('RDS_Machines_ListBox') -Scope 1 -Force
}
[System.Reflection.Assembly]::LoadWithPartialName("PresentationFramework") | Out-Null

function Import-Xaml {
    [xml]$xaml = Get-Content -Path "$PSScriptRoot\Horizon Golden Image Deployment Tool.xaml"
    $manager = New-Object System.Xml.XmlNamespaceManager -ArgumentList $xaml.NameTable
    $manager.AddNamespace("x", "http://schemas.microsoft.com/winfx/2006/xaml");
    $xaml.SelectNodes("//*[@x:Name='config_save_config_button']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='config_reset_config_button']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='config_test_credential_button']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='config_pod_combobox']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='config_ignore_cert_errors_checkbox']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='config_conserver_textbox']", $manager)[0].RemoveAttribute('IsKeyboardFocusedChanged')
    $xaml.SelectNodes("//*[@x:Name='config_pod_combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_Connect_Button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='VDI_DesktopPool_Combobox']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='VDI_Golden_Image_Combobox']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='VDI_Snapshot_Combobox']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='VDI_DesktopPool_Combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_Golden_Image_Combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_Snapshot_Combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_LofOffPolicy_Combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_Apply_Golden_Image_button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='VDI_Cancel_Secondary_Image_button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='VDI_Promote_Secondary_Image_button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='VDI_Memory_ComboBox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_timepicker_hour_combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_timepicker_minute_combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_CPUCount_ComboBox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_CoresPerSocket_ComboBox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_Machines_ListBox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='VDI_Apply_Secondary_Image_button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='RDS_Connect_Button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='RDS_Farm_Combobox']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='RDS_Golden_Image_Combobox']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='RDS_Snapshot_Combobox']", $manager)[0].RemoveAttribute('Click')
    $xaml.SelectNodes("//*[@x:Name='RDS_Farm_Combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_Golden_Image_Combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_Snapshot_Combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_LofOffPolicy_Combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_Apply_Golden_Image_button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='RDS_Cancel_Secondary_Image_button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='RDS_Promote_Secondary_Image_button']", $manager)[0].RemoveAttribute('click')
    $xaml.SelectNodes("//*[@x:Name='RDS_Memory_ComboBox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_timepicker_hour_combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_timepicker_minute_combobox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_CPUCount_ComboBox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_CoresPerSocket_ComboBox']", $manager)[0].RemoveAttribute('SelectionChanged')
    $xaml.SelectNodes("//*[@x:Name='RDS_Apply_Secondary_Image_button']", $manager)[0].RemoveAttribute('click')
    $xamlReader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($xamlReader)
    return $window
}

#ERROR: You need to define the x:Name attribute for this control to generate an event handler.


function Set-EventHandler {

    $config_reset_config_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            reset_config_click -sender $sender -e $e
        })
    $config_save_config_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            save_config_click -sender $sender -e $e
        })
    $config_test_credential_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            test-credential-click -sender $sender -e $e
        })
    $config_ignore_cert_errors_checkbox.Add_Checked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            config_ignore_cert_errors_checkbox_ischecked -sender $sender -e $e
        })
    $config_ignore_cert_errors_checkbox.Add_UnChecked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            config_ignore_cert_errors_checkbox_unchecked -sender $sender -e $e
        })
    $VDI_Connect_Button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_Connect_Button_click -sender $sender -e $e
        })
    $config_pod_combobox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            config_pod_combobox_selectionchanged -sender $sender -e $e
        })
    $VDI_DesktopPool_Combobox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            VDI_DesktopPool_Combobox_selectionchanged -sender $sender -e $e
        })
    $VDI_Golden_Image_Combobox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            VDI_Golden_Image_Combobox_selectionchanged -sender $sender -e $e
        })
    $VDI_Apply_Golden_Image_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_Apply_Golden_Image_button_click -sender $sender -e $e
        })
    $VDI_Cancel_Secondary_Image_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            send-status -Status "INFORMATIONAL" -message "VDI_Cancel_Secondary_Image_button was clicked"
            VDI_Cancel_Secondary_Image_push_button_click -sender $sender -e $e
        })
    $VDI_Promote_Secondary_Image_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_Promote_Secondary_Image_button_click -sender $sender -e $e
        })
    $VDI_Snapshot_Combobox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            VDI_Snapshot_Combobox_selectionchanged -sender $sender -e $e
        })
    $VDI_Resize_checkbox.Add_Checked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_Resize_checkbox_Checked -sender $sender -e $e
        })
    $VDI_Resize_checkbox.Add_UnChecked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_Resize_checkbox_UnChecked -sender $sender -e $e
        })
    $VDI_Enable_datetimepicker_checkbox.Add_Checked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_Enable_datetimepicker_checkbox_checked -sender $sender -e $e
        })
    $VDI_Enable_datetimepicker_checkbox.Add_UnChecked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_Enable_datetimepicker_checkbox_unchecked -sender $sender -e $e
        })
    $VDI_secondaryimage_checkbox.Add_Checked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_secondaryimage_checkbox_checked -sender $sender -e $e
        })
    $VDI_secondaryimage_checkbox.Add_UnChecked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_secondaryimage_checkbox_unchecked -sender $sender -e $e
        })
    $VDI_Apply_Secondary_Image_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            VDI_Apply_Secondary_Image_button_click -sender $sender -e $e
        })
    $VDI_CPUCount_ComboBox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            VDI_CPUCount_ComboBox_selectionchanged -sender $sender -e $e
        })
    $VDI_CoresPerSocket_ComboBox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            VDI_CoresPerSocket_ComboBox_selectionchanged -sender $sender -e $e
        })
    $VDI_Memory_ComboBox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            VDI_Memory_ComboBox_selectionchanged -sender $sender -e $e
        })
    $RDS_Connect_Button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Connect_Button_click -sender $sender -e $e
        })
    $RDS_Farm_Combobox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            RDS_Farm_Combobox_selectionchanged -sender $sender -e $e
        
        })
    $RDS_Golden_Image_Combobox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            RDS_Golden_Image_Combobox_selectionchanged -sender $sender -e $e
        })
    $RDS_Apply_Golden_Image_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Apply_Golden_Image_button_click -sender $sender -e $e
        })
    $RDS_Cancel_Secondary_Image_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Cancel_Secondary_Image_button_click -sender $sender -e $e
        })
    $RDS_Promote_Secondary_Image_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Promote_Secondary_Image_button_click -sender $sender -e $e
        })
    $RDS_Snapshot_Combobox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            RDS_Snapshot_Combobox_selectionchanged -sender $sender -e $e
        })
    $RDS_Resize_checkbox.Add_Checked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Resize_checkbox_Checked -sender $sender -e $e
        })
    $RDS_Resize_checkbox.Add_UnChecked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Resize_checkbox_UnChecked -sender $sender -e $e
        })
    $RDS_Enable_datetimepicker_checkbox.Add_Checked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Enable_datetimepicker_checkbox_checked -sender $sender -e $e
        })
    $RDS_Enable_datetimepicker_checkbox.Add_UnChecked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Enable_datetimepicker_checkbox_unchecked -sender $sender -e $e
        })
    $RDS_Apply_Secondary_Image_button.add_Click({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_Apply_Secondary_Image_button_click -sender $sender -e $e
        })
    $RDS_secondaryimage_checkbox.Add_Checked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_secondaryimage_checkbox_checked -sender $sender -e $e
        })
    $RDS_secondaryimage_checkbox.Add_UnChecked({
            param([System.Object]$sender, [System.Windows.RoutedEventArgs]$e)
            RDS_secondaryimage_checkbox_unchecked -sender $sender -e $e
        })
    $RDS_CPUCount_ComboBox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            RDS_CPUCount_ComboBox_selectionchanged -sender $sender -e $e
        })
    $RDS_CoresPerSocket_ComboBox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            RDS_CoresPerSocket_ComboBox_selectionchanged -sender $sender -e $e
        })
    $RDS_Memory_ComboBox.add_SelectionChanged({
            param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
            RDS_Memory_ComboBox_selectionchanged -sender $sender -e $e
        })
}
#endregion

#region Common_Functions

Function send-status {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Message,
        [Parameter()]
        [ValidateSet("INFORMATIONAL", "ERROR", "WARNING")]
        [string]$Status
    )
    $Status = $status.ToUpper()
    $timestamp = Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }
    $outputmessage = "$timestamp $Status : $message"
    if ($script:verboselogging) {
        Write-Verbose -message $outputmessage
    }
    $script:log.add($outputmessage)  | out-null
}

function store-status {
    Add-Content $LogFilePath $script:log -force
    $script:log.clear() 
}

function get-noteproperty {
    param($noteproperty)
    $noteproperty | get-member -type NoteProperty | foreach-object {
        $name = $_.Name ; 
        $value = $noteproperty."$($_.Name)"
        send-status -Status "INFORMATIONAL" -message "$name = $value"
    }
}

function Get-HRHeader() {
    param($accessToken)
    return @{
        'Authorization' = 'Bearer ' + $($accessToken.access_token)
        'Content-Type'  = "application/json"
    }
}

function Open-HRConnection() {
    param(
        [string] $ConnectionServerURL
    )
    $Credentials = New-Object psobject -Property @{
        username = ($configuration.Credentialsobject).username
        password = [System.Net.NetworkCredential]::new("", ($Configuration.Credentialsobject).password).Password
        domain   = ($configuration.Credentialsobject).domain
    }
    $domain = $Credentials.domain
    $username = $credentials.username
    $password = $Credentials.password
    send-status -Status "INFORMATIONAL" -message "Connecting to $serverurl as $domain\$username"
    try {
        if ($config_ignore_cert_errors_checkbox.isChecked -eq $true) {
            $result = invoke-restmethod -Method Post -uri "$ConnectionServerURL/rest/login" -ContentType "application/json" -Body ($Credentials | ConvertTo-Json) -SkipCertificateCheck -HttpVersion 3.0
            send-status -Status "INFORMATIONAL" -message "Successfully logged on"
        }
        else {
            $result = invoke-restmethod -Method Post -uri "$ConnectionServerURL/rest/login" -ContentType "application/json" -Body ($Credentials | ConvertTo-Json) -HttpVersion 3.0
            send-status -Status "INFORMATIONAL" -message "Successfully logged on"
        }
        send-status -Status "INFORMATIONAL" -message "Connection successfull."
        return $result
    }
    catch {
        send-status -Status "ERROR" -message "Error Connecting: $_"
        write-error -Message "Error Connecting: $_"
    }
}

function Close-HRConnection() {
    param(
        $refreshToken,
        $ConnectionServerURL
    )
    send-status -Status "INFORMATIONAL" -message  " Closing connection with $ConnectionServerURL"
    if ($config_ignore_cert_errors_checkbox.isChecked -eq $true) {
        return Invoke-RestMethod -Method post -uri "$ConnectionServerURL/rest/logout" -ContentType "application/json" -Body ($refreshToken | ConvertTo-Json) -SkipCertificateCheck -HttpVersion 3.0
        send-status -Status "INFORMATIONAL" -message "Logging off successfull"
    }
    else {
        return Invoke-RestMethod -Method post -uri "$ConnectionServerURL/rest/logout" -ContentType "application/json" -Body ($refreshToken | ConvertTo-Json) -HttpVersion 3.0
        send-status -Status "INFORMATIONAL" -message "Logging off successfull"
    }
}

function Refresh-HRConnection() {
    param(
        $refreshToken,
        $ConnectionServerURL
    )
    if ($config_ignore_cert_errors_checkbox.isChecked -eq $true) {
        return Invoke-RestMethod -Method post -uri "$ConnectionServerURL/rest/refresh" -ContentType "application/json" -Body ($refreshToken | ConvertTo-Json) -SkipCertificateCheck -HttpVersion 3.0
        send-status -Status "INFORMATIONAL" -message "Logging refreshed connection successfull"
    }
    else {
        return Invoke-RestMethod -Method post -uri "$ConnectionServerURL/rest/refresh" -ContentType "application/json" -Body ($refreshToken | ConvertTo-Json) -HttpVersion 3.0
        send-status -Status "INFORMATIONAL" -message "Logging refreshed connection successfull"
    }
}

function connect-hvpod() {
    param($PodName)
    send-status -Status "INFORMATIONAL" -message "trying to find a working connection server"
    [array]$conservers = $Configuration.ServerArray | Where-Object { $_.PodName -eq "$podname" } | select -expandproperty ServerDNS
    $count = $conservers.count
    $start = 0
    $result = "None"
    do {
        send-status -Status "INFORMATIONAL" -message  "Attempt: $start"
        $conserver = $conservers[$start]
        $serverurl = "https://$conserver"
        if ((Test-netConnection $conserver -port 443 -InformationLevel quiet) -eq $true) {
            $login_tokens = Open-HRConnection -ConnectionServerURL $serverurl
        }
        else {
            $login_tokens = $null
        }
        if ($null -ne $login_tokens) {
            $result = "Success"
            $Configuration.LastSelectedConnectionServer = $conserver
            send-status -Status "INFORMATIONAL" -message "Connected using $conserver"
            return $login_tokens
        }
        else {
            $result = "None"
            $start++
            if ($start -lt $count) {
                send-status -Status "WARNING" -message "Failed connecting to $conserver, trying the next one."
            }
            else {
                send-status -Status "ERROR" -message "Cannot find a working connection server for $podname"
                $result = "Failure"
                return $result
            }
        }

    }
    until(($result -eq "Success") -or ($result -eq "Failure"))
}

function Get-HorizonRestData() {
    [CmdletBinding(DefaultParametersetName = 'None')] 
    param(
        [Parameter(Mandatory = $true,
            HelpMessage = 'url to the server i.e. https://pod1cbr1.loft.lab' )]
        [string] $ConnectionServerURL,

        [Parameter(Mandatory = $false,
            ParameterSetName = "filteringandpagination",
            HelpMessage = 'Array of ordered hashtables' )]
        [array] $filters,

        [Parameter(Mandatory = $false,
            ParameterSetName = "filteringandpagination",
            HelpMessage = 'Type of filter Options: And, Or' )]
        [ValidateSet('And', 'Or', IgnoreCase = $false)]
        [string] $Filtertype,

        [Parameter(Mandatory = $false,
            ParameterSetName = "filteringandpagination",
            HelpMessage = 'Page size, default = 500' )]
        [int] $pagesize = 500,

        [Parameter(Mandatory = $true,
            HelpMessage = 'Part after the url in the swagger UI i.e. /external/v1/ad-users-or-groups' )]
        [string] $RestMethod,

        [Parameter(Mandatory = $true,
            HelpMessage = 'Part after the url in the swagger UI i.e. /external/v1/ad-users-or-groups' )]
        [PSCustomObject] $accessToken,

        [Parameter(Mandatory = $false,
            ParameterSetName = "filteringandpagination",
            HelpMessage = '$True for rest methods that contain pagination and filtering, default = False' )]
        [switch] $filteringandpagination,

        [Parameter(Mandatory = $false,
            ParameterSetName = "id",
            HelpMessage = 'To be used with single id based queries like /monitor/v1/connection-servers/{id}' )]
        [string] $id
    )
    if ($filteringandpagination) {
        if ($filters) {
            $filterhashtable = [ordered]@{}
            $filterhashtable.add('type', $filtertype)
            $filterhashtable.filters = @()
            foreach ($filter in $filters) {
                $filterhashtable.filters += $filter
            }
            $filterflat = $filterhashtable | convertto-json -Compress
            $urlstart = $ConnectionServerURL + "/rest/" + $RestMethod + "?filter=" + $filterflat + "&page="
        }
        else {
            $urlstart = $ConnectionServerURL + "/rest/" + $RestMethod + "?page="
        }
        $results = [System.Collections.ArrayList]@()
        $page = 1
        $uri = $urlstart + $page + "&size=$pagesize"
        if ($config_ignore_cert_errors_checkbox.isChecked -eq $true) {
            send-status -Status "INFORMATIONAL" -message "Getting data from $uri"
            $response = Invoke-RestMethod $uri -Method 'GET' -Headers (Get-HRHeader -accessToken $accessToken) -ResponseHeadersVariable responseheader -SkipCertificateCheck -HttpVersion 3.0
        }
        else {
            send-status -Status "INFORMATIONAL" -message "Getting data from $uri"
            $response = Invoke-RestMethod $uri -Method 'GET' -Headers (Get-HRHeader -accessToken $accessToken) -ResponseHeadersVariable responseheader -HttpVersion 3.0
        }
        
        $response.foreach({ $results.add($_) }) | out-null
        if ($responseheader.HAS_MORE_RECORDS -contains "TRUE") {
            do {
                $page++
                $uri = $urlstart + $page + "&size=$pagesize"
                if ($config_ignore_cert_errors_checkbox.isChecked -eq $true) {
                    send-status -Status "INFORMATIONAL" -message "Getting more data from $uri"
                    $response = Invoke-RestMethod $uri -Method 'GET' -Headers (Get-HRHeader -accessToken $accessToken) -ResponseHeadersVariable responseheader -SkipCertificateCheck -HttpVersion 3.0
                }
                else {
                    send-status -Status "INFORMATIONAL" -message "Getting more data from $uri"
                    $response = Invoke-RestMethod $uri -Method 'GET' -Headers (Get-HRHeader -accessToken $accessToken) -ResponseHeadersVariable responseheader -HttpVersion 3.0
                }
                $response.foreach({ $results.add($_) }) | out-null
            } until ($responseheader.HAS_MORE_RECORDS -notcontains "TRUE")
        }
    }
    elseif ($id) {
        $uri = $ConnectionServerURL + "/rest/" + $RestMethod + "/" + $id
        if ($config_ignore_cert_errors_checkbox.isChecked -eq $true) {
            send-status -Status "INFORMATIONAL" -message "Getting data from $uri"
            $results = Invoke-RestMethod $uri -Method 'GET' -Headers (Get-HRHeader -accessToken $accessToken) -ResponseHeadersVariable responseheader -SkipCertificateCheck -HttpVersion 3.0
        }
        else {
            send-status -Status "INFORMATIONAL" -message "Getting data from $uri"
            $results = Invoke-RestMethod $uri -Method 'GET' -Headers (Get-HRHeader -accessToken $accessToken) -ResponseHeadersVariable responseheader -HttpVersion 3.0
        }
    }
    else {
        $uri = $ConnectionServerURL + "/rest/" + $RestMethod
        if ($config_ignore_cert_errors_checkbox.isChecked -eq $true) {
            send-status -Status "INFORMATIONAL" -message "Getting data from $uri"
            $results = Invoke-RestMethod $uri -Method 'GET' -Headers (Get-HRHeader -accessToken $accessToken) -ResponseHeadersVariable responseheader -SkipCertificateCheck -HttpVersion 3.0
        }
        else {
            send-status -Status "INFORMATIONAL" -message "Getting data from $uri"
            $results = Invoke-RestMethod $uri -Method 'GET' -Headers (Get-HRHeader -accessToken $accessToken) -ResponseHeadersVariable responseheader -HttpVersion 3.0
        }
    }

    return $results
}

function invoke-hvcommand() {
    param(
        $accesstoken,
        [string]$URL,
        [array]$json,
        [string]$Method
    )
    try {
        if ($config_ignore_cert_errors_checkbox.isChecked -eq $true) {
            send-status -Status "INFORMATIONAL" -message "Skipping certificate checks"
            if ($json) {
                send-status -Status "INFORMATIONAL" -message "Invoking method $method against $URL with body $json"
                return  Invoke-RestMethod -Method $Method -uri "$URL" -ContentType "application/json" -Headers (Get-HRHeader -accessToken $accessToken) -body $json -SkipCertificateCheck
            }
            else {
                send-status -Status "INFORMATIONAL" -message "Invoking method $method against $URL"
                return Invoke-RestMethod -Method $Method -uri "$URL" -ContentType "application/json" -Headers (Get-HRHeader -accessToken $accessToken) -SkipCertificateCheck

            }
        }
        else {
            if ($json) {
                send-status -Status "INFORMATIONAL" -message "Invoking method $method against $URL with body $json"
                return Invoke-RestMethod -Method $Method -uri "$URL" -ContentType "application/json" -Headers (Get-HRHeader -accessToken $accessToken) -body $json
            }
            else {
                send-status -Status "INFORMATIONAL" -message "Invoking method $method against $URL"
                return Invoke-RestMethod -Method $Method -uri "$URL" -ContentType "application/json" -Headers (Get-HRHeader -accessToken $accessToken)
            }
        }
    }
    catch {
        return $_
    }
}

function Get-HorizonCloudPodStatus {
    param(
        $accesstoken,
        $ConnectionServerURL
    )
    send-status -Status "INFORMATIONAL" -message "Getting Horizon Cloud Pod Status"
    return  (Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $ConnectionServerURL -RestMethod "federation/v1/cpa").local_connection_server_status
}

function Get-HorizonCloudPodDetails {
    param(
        $accesstoken,
        $ConnectionServerURL
    )
    send-status -Status "INFORMATIONAL" -message "Getting Horizon Cloud Pod details"
    $CloudPodDetails = @()
    $pods = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $ConnectionServerURL -RestMethod "federation/v1/pods"
    foreach ($pod in $pods) {
        $PodName = $pod.name
        send-status -Status "INFORMATIONAL" -message "Getting details for $podname"
        $restmethod = "federation/v1/pods/" + $pod.id + "/endpoints"
        $PodDetails = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $ConnectionServerURL -RestMethod $restmethod
        foreach ($PodDetail in $PodDetails) {
            $name = $PodDetail.name 
            send-status -Status "INFORMATIONAL" -message "Creating object with details for $name"
            $server_address = $PodDetail.server_address
            $ServerDNS = ($server_address.Replace("https://", "")).split(":")[0]
            $DetailObject = [PSCustomObject]@{
                PodName   = $PodName
                Name      = $name
                ServerDNS = $ServerDNS
            }
            $CloudPodDetails += $DetailObject
        }
    }
    return $CloudPodDetails
}

function Get-HorizonNonCloudPodDetails {
    param(
        $accesstoken,
        $ConnectionServerURL,
        $ServerName
    )
    send-status -Status "INFORMATIONAL" -message "Getting Horizon Non Cloud Pod details"
    $EnvDetails = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $ConnectionServerURL -RestMethod "config/v2/environment-properties"
    $ConDetails = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $ConnectionServerURL -RestMethod "monitor/v2/connection-servers"
    $PodName = $EnvDetails.cluster_name
    send-status -Status "INFORMATIONAL" -message "Getting details for $podname"
    $PodDetails = @()
    foreach ($ConDetail in $ConDetails) {
        $name = $ConDetail.name
        send-status -Status "INFORMATIONAL" -message "Creating object with details for $name"
        $ServerDNS = $servername.replace(($servername.split(".")[0]), $name)
        send-status -Status "INFORMATIONAL" -message "Server DNS should be $ServerDNS"
        $DetailObject = [PSCustomObject]@{
            PodName   = $PodName
            Name      = $name
            ServerDNS = $ServerDNS
        }
        $PodDetails += $DetailObject
    }
    return $PodDetails
}

function DecodeBase64Image {

    param (
        [Parameter(Mandatory = $true)]
        [String]$ImageBase64
    )
    # Parameter help description
    $ObjBitmapImage = New-Object System.Windows.Media.Imaging.BitmapImage #Provides a specialized BitmapSource that is optimized for loading images using Extensible Application Markup Language (XAML).
    $ObjBitmapImage.BeginInit() #Signals the start of the BitmapImage initialization.
    $ObjBitmapImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($ImageBase64) #Creates a stream whose backing store is memory.
    $ObjBitmapImage.EndInit() #Signals the end of the BitmapImage initialization.
    $ObjBitmapImage.Freeze() #Makes the current object unmodifiable and sets its IsFrozen property to true.
    $ObjBitmapImage
}
#endregio

#region Config


Function set-credentials {
    send-status -Status "INFORMATIONAL" -message "reading credentials from the gui"
    $credentials = @{
        username = $config_username_textbox.Text;
        domain   = $config_domain_textbox.Text;
        password = $config_passwordbox.Password | ConvertTo-securestring -AsPlainText
    }
    $configuration.Credentialsobject = $credentials
    store-status
}


Function New-Configuration {
    $Script:Configuration = @{
        Credentialsobject            = ""
        ServerArray                  = ""
        LastSelectedPod              = ""
        LastSelectedConnectionServer = ""
    }
}

function reset_config_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message "Reset config button was clicked."
    send-status -Status "INFORMATIONAL" -message "Clearing Configuration"
    New-Configuration
    if (Test-Path $ConfigurationFilePath) {
        send-status -Status "INFORMATIONAL" -message "Existing configuration file found, removing."
        Get-Item -Path $ConfigurationFilePath | Remove-Item -Force
    }
    $config_pod_combobox.Items.CLear()
    $config_conserver_combobox.Items.CLear()
    $config_conserver_textbox.Text = $stdconservertext
    $config_username_textbox.Text = "UserName"
    $config_domain_textbox.Text = "Domain"
    $config_passwordbox.password = "******"
    $config_credential_label.Content = "Credentials cleared."
    store-status
}


function save_config_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message "Save Config Button was clicked"
    $Configuration.LastSelectedPod = $config_pod_combobox.SelectedItem
    $Configuration.LastSelectedConnectionServer = $config_conserver_combobox.SelectedItem

    if ($Configuration.ServerArray -eq "" -or $Configuration.Credentialsobject -eq "") {
        send-status -Status "INFORMATIONAL" -message "No Config found to save, array of servers and credentials are required."
        $config_credential_label.Content = "No configuration to save, did you click test credentials first?"
    }
    elseif (test-path -Path $Configurationfolder) {
        send-status -Status "INFORMATIONAL" -message "Configuration folder found, saving configuration to file"
        $Configuration | Export-Clixml -Path $configurationfilepath
        $config_credential_label.Content = "Configuration saved successfully."
    }
    else {
        send-status -Status "INFORMATIONAL" -message "Configuration folder not found, creating $configurationfolder"
        New-Item -Path $Configurationfolder -ItemType Directory
        send-status -Status "INFORMATIONAL" -message "Saving configuration to file."
        $Configuration | Export-Clixml -Path $configurationfilepath
        $config_credential_label.Content = "Configuration saved successfully."
    } 
    store-status
}

function test-credential-click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message "Testing credentials"
    if (($config_username_textbox.text -like "Username") -and ($config_domain_textbox.text -like "domain") -and ($config_passwordbox.password -eq "******") -and ($config_conserver_textbox.Text -eq $stdconservertext) -and !($config_conserver_combobox.SelectedItem)) {
        send-status -Status "INFORMATIONAL" -message "No custom connection Server or credentials found"
        $config_credential_label.Content = "Please enter Connection Server DNS address and credentials first."
    }
    elseif (($config_conserver_textbox.Text -eq $stdconservertext) -and !($config_conserver_combobox.SelectedItem)) {
        send-status -Status "INFORMATIONAL" -message "No custom connection Server defined and none selected either"
        $config_credential_label.Content = "Please enter Connection Server DNS address first."
    }
    elseif (($config_conserver_textbox.Text -ne $stdconservertext) -and !(Test-Connection -targetname ($config_conserver_textbox).Text -quiet)) {
        send-status -Status "WARNING" -message  "Not able to ping the Connection Server"
        $config_credential_label.Content = "Error pinging the Connection Server."
    }
    elseif (($config_username_textbox.text -notlike "Username") -and ($config_domain_textbox.text -notlike "domain") -and ($config_passwordbox.password -ne "******")) {
        send-status -Status "INFORMATIONAL" -message "Testing credentials"
        set-credentials
        if ($config_conserver_textbox.Text -ne $stdconservertext) {
            $connectionserveraddress = $config_conserver_textbox.Text
        }
        else {
            $connectionserveraddress = $config_conserver_combobox.SelectedItem
        }
        $serverurl = "https://$connectionserveraddress"
        try {
            $login_tokens = Open-HRConnection -ConnectionServerURL $serverurl
            $AccessToken = $login_tokens | Select-Object Access_token
            $RefreshToken = $login_tokens | Select-Object Refresh_token
            $CloudPodStatus = Get-HorizonCloudPodStatus -ConnectionServerURL $serverurl -accesstoken $AccessToken
            send-status -Status "INFORMATIONAL" -message "Cloud Pod Status: $cloudPodStatus"
            if ($CloudPodStatus -eq "ENABLED") {
                $CloudPodDetails = Get-HorizonCloudPodDetails -ConnectionServerURL $serverurl -accesstoken $AccessToken
                $configuration.ServerArray = $CloudPodDetails
            }
            else {
                $PodDetails = Get-HorizonNonCloudPodDetails -ConnectionServerURL $serverurl -accesstoken $AccessToken -ServerName $connectionserveraddress
                $configuration.ServerArray = $PodDetails
            }
            send-status -Status "INFORMATIONAL" -message "Logging off from $serverURL"    
            Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverurl
            send-status -Status "INFORMATIONAL" -message  "Logged off from $serverURL"
            send-status -Status "INFORMATIONAL" -message  "Connection test was a success"
            $testresult = "Success"
            $config_credential_label.Content = "Credentials tested successfully."
        }
        catch {
            send-status -Status "ERROR" -message "Connection test was a failure"
            $config_credential_label.Content = "Credentials testing failed."
            $testresult = "Failure"
        }
        $Password = $NULL
        if ($testresult -eq "Success") {
            $config_pod_combobox.Items.CLear()
            $config_conserver_combobox.Items.CLear()
            foreach ($pod in ($configuration.ServerArray | Select-Object -expandproperty PodName -unique)) {
                $config_pod_combobox.Items.Add($pod)  | out-null
            }
            #        foreach($ServerDNS in ($configuration.ServerArray | Select-Object -expandproperty ServerDNS -unique)){
            $config_pod_combobox.SelectedItem = ($configuration.ServerArray | Where-Object { $_.ServerDNS -eq $connectionserveraddress }).PodName    
            foreach ($ServerDNS in ($configuration.ServerArray | where-object { $_.podname -eq ($config_pod_combobox.SelectedItem) } | Select-Object -expandproperty ServerDNS -unique)) {
                $config_conserver_combobox.Items.Add($ServerDNS) | out-null
            }
        
            $config_conserver_combobox.SelectedItem = ($configuration.ServerArray | Where-Object { $_.ServerDNS -eq $connectionserveraddress }).ServerDNS
            $config_conserver_textbox.Text = $stdconservertext
        }
    }
    else {
        send-status -Status "WARNING" -message  "No credentials found, credentials need to be entered first"
        $config_credential_label.Content = "Please enter credentials first."
    }
    store-status
}


function config_ignore_cert_errors_checkbox_ischecked() {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message "Ignore Certificates Checkbox has been checked"
    store-status
}

function config_ignore_cert_errors_checkbox_unchecked() {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message "Ignore Certificates Checkbox has been unchecked"
    store-status
}

function config_pod_combobox_selectionchanged {
    param($sender, $e)
    $config_conserver_combobox.Items.CLear()
    if ($null -ne $config_pod_combobox.SelectedItem) {
        foreach ($ServerDNS in ($configuration.ServerArray | where-object { $_.podname -eq ($config_pod_combobox.SelectedItem) } | Select-Object -expandproperty ServerDNS -unique)) {
            $config_conserver_combobox.Items.Add($ServerDNS) | out-null
        }
    }
}

function Load-Configuration {
    if (test-path -Path $ConfigurationFilePath) {
        send-status -Status "INFORMATIONAL" -message "Importing Config from $ConfigurationFilePath."
        $Script:Configuration = Import-Clixml $ConfigurationFilePath
        if ($Configuration.Credentialsobject -ne "") {
            $config_credential_label.Content = "Credentials loaded from configuration file."
            $config_username_textbox.Text = ($Configuration.Credentialsobject).username
            $config_domain_textbox.Text = ($Configuration.Credentialsobject).domain
            $config_passwordbox.Password = [System.Net.NetworkCredential]::new("", ($Configuration.Credentialsobject).password).Password
        }
        foreach ($pod in ($configuration.ServerArray | Select-Object -expandproperty PodName -unique)) {
            $config_pod_combobox.Items.Add($pod)  | out-null
        }
        if ($Configuration.LastSelectedPod -ne "") {
            $config_pod_combobox.SelectedItem = $Configuration.LastSelectedPod
        }
        foreach ($ServerDNS in ($configuration.ServerArray | Select-Object -expandproperty ServerDNS -unique)) {
            $config_conserver_combobox.Items.Add($ServerDNS) | out-null
        }
        if ($Configuration.LastSelectedConnectionServer -ne "") {
            $config_conserver_combobox.SelectedItem = $Configuration.LastSelectedConnectionServer
        }
        send-status -Status "INFORMATIONAL" -message "Loaded config:"
        send-status -Status "INFORMATIONAL" -message  ($configuration | out-string -Width 4096)

        send-status -Status "INFORMATIONAL" -message "Successfully loaded configuration"
    }
    else {
        send-status -Status "INFORMATIONAL" -message  "No Configuration found, starting with Default"
        New-Configuration
    }
    store-status
}
#endregion

#region VDI_Functions

function VDI_secondaryimage_checkbox_Checked() {
    param($sender, $e)
    if (($VDI_Snapshot_Combobox).IsEnabled -eq $true) {
        $VDI_Machines_ListBox.IsEnabled = $true
    }
}

function VDI_secondaryimage_checkbox_UnChecked() {
    param($sender, $e)
    $VDI_Machines_ListBox.IsEnabled = $false
}

function VDI_Enable_datetimepicker_checkbox_checked() {
    param($sender, $e)
    $datetime = get-date
    if ($null -eq $VDI_datepicker.SelectedDate) {
        $VDI_datepicker.SelectedDate = $datetime
    }
    $VDI_timepicker_hour_combobox.SelectedItem = Get-Date -Format HH
    [int]$minute = $datetime | select-object -expandproperty minute
    [int]$hour = $datetime | select-object -expandproperty hour
    $VDI_timepicker_minute_combobox.SelectedItem = $minute
    $VDI_timepicker_hour_combobox.SelectedItem = $hour
    $VDI_timepicker_hour_combobox.IsEnabled = $true
    $VDI_timepicker_minute_combobox.IsEnabled = $true
    $VDI_datepicker.IsEnabled = $true
}

function VDI_Enable_datetimepicker_checkbox_unchecked() {
    param($sender, $e)
    $VDI_datepicker.IsEnabled = $false
    $VDI_timepicker_hour_combobox = $false
    $VDI_timepicker_minute_combobox = $false
}

function VDI_Resize_Checkbox_Checked() {
    param($sender, $e)
    if (($VDI_Snapshot_Combobox).IsEnabled -eq $true) {
        if ($null -ne $VDI_CoresPerSocket_ComboBox.SelectedItem -and $null -ne $VDI_Memory_ComboBox.SelectedItem -and $null -ne $VDI_CPUCount_ComboBox.SelectedItem) {
            $VDI_Apply_Golden_Image_button.IsEnabled = $true
        }
        else {
            $VDI_Apply_Golden_Image_button.IsEnabled = $false
        }
        $VDI_Memory_ComboBox.IsEnabled = $true
        $VDI_CPUCount_ComboBox.IsEnabled = $true
        $VDI_CoresPerSocket_ComboBox.IsEnabled = $true
    }
}

function VDI_Resize_Checkbox_UnChecked() {
    param($sender, $e)
    $VDI_Memory_ComboBox.IsEnabled = $false
    $VDI_CPUCount_ComboBox.IsEnabled = $false
    $VDI_CoresPerSocket_ComboBox.IsEnabled = $false
    if ($null -ne ($VDI_Snapshot_Combobox).SelectedItem) {
        $VDI_Apply_Golden_Image_button.IsEnabled = $true
    }
}

function VDI_CPUCount_ComboBox_selectionchanged {
    param($sender, $e)
    $totalcorecount = $null
    $corespersocketcount = $null
    $memoryselectedsize = $null
    $totalcorecount = $VDI_CPUCount_ComboBox.SelectedItem
    $corespersocketcount = $VDI_CoresPerSocket_ComboBox.SelectedItem
    $memoryselectedsize = $VDI_Memory_ComboBox.SelectedItem
    if (($null -ne $totalcorecount -and $null -ne $corespersocketcount -and $null -ne $memoryselectedsize) -and ($totalcorecount -ge $corespersocketcount) -and (($totalcorecount / $corespersocketcount) -in (1..999))) {
        $VDI_Apply_Golden_Image_button.IsEnabled = $true
    }
    else {
        $VDI_Apply_Golden_Image_button.IsEnabled = $false
    }
}

function VDI_CoresPerSocket_ComboBox_selectionchanged {
    param($sender, $e)
    $totalcorecount = $null
    $corespersocketcount = $null
    $memoryselectedsize = $null
    $totalcorecount = $VDI_CPUCount_ComboBox.SelectedItem
    $corespersocketcount = $VDI_CoresPerSocket_ComboBox.SelectedItem
    $memoryselectedsize = $VDI_Memory_ComboBox.SelectedItem
    if (($null -ne $totalcorecount -and $null -ne $corespersocketcount -and $null -ne $memoryselectedsize) -and ($totalcorecount -ge $corespersocketcount) -and (($totalcorecount / $corespersocketcount) -in (1..999))) {
        $VDI_Apply_Golden_Image_button.IsEnabled = $true
    }
    else {
        $VDI_Apply_Golden_Image_button.IsEnabled = $false
    }
}

function VDI_Memory_ComboBox_selectionchanged {
    param($sender, $e)
    $totalcorecount = $null
    $corespersocketcount = $null
    $memoryselectedsize = $null
    $totalcorecount = $VDI_CPUCount_ComboBox.SelectedItem
    $corespersocketcount = $VDI_CoresPerSocket_ComboBox.SelectedItem
    $memoryselectedsize = $VDI_Memory_ComboBox.SelectedItem
    if (($null -ne $totalcorecount -and $null -ne $corespersocketcount -and $null -ne $memoryselectedsize) -and ($totalcorecount -ge $corespersocketcount) -and (($totalcorecount / $corespersocketcount) -in (1..999))) {
        $VDI_Apply_Golden_Image_button.IsEnabled = $true
    }
    else {
        $VDI_Apply_Golden_Image_button.IsEnabled = $false
    }
}

function vdi_snapshot_combobox_selectionchanged {
    param($sender, $e)
    if ($null -ne $VDI_Snapshot_Combobox.SelectedItem) {
        $desktoppool = $VDI_DesktopPool_Combobox.SelectedItem
        $VDI_Apply_Golden_Image_button.IsEnabled = $true
        $VDI_Enable_datetimepicker_checkbox.IsEnabled = $true
        $VDI_vtpm_checkbox.IsEnabled = $true
        $VDI_StopOnError_checkbox.IsEnabled = $true
        $VDI_LofOffPolicy_Combobox.IsEnabled = $true
        $VDI_Resize_checkbox.IsChecked = $false
        $VDI_Resize_checkbox.IsEnabled = $true
        $VDI_secondaryimage_checkbox.IsEnabled = $true
        $pool_memsize = $null
        $pool_cpucount = $null
        $pool_corespersocket = $null
        [int]$pool_memsize = ($desktoppool.provisioning_settings).compute_profile_ram_mb
        [int32]$pool_cpucount = ($desktoppool.provisioning_settings).compute_profile_num_cpus
        [int32]$pool_corespersocket = ($desktoppool.provisioning_settings).compute_profile_num_cores_per_socket
        if ($pool_memsize -ne 0 -and $null -ne $pool_memsize) {
            $VDI_Resize_checkbox.IsChecked = $true
            $VDI_Memory_ComboBox.SelectedItem = $pool_memsize
            $VDI_CPUCount_ComboBox.SelectedValue = $pool_cpucount
            $VDI_CoresPerSocket_ComboBox.SelectedValue = $pool_corespersocket
        }
        else {
            $VDI_Resize_checkbox.IsChecked = $false
        }
        if ($VDI_Resize_Checkbox.IsChecked -eq $true) {
            $VDI_Memory_ComboBox.IsEnabled = $true
            $VDI_CPUCount_ComboBox.IsEnabled = $true
            $VDI_CoresPerSocket_ComboBox.IsEnabled = $true
        }
        if ($VDI_secondaryimage_checkbox.IsChecked -eq $true) {
            $VDI_Machines_ListBox.IsEnabled = $true
        }
    }
    else {
        $VDI_Resize_checkbox.IsChecked = $false
        $VDI_Resize_checkbox.IsEnabled = $false
        $VDI_Memory_ComboBox.IsEnabled = $false
        $VDI_CPUCount_ComboBox.IsEnabled = $false
        $VDI_CoresPerSocket_ComboBox.IsEnabled = $false
        $VDI_Apply_Golden_Image_button.IsEnabled = $false
        $VDI_Enable_datetimepicker_checkbox.IsEnabled = $false
        $VDI_vtpm_checkbox.IsEnabled = $false
        $VDI_StopOnError_checkbox.IsEnabled = $false
        $VDI_LofOffPolicy_Combobox.IsEnabled = $false
    }
}

function VDI_Apply_Secondary_Image_button_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message  "Deployong secondary image to extra machines"
    $podname = ($VDI_DesktopPool_Combobox.SelectedItem).Podname
    $desktoppoolid = ($VDI_DesktopPool_Combobox.SelectedItem).Id
    try {
        $login_tokens = connect-hvpod -podname $podname
        if ($login_tokens -eq "Failure") {
            send-status -Status "ERROR" -message "failed to connect so can't apply secondary image."
            $VDI_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to apply the secondary image"
            break
        }
        $AccessToken = $login_tokens | Select-Object Access_token
        $RefreshToken = $login_tokens | Select-Object Refresh_token
        $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
        $serverURL = "https://$lastusedserver"
        $VDI_Statusbox_Label.Content = "Status: Connected"
    }
    catch {
        send-status -Status "ERROR" -message  "Error Connecting."
        $VDI_Statusbox_Label.Content = "Status: Error connecting"
    }
    [array]$targetmachines = ($VDI_Machines_ListBox.SelectedItems).id
    [array]$targetmachinenames = ($VDI_Machines_ListBox.SelectedItems).Name
    send-status -Status "INFORMATIONAL" -message  "Secondary Image will be applied to these machines after being initialized: $targetmachinenames"
    $json = $targetmachines | ConvertTo-Json -Depth 100 -AsArray
    $result = invoke-hvcommand -URL "$serverURL/rest/inventory/v1/desktop-pools/$desktoppoolid/action/apply-image?pending_image=true" -accesstoken $AccessToken -json $json -Method Post
    $resultcount = $result.count
    $success = $result | Where-Object { $_.status_code -eq 200 }
    $successcount = $success.count
    $failures = $result | Where-Object { $_.status_code -ne 200 }
    $failurecount = $failures.count
    if ($successcount -eq 0) {
        send-status -Status "ERROR" -message "Failure starting Golden Image deployment"
        $VDI_Statusbox_Label.Content = "Failure starting Golden Image deployment"
        send-status -Status "ERROR" -message "Error per selected machine to deploy Secondary Image to:"
        foreach ($failure in $failures) {
            $name = ($VDI_Machines_ListBox.SelectedItems | Where-Object { $_.id -eq $failure.id }).name
            $error = $failure.errors.error_message
            send-status -Status "ERROR" -Message "Failed to deploy image for machine $name with error $error"
        }
    }
    elseif ($failurecount -eq 0) {
        send-status -Status "INFORMATIONAL" -message "Started Golden Image deployment"
        $VDI_Statusbox_Label.Content = "Started Golden Image Deployment"
    }
    else {
        send-status -Status "ERROR" -message "Partial failure starting Golden Image deployment"
        $VDI_Statusbox_Label.Content = "Partial failure starting Golden Image deployment"
        send-status -Status "ERROR" -message "Error per selected machine to deploy Secondary Image to:"
        foreach ($failure in $failures) {
            $name = ($VDI_Machines_ListBox.SelectedItems | Where-Object { $_.id -eq $failure.id }).name
            $error = $failure.errors.error_message
            send-status -Status "ERROR" -Message "Failed to deploy image for machine $name with error $error"
        }
    }

    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    store-status
}

function VDI_Cancel_Secondary_Image_push_button_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message  "cancelling current secondary image"
    $podname = ($VDI_DesktopPool_Combobox.SelectedItem).Podname
    $desktoppoolid = ($VDI_DesktopPool_Combobox.SelectedItem).Id
    try {
        $login_tokens = connect-hvpod -podname $podname
        if ($login_tokens -eq "Failure") {
            send-status -Status "ERROR" -message  "failed to connect so can't cancel this secondary image."
            $VDI_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to cancel the image"
            break
        }
        $AccessToken = $login_tokens | Select-Object Access_token
        $RefreshToken = $login_tokens | Select-Object Refresh_token
        $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
        $serverURL = "https://$lastusedserver"
        $VDI_Statusbox_Label.Content = "Status: Connected"
    }
    catch {
        send-status -Status "INFORMATIONAL" -message  "Error Connecting."
        $VDI_Statusbox_Label.Content = "Status: Error connecting"
    }
    $result = invoke-hvcommand -URL "$serverURL/rest/inventory/v1/desktop-pools/$desktoppoolid/action/cancel-scheduled-push-image" -accesstoken $AccessToken -Method Post
    $result = $result | ConvertFrom-Json
    if ($result.status -eq "BAD_REQUEST") {
        $errors = ($result.errors).error_key
        send-status -Status "ERROR" -message  "Failure cancelling secondary image"
        $VDI_Statusbox_Label.Content = "Failure cancelling secondary image"
        send-status -Status "ERROR" -message "$errors"
    }
    else {
        send-status -Status "INFORMATIONAL" -message "Started cancelling secondary image"
        $VDI_Statusbox_Label.Content = "Started cancelling secondary image"
        $VDI_Promote_Secondary_Image_button.IsEnabled = $false
        $VDI_Cancel_Secondary_Image_button.IsEnabled = $false
        $VDI_Apply_Secondary_Image_button.IsEnabled = $false
        $VDI_Machines_ListBox.IsEnabled = $false
    }
    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    store-status
}


function VDI_Promote_Secondary_Image_button_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message  "Promoting current secondary image"
    $podname = ($VDI_DesktopPool_Combobox.SelectedItem).Podname
    $desktoppoolid = ($VDI_DesktopPool_Combobox.SelectedItem).Id
    try {
        $login_tokens = connect-hvpod -podname $podname
        if ($login_tokens -eq "Failure") {
            send-status -Status "ERROR" -message "failed to connect so can't promote the secondary image."
            $VDI_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to promote the image"
            break
        }
        $AccessToken = $login_tokens | Select-Object Access_token
        $RefreshToken = $login_tokens | Select-Object Refresh_token
        $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
        $serverURL = "https://$lastusedserver"
        $VDI_Statusbox_Label.Content = "Status: Connected"
    }
    catch {
        send-status -Status "INFORMATIONAL" -message  "Error Connecting."
        $VDI_Statusbox_Label.Content = "Status: Error connecting"
    }

    $result = invoke-hvcommand -URL "$serverURL/rest/inventory/v1/desktop-pools/$desktoppoolid/action/promote-pending-image" -accesstoken $AccessToken -Method Post
    $result = $result | ConvertFrom-Json
    if ($result.status -eq "BAD_REQUEST") {
        $errors = ($result.errors).error_key
        send-status -Status "ERROR" -message "Failure promoting secondary image"
        $VDI_Statusbox_Label.Content = "Failure promoting secondary image"
        send-status -Status "INFORMATIONAL" -message "$errors"
    }
    else {
        send-status -Status "INFORMATIONAL" -message "Started promoting secondary image"
        $VDI_Statusbox_Label.Content = "Started promoting secondary image"
        $VDI_Promote_Secondary_Image_button.IsEnabled = $false
        $VDI_Cancel_Secondary_Image_button.IsEnabled = $false
        $VDI_Apply_Secondary_Image_button.IsEnabled = $false
        $VDI_Machines_ListBox.IsEnabled = $false
    }
    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    store-status
}

function VDI_Apply_Golden_Image_button_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message  " Applying golden image"
    $podname = ($VDI_DesktopPool_Combobox.SelectedItem).Podname
    $desktoppoolid = ($VDI_DesktopPool_Combobox.SelectedItem).Id
    $basevmid = ($VDI_Golden_Image_Combobox.SelectedItem).Id
    $basesnapshotid = ($VDI_Snapshot_Combobox.SelectedItem).Id
    $datahashtable = [ordered]@{}
    $logoffpolicy = $VDI_LofOffPolicy_Combobox.SelectedValue
    [array]$targetmachines = ($VDI_Machines_ListBox.SelectedItems).id
    [array]$targetmachinenames = ($VDI_Machines_ListBox.SelectedItems).Name
    send-status -Status "INFORMATIONAL" -message  "Secondary Image will be applied to these machines after being initialized: $targetmachinenames"

    if ($VDI_vtpm_checkbox.IsCHecked -eq $true) {
        $datahashtable.add('add_virtual_tpm', $true)
    }
    else {
        $datahashtable.add('add_virtual_tpm', $false)
    }
    if ($VDI_resize_checkbox.IsChecked -eq $true) {
        $datahashtable.add('compute_profile_num_cores_per_socket', $VDI_CoresPerSocket_ComboBox.SelectedValue)
        $datahashtable.add('compute_profile_num_cpus', $VDI_CPUCount_ComboBox.SelectedValue)
        $datahashtable.add('compute_profile_ram_mb', $VDI_Memory_ComboBox.SelectedItem)
    }
    $datahashtable.add('logoff_policy', $logoffpolicy)
    if ($VDI_secondaryimage_checkbox.IsChecked -eq $true) {
        $datahashtable.add('machine_ids', $targetmachines)
    }
    $datahashtable.add('parent_vm_id', $basevmid)
    if ($VDI_secondaryimage_checkbox.IsChecked -eq $true) {
        $datahashtable.add('selective_push_image', $true)
    }
  
    $datahashtable.add('snapshot_id', $basesnapshotid)
    if ($VDI_Enable_datetimepicker_checkbox.IsChecked -eq $true) {
        $starttime = get-date $VDI_datepicker.SelectedDate -Hour $VDI_timepicker_hour_combobox.SelectedItem -Minute $VDI_timepicker_minute_combobox.SelectedItem
        $epoch = ([DateTimeOffset]$starttime).ToUnixTimeMilliseconds()
        $datahashtable.add('start_time', $epoch)
    }
    $datahashtable.add('stop_on_first_error', $VDI_StopOnError_checkbox.IsChecked)
    try {
        $login_tokens = connect-hvpod -podname $podname
        if ($login_tokens -eq "Failure") {
            send-status -Status "ERROR" -message "failed to connect so can't apply this new Golden Image."
            $VDI_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to deploy the image"
            break
        }
        $AccessToken = $login_tokens | Select-Object Access_token
        $RefreshToken = $login_tokens | Select-Object Refresh_token
        $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
        $serverURL = "https://$lastusedserver"
        $VDI_Statusbox_Label.Content = "Status: Connected"
    }
    catch {
        send-status -Status "ERROR" -message  "Error Connecting."
        $VDI_Statusbox_Label.Content = "Status: Error connecting"
    }
    $json = $datahashtable | ConvertTo-Json -Depth 100
    $result = invoke-hvcommand -URL "$serverURL/rest/inventory/v2/desktop-pools/$desktoppoolid/action/schedule-push-image" -accesstoken $AccessToken -json $json -Method Post
    if ($VDI_secondaryimage_checkbox.IsChecked -eq $true) {
        $resultcount = $result.count
        $success = $result | Where-Object { $_.status_code -eq 200 }
        $successcount = $success.count
        $failures = $result | Where-Object { $_.status_code -ne 200 }
        $failurecount = $failures.count
        if ($successcount -eq 0) {
            send-status -Status "ERROR" -message "Failure starting Golden Image deployment"
            $VDI_Apply_Golden_Image_button.IsEnabled = $true
            $VDI_Statusbox_Label.Content = "Failure starting Golden Image deployment"
            send-status -Status "ERROR" -message "Error per selected machine to deploy Secondary Image to:"
            foreach ($failure in $failures) {
                $name = ($VDI_Machines_ListBox.SelectedItems | Where-Object { $_.id -eq $failure.id }).name
                $error = $failure.errors.error_message
                send-status -Status "ERROR" -Message "Failed to deploy image for machine $name with error $error"
            }
        }
        elseif ($failurecount -eq 0) {
            send-status -Status "INFORMATIONAL" -message "Started Golden Image deployment"
            $VDI_Apply_Golden_Image_button.IsEnabled = $false
            $VDI_Statusbox_Label.Content = "Started Golden Image Deployment"
        }
        else {
            send-status -Status "ERROR" -message "Partial failure starting Golden Image deployment"
            $VDI_Apply_Golden_Image_button.IsEnabled = $false
            $VDI_Statusbox_Label.Content = "Partial failure starting Golden Image deployment"
            send-status -Status "ERROR" -message "Error per selected machine to deploy Secondary Image to:"
            foreach ($failure in $failures) {
                $name = ($VDI_Machines_ListBox.SelectedItems | Where-Object { $_.id -eq $failure.id }).name
                $error = $failure.errors.error_message
                send-status -Status "ERROR" -Message "Failed to deploy image for machine $name with error $error"
            }
        }
    }
    else {
        $result = $result | ConvertFrom-Json
        if ($result.status -eq "BAD_REQUEST") {
            $errors = ($result.errors).error_key
            send-status -Status "ERROR" -message "Failure starting Golden Image deployment"
            $VDI_Apply_Golden_Image_button.IsEnabled = $true
            $VDI_Statusbox_Label.Content = "Failure starting Golden Image deployment"
            send-status -Status "ERROR" -message "$errors"
        }
        else {
            send-status -Status "INFORMATIONAL" -message "Started Golden Image deployment"
            $VDI_Apply_Golden_Image_button.IsEnabled = $false
            $VDI_Statusbox_Label.Content = "Started Golden Image Deployment"
        }
    }


    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    store-status
}

function VDI_DesktopPool_Combobox_selectionchanged {
    param($sender, $e)
    if ($null -ne $VDI_DesktopPool_Combobox.SelectedItem) {
        $VDI_Status_Textblock.Text = "
        Desktop Pool Status:"
        $VDI_Golden_Image_Combobox.SelectedItem = $null
        $VDI_Snapshot_Combobox.SelectedItem = $null
        $VDI_Memory_ComboBox.SelectedItem = $null
        $VDI_CPUCount_ComboBox.SelectedValue = $null
        $VDI_CoresPerSocket_ComboBox.SelectedValue = $null
        $VDI_Resize_checkbox.IsChecked = $false
        $desktoppool = $VDI_DesktopPool_Combobox.SelectedItem
        $podname = $desktoppool.podname
        $VDI_Machines_ListBox.ItemsSource = $null
        $desktoppoolname = $desktoppool.name
        switch ($desktoppool.enabled) {
            "true" { $desktoppoolenabledstate = "Enabled" }
            "false" { $desktoppoolenabledstate = "Disabled" }
        }
        switch ($desktoppool.enable_provisioning) {
            "true" { $desktoppoolprovisioningstate = "Enabled" }
            "false" { $desktoppoolprovisioningstate = "Disabled" }
        }
        $desktoppooldisplayname = $desktoppool.display_name
        $provisioning_settings = $desktoppool.provisioning_settings
        $provisioning_status_data = $desktoppool.provisioning_status_data
        $instant_clone_push_image_settings = $provisioning_status_data.instant_clone_push_image_settings
        $desktoppoolId = $desktoppool.id
        $basevmid = $provisioning_settings.parent_vm_id
        $dpbasesnapshotid = $provisioning_settings.base_snapshot_id

        $secondarybasevmid = $provisioning_status_data.instant_clone_pending_image_parent_vm_id
        $secondarybasesnapshotid = $provisioning_status_data.instant_clone_pending_image_snapshot_id
        $instant_clone_pending_image_progress = $provisioning_status_data.instant_clone_pending_image_progress
        $vcenterid = $desktoppool.vcenter_id
        $dpbasevm = $script:DataTable.basevms | Where-Object { $_.id -eq $basevmid -and $_.vcenter_id -eq $vcenterid }
        $dpbasesnapshot = $script:DataTable.basesnapshots | Where-Object { $_.id -eq $dpbasesnapshotid -and $_.vcenter_id -eq $vcenterid }
        $secondarybasevm = $script:DataTable.basevms | Where-Object { $_.id -eq $secondarybasevmid -and $_.vcenter_id -eq $vcenterid }
        $secondarybasesnapshot = $script:DataTable.basesnapshots | Where-Object { $_.id -eq $secondarybasesnapshotid -and $_.vcenter_id -eq $vcenterid }
        $instant_clone_current_image_state = $provisioning_status_data.instant_clone_current_image_state
        $instant_clone_pending_image_state = $provisioning_status_data.instant_clone_pending_image_state
        $instant_clone_operation = $provisioning_status_data.instant_clone_operation
        $parentvmname = $dpbasevm.name
        $snapshotname = $dpbasesnapshot.name
        $secondaryvmname = $secondarybasevm.name
        $secondarysnapshotname = $secondarybasesnapshot.name
        switch ($provisioning_settings_data.add_virtual_tpm) {
            "true" { $addtpm = "Enabled" }
            "false" { $addtpm = "Disabled" }
        }
        if ($null -ne $instant_clone_push_image_settings.start_time) {
            $instantcloneoperationscheduledtime = ([datetimeoffset]::FromUnixTimeMilliseconds($instant_clone_push_image_settings.start_time).DateTime).ToLocalTime()
        }
        $VDI_Status_Textblock.Text = "
        Desktop Pool Status:
        Poolname = $desktoppoolname
        Display name = $desktoppooldisplayname
        Desktop Pool State = $desktoppoolenabledstate
        Provisioning State = $desktoppoolprovisioningstate
        Current Image State = $instant_clone_current_image_state
        Instant Clone Operation = $instant_clone_operation
        Image Push Start Time = $instantcloneoperationscheduledtime
        Base VM = $parentvmname
        Base Snapshot = $snapshotname
        Secondary or Pending VM = $secondaryvmname
        Secondary or Pending Snapshot = $secondarysnapshotname
        Pending Image State = $instant_clone_pending_image_state
        Pending Image Progress = $instant_clone_pending_image_progress %
        "

        send-status -Status "INFORMATIONAL" -message  "Selected: $desktoppoolname"
        $deploymentstate = $desktoppool.provisioning_status_data
        $VDI_Apply_Golden_Image_button.IsEnabled = $false
        $VDI_Snapshot_Combobox.IsEnabled = $false
        $VDI_Golden_Image_Combobox.IsEnabled = $false
        $VDI_Cancel_Secondary_Image_button.IsEnabled = $false
        $VDI_Promote_Secondary_Image_button.IsEnabled = $false
        $VDI_Apply_Secondary_Image_button.IsEnabled = $false
        $VDI_Machines_ListBox.IsEnabled = $false
        $VDI_Enable_datetimepicker_checkbox.IsEnabled = $false
        $VDI_vtpm_checkbox.IsEnabled = $false
        $VDI_StopOnError_checkbox.IsEnabled = $false
        $VDI_LofOffPolicy_Combobox.IsEnabled = $false
        $VDI_Resize_checkbox.IsEnabled = $false
        $VDI_secondaryimage_checkbox.IsEnabled = $false
        if (($deploymentstate.instant_clone_operation -eq "NONE" -and $null -eq $deploymentstate.instant_clone_pending_image_state) -or ($deploymentstate.instant_clone_operation -eq "NONE" -and $deploymentstate.instant_clone_pending_image_state -eq "FAILED")) {
            $VDI_Golden_Image_Combobox.ItemsSource = $null
            $VDI_Snapshot_Combobox.ItemsSource = $null
            $availablebasevms = $script:DataTable.Basevms | Where-Object { $_.vcenter_id -eq ($desktoppool.vcenter_id) }
            $VDI_Golden_Image_Combobox.ItemsSource = $availablebasevms
            $VDI_Golden_Image_Combobox.DisplayMemberPath = 'Name'
            $VDI_Golden_Image_Combobox.SelectedValuePath = 'Id'
            $VDI_Golden_Image_Combobox.IsEnabled = $true
            $VDI_Cancel_Secondary_Image_button.IsEnabled = $false
            $VDI_Promote_Secondary_Image_button.IsEnabled = $false
            $VDI_Apply_Secondary_Image_button.IsEnabled = $false
            $VDI_Machines_ListBox.IsEnabled = $false
        }
        elseif ($deploymentstate.instant_clone_pending_image_state -eq "READY_HELD" -and $deploymentstate.instant_clone_operation -eq "NONE") {
            $VDI_Apply_Golden_Image_button.IsEnabled = $false
            $VDI_Cancel_Secondary_Image_button.IsEnabled = $true
            $VDI_Promote_Secondary_Image_button.IsEnabled = $true
            $VDI_Apply_Secondary_Image_button.IsEnabled = $true
            $VDI_Machines_ListBox.IsEnabled = $true
        }
        send-status -Status "INFORMATIONAL" -message  "Connecting to pod $podname to gather machines"
        try {
            $login_tokens = connect-hvpod -podname $podname
            if ($login_tokens -eq "Failure") {
                send-status -Status "ERROR" -message "failed to connect so can't get machine data."
                $VDI_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to get machine data"
                break
            }
            $AccessToken = $login_tokens | Select-Object Access_token
            $RefreshToken = $login_tokens | Select-Object Refresh_token
            $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
            $serverURL = "https://$lastusedserver"
            send-status -Status "INFORMATIONAL" -message  $serverurl
            $VDI_Statusbox_Label.Content = "Status: Connected"
        }
        catch {
            send-status -Status "ERROR" -message  "Error Connecting."
            $VDI_Statusbox_Label.Content = "Status: Error connecting"
            break
        }
        $machinefilter = [ordered]@{}
        $machinefilter.add('type', 'Equals') 
        $machinefilter.add('name', 'desktop_pool_id')
        $machinefilter.add('value', $desktoppoolId)
        [array]$desktoppoolmachines = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "inventory/v3/machines" -filteringandpagination -filters $machinefilter -Filtertype "And"
        $desktoppoolmachines = $desktoppoolmachines | Sort-Object Name
        $VDI_Machines_ListBox.ItemsSource = $null
        $VDI_Machines_ListBox.ItemsSource = $desktoppoolmachines
        $VDI_Machines_ListBox.DisplayMemberPath = 'Name'
        $VDI_Machines_ListBox.SelectedValuePath = 'Id'

        Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    }
    else {
        $VDI_DesktopPool_Combobox.IsEnabled = $false
        $VDI_Apply_Golden_Image_button.IsEnabled = $false
        $VDI_Promote_Secondary_Image_button.IsEnabled = $false
        $VDI_Apply_Secondary_Image_button.IsEnabled = $false
        $VDI_Cancel_Secondary_Image_button.IsEnabled = $false
        $VDI_Golden_Image_Combobox.IsEnabled = $false
        $VDI_Snapshot_Combobox.IsEnabled = $false
        $VDI_Machines_ListBox.IsEnabled = $false
        $VDI_Enable_datetimepicker_checkbox.IsEnabled = $false
        $VDI_vtpm_checkbox.IsEnabled = $false
        $VDI_StopOnError_checkbox.IsEnabled = $false
        $VDI_LofOffPolicy_Combobox.IsEnabled = $false
        $VDI_Resize_checkbox.IsEnabled = $false
        $VDI_secondaryimage_checkbox.IsEnabled = $false
    }
    store-status
}

function VDI_Golden_Image_Combobox_selectionchanged {
    param($sender, $e)
    $VDI_Apply_Golden_Image_button.IsEnabled = $false
    $VDI_Snapshot_Combobox.IsEnabled = $false
    $VDI_vtpm_checkbox.IsEnabled = $false
    $VDI_StopOnError_checkbox.IsEnabled = $false
    $VDI_LofOffPolicy_Combobox.IsEnabled = $false
    $VDI_Resize_checkbox.IsEnabled = $false
    $VDI_secondaryimage_checkbox.IsEnabled = $false
    $VDI_Memory_ComboBox.IsEnabled = $false
    $VDI_CPUCount_ComboBox.IsEnabled = $false
    $VDI_CoresPerSocket_ComboBox.IsEnabled = $false
    if ($null -ne $VDI_Golden_Image_Combobox.SelectedItem) {
        $desktoppool = $script:VDI_DesktopPool_Combobox.SelectedItem
        $desktoppoolId = $desktoppool.id
        $basevm = $VDI_Golden_Image_Combobox.SelectedItem
        $BaseVMId = $basevm.Id
        $basevmname = $basevm.name
        $podname = $basevm.podname
        $vcenterid = $basevm.vcenter_id
        send-status -Status "INFORMATIONAL" -message  "Selected: $basevmname"
        $VDI_Snapshot_Combobox.ItemsSource = $null
        $basevm = $script:DataTable.basevms | Where-Object { $_.name -eq $goldenimagename }
        send-status -Status "INFORMATIONAL" -message  "Connecting to pod $podname to gather Snapshots"
        try {
            $login_tokens = connect-hvpod -podname $podname
            if ($login_tokens -eq "Failure") {
                send-status -Status "INFORMATIONAL" -message  "failed to connect so can't get snapshots."
                $VDI_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to get snapshot data"
                break
            }
            $AccessToken = $login_tokens | Select-Object Access_token
            $RefreshToken = $login_tokens | Select-Object Refresh_token
            $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
            $serverURL = "https://$lastusedserver"
            send-status -Status "INFORMATIONAL" -message  $serverurl
            $VDI_Statusbox_Label.Content = "Status: Connected"
        }
        catch {
            send-status -Status "ERROR" -message  "Error Connecting."
            $VDI_Statusbox_Label.Content = "Status: Error connecting"
            break
        }
        [array]$availablebasesnapshots = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "external/v1/base-snapshots?base_vm_id=$basevmid&vcenter_id=$vcenterid"
        $availablebasesnapshots | Add-Member -membertype NoteProperty -Name "basevmid"  -Value $basevmid
        $VDI_Snapshot_Combobox.ItemsSource = $null
        $VDI_Snapshot_Combobox.ItemsSource = $availablebasesnapshots
        $VDI_Snapshot_Combobox.DisplayMemberPath = 'Name'
        $VDI_Snapshot_Combobox.SelectedValuePath = 'Id'
        $VDI_Snapshot_Combobox.IsEnabled = $true
        Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    }
    store-status
}
    
function VDI_Connect_Button_click {
    $VDI_Connect_Button.IsEnabled = $false
    $VDI_DesktopPool_Combobox.IsEnabled = $false
    $VDI_Apply_Golden_Image_button.IsEnabled = $false
    $VDI_Promote_Secondary_Image_button.IsEnabled = $false
    $VDI_Apply_Secondary_Image_button.IsEnabled = $false
    $VDI_Cancel_Secondary_Image_button.IsEnabled = $false
    $VDI_Golden_Image_Combobox.IsEnabled = $false
    $VDI_Snapshot_Combobox.IsEnabled = $false
    $VDI_Machines_ListBox.IsEnabled = $false
    $VDI_Enable_datetimepicker_checkbox.IsEnabled = $false
    $VDI_vtpm_checkbox.IsEnabled = $false
    $VDI_StopOnError_checkbox.IsEnabled = $false
    $VDI_LofOffPolicy_Combobox.IsEnabled = $false
    $VDI_Resize_checkbox.IsEnabled = $false
    $VDI_secondaryimage_checkbox.IsEnabled = $false
    $VDI_DesktopPool_Combobox.ItemsSource = $null
    $VDI_Snapshot_Combobox.ItemsSource = $null
    $VDI_Golden_Image_Combobox.ItemsSource = $null
    $VDI_Statusbox_Label.Content = "Status: Connecting"
    $window.Dispatcher.Invoke([action] {}, "Render") 
    $connectionserveraddress = $config_conserver_combobox.SelectedItem
    $script:serverurl = "https://$connectionserveraddress"
    $podnames = $Configuration.ServerArray | Select-Object -expandproperty podname -unique
    $Script:DataTable = @{
        DesktopPools  = New-Object System.Collections.ArrayList
        RDSFarms      = New-Object System.Collections.ArrayList
        vcenters      = New-Object System.Collections.ArrayList
        datacenters   = New-Object System.Collections.ArrayList
        basevms       = New-Object System.Collections.ArrayList
        basesnapshots = New-Object System.Collections.ArrayList
    }
    foreach ($podname in $podnames) {
        send-status -Status "INFORMATIONAL" -message  "Connecting to pod $podname"
        try {
            $login_tokens = connect-hvpod -podname $podname
            if ($login_tokens -eq "Failure") {
                send-status -Status "ERROR" -message "failed to connect so can't continue for this pod."
                $VDI_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to get data"
                break
            }
            $AccessToken = $login_tokens | Select-Object Access_token
            $RefreshToken = $login_tokens | Select-Object Refresh_token
            $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
            $serverURL = "https://$lastusedserver"
            send-status -Status "INFORMATIONAL" -message $serverurl
            $VDI_Statusbox_Label.Content = "Status: Connected"
        }
        catch {
            send-status -Status "ERROR" -message  "Error Connecting."
            $VDI_Statusbox_Label.Content = "Status: Error connecting"
            break
        }

        send-status -Status "INFORMATIONAL" -message  "Getting Desktop Pools"
        $filterarray = @()
        $desktopfilter = [ordered]@{}
        $desktopfilter.add('type', 'Equals') 
        $desktopfilter.add('name', 'source')
        $desktopfilter.add('value', 'INSTANT_CLONE')
        $typefilter = [ordered]@{}
        $typefilter.add('type', 'Equals') 
        $typefilter.add('name', 'type')
        $typefilter.add('value', 'AUTOMATED')
        $filterarray += $desktopfilter
        $filterarray += $typefilter
        [array]$desktoppools = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "inventory/v6/desktop-pools" -filteringandpagination -filters $filterarray -Filtertype "And"
        $desktoppools | add-member -membertype NoteProperty -Name "podname"  -Value $podname
        $script:DataTable.DesktopPools += $desktoppools
        send-status -Status "INFORMATIONAL" -message  "Getting vCenter Servers"
        [array]$vcenters = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "config/v2/virtual-centers" 
        foreach ($vcenter in $vcenters) {
            $vcenterid = $vcenter.id
            $vcenter | add-member -membertype NoteProperty -Name "podname"  -Value $podname
            $Script:DataTable.vcenters += $vcenter
            [array]$datacenters = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "external/v1/datacenters?vcenter_id=$vcenterid"
            foreach ($datacenter in $datacenters) {
                $datacenterid = $datacenter.id
                $datacenter | add-member -membertype NoteProperty -Name "podname"  -Value $podname
                $Script:DataTable.datacenters += $datacenter
                $basevms = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "external/v1/base-vms?datacenter_id=$datacenterid&filter_incompatible_vms=true&vcenter_id=$vcenterid"
                $basevms = $basevms | Where-Object { $_.incompatible_reasons -notcontains "UNSUPPORTED_OS" }
                $basevms | Add-Member -membertype NoteProperty -Name "podname"  -Value $podname
                $Script:DataTable.basevms += $basevms
                foreach ($basevm in $basevms) {
                    $basevmid = $basevm.id
                    [array]$availablebasesnapshots = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "external/v1/base-snapshots?base_vm_id=$basevmid&vcenter_id=$vcenterid"
                    $availablebasesnapshots | Add-Member -membertype NoteProperty -Name "basevmid"  -Value $basevmid
                    $Script:DataTable.basesnapshots += $availablebasesnapshots
                }
            }
        }
    }
    $VDI_DesktopPool_Combobox.IsEnabled = $true
    $VDI_DesktopPool_Combobox.ItemsSource = $Script:DataTable.DesktopPools
    $VDI_DesktopPool_Combobox.DisplayMemberPath = 'Name'
    $VDI_DesktopPool_Combobox.SelectedValuePath = 'Id'
    $VDI_DesktopPool_Combobox.SelectedItem = ($VDI_DesktopPool_Combobox.Items[0])
    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    $VDI_Connect_Button.Content = "Refresh"
    $VDI_Connect_Button.IsEnabled = $true
    store-status
}
#endregion

#region RDS_Functions

function RDS_Resize_Checkbox_Checked() {
    param($sender, $e)
    if (($RDS_Snapshot_Combobox).IsEnabled -eq $true) {
        if ($null -ne $RDS_Memory_ComboBox.SelectedItem -and $null -ne $RDS_CPUCount_ComboBox.SelectedItem -and $null -ne $RDS_CoresPerSocket_ComboBox.SelectedItem) {
            $RDS_Apply_Golden_Image_button.IsEnabled = $true
        }
        else {
            $RDS_Apply_Golden_Image_button.IsEnabled = $false
        }
        $RDS_Memory_ComboBox.IsEnabled = $true
        $RDS_CPUCount_ComboBox.IsEnabled = $true
        $RDS_CoresPerSocket_ComboBox.IsEnabled = $true
    }
}

function RDS_Resize_Checkbox_UnChecked() {
    param($sender, $e)
    $RDS_Memory_ComboBox.IsEnabled = $false
    $RDS_CPUCount_ComboBox.IsEnabled = $false
    $RDS_CoresPerSocket_ComboBox.IsEnabled = $false
    if ($null -ne ($RDS_Snapshot_Combobox).SelectedItem) {
        $RDS_Apply_Golden_Image_button.IsEnabled = $true
    }
}

function RDS_CPUCount_ComboBox_selectionchanged {
    param($sender, $e)
    $totalcorecount = $null
    $corespersocketcount = $null
    $memoryselectedsize = $null
    $totalcorecount = $RDS_CPUCount_ComboBox.SelectedItem
    $corespersocketcount = $RDS_CoresPerSocket_ComboBox.SelectedItem
    $memoryselectedsize = $RDS_Memory_ComboBox.SelectedItem
    if (($null -ne $totalcorecount -and $null -ne $corespersocketcount -and $null -ne $memoryselectedsize) -and ($totalcorecount -ge $corespersocketcount) -and (($totalcorecount / $corespersocketcount) -in (1..999))) {
        $RDS_Apply_Golden_Image_button.IsEnabled = $true
    }
    else {
        $RDS_Apply_Golden_Image_button.IsEnabled = $false
    }
}

function RDS_CoresPerSocket_ComboBox_selectionchanged {
    param($sender, $e)
    $totalcorecount = $null
    $corespersocketcount = $null
    $memoryselectedsize = $null
    $totalcorecount = $RDS_CPUCount_ComboBox.SelectedItem
    $corespersocketcount = $RDS_CoresPerSocket_ComboBox.SelectedItem
    $memoryselectedsize = $RDS_Memory_ComboBox.SelectedItem
    if (($null -ne $totalcorecount -and $null -ne $corespersocketcount -and $null -ne $memoryselectedsize) -and ($totalcorecount -ge $corespersocketcount) -and (($totalcorecount / $corespersocketcount) -in (1..999))) {
        $RDS_Apply_Golden_Image_button.IsEnabled = $true
    }
    else {
        $RDS_Apply_Golden_Image_button.IsEnabled = $false
    }
}

function RDS_Memory_ComboBox_selectionchanged {
    param($sender, $e)
    $totalcorecount = $null
    $corespersocketcount = $null
    $memoryselectedsize = $null
    $totalcorecount = $RDS_CPUCount_ComboBox.SelectedItem
    $corespersocketcount = $RDS_CoresPerSocket_ComboBox.SelectedItem
    $memoryselectedsize = $RDS_Memory_ComboBox.SelectedItem
    if (($null -ne $totalcorecount -and $null -ne $corespersocketcount -and $null -ne $memoryselectedsize) -and ($totalcorecount -ge $corespersocketcount) -and (($totalcorecount / $corespersocketcount) -in (1..999))) {
        $RDS_Apply_Golden_Image_button.IsEnabled = $true
    }
    else {
        $RDS_Apply_Golden_Image_button.IsEnabled = $false
    }
}

function RDS_secondaryimage_checkbox_Checked() {
    param($sender, $e)
    if (($RDS_Snapshot_Combobox).IsEnabled -eq $true) {
        $RDS_Machines_ListBox.IsEnabled = $true
    }
}

function RDS_secondaryimage_checkbox_UnChecked() {
    param($sender, $e)
    $RDS_Machines_ListBox.IsEnabled = $false
}

function RDS_Enable_datetimepicker_checkbox_checked() {
    param($sender, $e)
    $datetime = get-date
    if ($null -eq $RDS_datepicker.SelectedDate) {
        $RDS_datepicker.SelectedDate = $datetime
    }
    $RDS_datepicker.IsEnabled = $true
    $RDS_timepicker_hour_combobox.SelectedItem = Get-Date -Format HH
    [int]$minute = $datetime | select-object -expandproperty minute
    [int]$hour = $datetime | select-object -expandproperty hour
    $RDS_timepicker_minute_combobox.SelectedItem = $minute
    $RDS_timepicker_hour_combobox.SelectedItem = $hour
    $RDS_timepicker_hour_combobox.IsEnabled = $true
    $RDS_timepicker_minute_combobox.IsEnabled = $true
    $RDS_datepicker.IsEnabled = $true
}

function RDS_Enable_datetimepicker_checkbox_unchecked() {
    param($sender, $e)
    $RDS_datepicker.IsEnabled = $false
    $RDS_timepicker_hour_combobox = $false
    $RDS_timepicker_minute_combobox = $false
}

function RDS_snapshot_combobox_selectionchanged {
    param($sender, $e)
    if ($null -ne $RDS_Snapshot_Combobox.SelectedItem) {
        $rdsfarm = $RDS_Farm_Combobox.SelectedItem
        $provisioning_settings = ($rdsfarm.automated_farm_settings).provisioning_settings
        $RDS_Apply_Golden_Image_button.IsEnabled = $true
        $RDS_secondaryimage_checkbox.IsEnabled = $true
        $RDS_Enable_datetimepicker_checkbox.IsEnabled = $true
        $RDS_Resize_checkbox.IsEnabled = $true
        $RDS_Resize_checkbox.IsEnabled = $true
        $RDS_StopOnError_checkbox.IsEnabled = $true
        $RDS_LofOffPolicy_Combobox.IsEnabled = $true

        $farm_memsize = $null
        $farm_cpucount = $null
        $farm_corespersocket = $null
        [int]$farm_memsize = ($provisioning_settings).compute_profile_ram_mb
        [int32]$farm_cpucount = ($provisioning_settings).compute_profile_num_cpus
        [int32]$farm_corespersocket = ($provisioning_settings).compute_profile_num_cores_per_socket
        if ($farm_memsize -ne 0 -and $null -ne $farm_memsize) {
            $RDS_Resize_checkbox.IsChecked = $true
            $RDS_Memory_ComboBox.SelectedItem = $farm_memsize
            $RDS_CPUCount_ComboBox.SelectedValue = $farm_cpucount
            $RDS_CoresPerSocket_ComboBox.SelectedValue = $farm_corespersocket
        }
        else {
            $RDS_Resize_checkbox.IsChecked = $false
        }


        if ($RDS_Resize_checkbox.IsChecked -eq $true) {
            $RDS_Memory_ComboBox.IsEnabled = $true
            $RDS_CPUCount_ComboBox.IsEnabled = $true
            $RDS_CoresPerSocket_ComboBox.IsEnabled = $true
        }
        if ($RDS_secondaryimage_checkbox.IsChecked -eq $true) {
            $RDS_Machines_ListBox.IsEnabled = $true
        }
    }
    else {
        $RDS_Resize_checkbox.IsChecked = $false
        $RDS_Resize_checkbox.IsEnabled = $false
        $RDS_Memory_ComboBox.IsEnabled = $false
        $RDS_CPUCount_ComboBox.IsEnabled = $false
        $RDS_CoresPerSocket_ComboBox.IsEnabled = $false
        $RDS_Apply_Golden_Image_button.IsEnabled = $false
        $RDS_Enable_datetimepicker_checkbox.IsEnabled = $false
        $RDS_StopOnError_checkbox.IsEnabled = $false
        $RDS_LofOffPolicy_Combobox.IsEnabled = $false
    }
}


function RDS_Apply_Secondary_Image_button_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message  "Deployong secondary image to extra machines"
    $podname = ($RDS_Farm_Combobox.SelectedItem).Podname
    $farmid = ($RDS_Farm_Combobox.SelectedItem).Id
    try {
        $login_tokens = connect-hvpod -podname $podname
        if ($login_tokens -eq "Failure") {
            send-status -Status "ERROR" -message "failed to connect so can't apply secondary image."
            $RDS_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to deploy the secondary image"
            break
        }
        $AccessToken = $login_tokens | Select-Object Access_token
        $RefreshToken = $login_tokens | Select-Object Refresh_token
        $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
        $serverURL = "https://$lastusedserver"
        $RDS_Statusbox_Label.Content = "Status: Connected"
    }
    catch {
        send-status -Status "ERROR" -message  "Error Connecting."
        $RDS_Statusbox_Label.Content = "Status: Error connecting"
    }
    [array]$targetmachines = ($RDS_Machines_ListBox.SelectedItems).id
    [array]$targetmachinenames = ($RDS_Machines_ListBox.SelectedItems).Name
    send-status -Status "INFORMATIONAL" -message  "Secondary Image will be applied to these machines after being initialized: $targetmachinenames"
    $json = $targetmachines | ConvertTo-Json -Depth 100 -AsArray
    $result = invoke-hvcommand -URL "$serverURL/rest/inventory/v1/farms/$farmid/action/apply-image?pending_image=true" -accesstoken $AccessToken -json $json -Method Post
    $resultcount = $result.count
    $success = $result | Where-Object { $_.status_code -eq 200 }
    $successcount = $success.count
    $failures = $result | Where-Object { $_.status_code -ne 200 }
    $failurecount = $failures.count
    if ($successcount -eq 0) {
        send-status -Status "ERROR" -message "Failure starting Golden Image deployment"
        $RDS_Statusbox_Label.Content = "Failure starting Golden Image deployment"
        send-status -Status "ERROR" -message "Error per selected machine to deploy Secondary Image to:"
        foreach ($failure in $failures) {
            $name = ($RDS_Machines_ListBox.SelectedItems | Where-Object { $_.id -eq $failure.id }).name
            $error = $failure.errors.error_message
            send-status -Status "ERROR" -Message "Failed to deploy image for machine $name with error $error"
        }
    }
    elseif ($failurecount -eq 0) {
        send-status -Status "INFORMATIONAL" -message "Started Golden Image deployment"
        $RDS_Statusbox_Label.Content = "Started Golden Image Deployment"
    }
    else {
        send-status -Status "ERROR" -message "Partial failure starting Golden Image deployment"
        $RDS_Statusbox_Label.Content = "Partial failure starting Golden Image deployment"
        send-status -Status "ERROR" -message "Error per selected machine to deploy Secondary Image to:"
        foreach ($failure in $failures) {
            $name = ($RDS_Machines_ListBox.SelectedItems | Where-Object { $_.id -eq $failure.id }).name
            $error = $failure.errors.error_message
            send-status -Status "ERROR" -Message "Failed to deploy image for machine $name with error $error"
        }
    }
    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    store-status
}

function RDS_Cancel_Secondary_Image_button_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message  "Cancelling current image push"
    $podname = ($RDS_Farm_Combobox.SelectedItem).Podname
    $farmid = ($RDS_Farm_Combobox.SelectedItem).Id
    try {
        $login_tokens = connect-hvpod -podname $podname
        if ($login_tokens -eq "Failure") {
            send-status -Status "ERROR" -message "failed to connect so can't cancel secondary image."
            $RDS_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to cancel the image"
            break
        }
        $AccessToken = $login_tokens | Select-Object Access_token
        $RefreshToken = $login_tokens | Select-Object Refresh_token
        $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
        $serverURL = "https://$lastusedserver"
        $RDS_Statusbox_Label.Content = "Status: Connected"
    }
    catch {
        send-status -Status "INFORMATIONAL" -message  "Error Connecting."
        $RDS_Statusbox_Label.Content = "Status: Error connecting"
    }
    $datahashtable = [ordered]@{}
    $datahashtable.add('maintenance_mode', "IMMEDIATE")
    $json = $datahashtable | ConvertTo-Json -Depth 100
    $result = invoke-hvcommand -URL "$serverURL/rest/inventory/v1/farms/$farmid/action/cancel-scheduled-maintenance" -accesstoken $AccessToken -json $json -Method Post
    $result = $result | ConvertFrom-Json
    if ($result.status -eq "BAD_REQUEST") {
        $errors = ($result.errors).error_key
        send-status -Status "ERROR" -message "Failure cancelling secondary image"
        $RDS_Statusbox_Label.Content = "Failure cancelling secondary image"
        send-status -Status "ERROR" -message "$errors"
    }
    else {
        send-status -Status "INFORMATIONAL" -message "Started cancelling secondary image"
        $RDS_Statusbox_Label.Content = "Started cancelling secondary image"
        $RDS_Promote_Secondary_Image_button.IsEnabled = $false
        $RDS_Cancel_Secondary_Image_button.IsEnabled = $false
        $RDS_Apply_Secondary_Image_button.IsEnabled = $false
        $RDS_Machines_ListBox.IsEnabled = $false
    }
    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    store-status
}

function RDS_Promote_Secondary_Image_button_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message  "Cancelling current image push"
    $podname = ($RDS_Farm_Combobox.SelectedItem).Podname
    $RDSFarmid = ($RDS_Farm_Combobox.SelectedItem).Id
    try {
        $login_tokens = connect-hvpod -podname $podname
        if ($login_tokens -eq "Failure") {
            send-status -Status "ERROR" -message "failed to connect so can't promote secondary image."
            $RDS_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to promote the image"
            break
        }
        $AccessToken = $login_tokens | Select-Object Access_token
        $RefreshToken = $login_tokens | Select-Object Refresh_token
        $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
        $serverURL = "https://$lastusedserver"
        $RDS_Statusbox_Label.Content = "Status: Connected"
    }
    catch {
        send-status -Status "INFORMATIONAL" -message  "Error Connecting."
        $RDS_Statusbox_Label.Content = "Status: Error connecting"
    }

    $result = invoke-hvcommand -URL "$serverURL/rest/inventory/v1/farms/$RDSFarmid/action/promote-pending-image" -accesstoken $AccessToken -Method Post
    $result = $result | ConvertFrom-Json
    if ($result.status -eq "BAD_REQUEST") {
        $errors = ($result.errors).error_key
        send-status -Status "ERROR" -message "Failure promoting secondary image"
        $RDS_Statusbox_Label.Content = "Failure promoting secondary image"
        send-status -Status "ERROR" -message "$errors"
    }
    else {
        send-status -Status "INFORMATIONAL" -message "Started promoting secondary image"
        $RDS_Statusbox_Label.Content = "Started promoting secondary image"
        $RDS_Promote_Secondary_Image_button.IsEnabled = $false
        $RDS_Cancel_Secondary_Image_button.IsEnabled = $false
        $RDS_Apply_Secondary_Image_button.IsEnabled = $false
        $RDS_Machines_ListBox.IsEnabled = $false
    }
    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    store-status
}

function RDS_Apply_Golden_Image_button_click {
    param($sender, $e)
    send-status -Status "INFORMATIONAL" -message  " Applying golden image"
    $podname = ($RDS_Farm_Combobox.SelectedItem).Podname
    $farmid = ($RDS_Farm_Combobox.SelectedItem).Id
    $basevmid = ($RDS_Golden_Image_Combobox.SelectedItem).Id
    $basesnapshotid = ($RDS_Snapshot_Combobox.SelectedItem).Id
    $datahashtable = [ordered]@{}
    $logoffpolicy = $RDS_LofOffPolicy_Combobox.SelectedValue
    [array]$targetmachines = ($RDS_Machines_ListBox.SelectedItems).id
    
    [array]$targetmachinenames = ($RDS_Machines_ListBox.SelectedItems).Name
    send-status -Status "INFORMATIONAL" -message "Secondary Image will be applied to these machines after being initialized: $targetmachinenames"
    if ($RDS_resize_checkbox.IsChecked -eq $true) {
        $datahashtable.add('compute_profile_num_cores_per_socket', $RDS_CoresPerSocket_ComboBox.SelectedValue)
        $datahashtable.add('compute_profile_num_cpus', $RDS_CPUCount_ComboBox.SelectedValue)
        $datahashtable.add('compute_profile_ram_mb', $RDS_Memory_ComboBox.SelectedItem)
    }
    $datahashtable.add('logoff_policy', $logoffpolicy)
    $datahashtable.add('maintenance_mode', "IMMEDIATE")
    if ($RDS_Enable_datetimepicker_checkbox.IsChecked -eq $true) {
        $starttime = get-date $RDS_datepicker.SelectedDate -Hour $RDS_timepicker_hour_combobox.SelectedItem -Minute $RDS_timepicker_minute_combobox.SelectedItem
        $epoch = ([DateTimeOffset]$starttime).ToUnixTimeMilliseconds()
        $datahashtable.add('next_scheduled_time', $epoch)
    }
    $datahashtable.add('parent_vm_id', $basevmid)
    if ($RDS_secondaryimage_checkbox.IsChecked -eq $true) {
        if (($targetmachines).count -gt 0) {
            $datahashtable.add('rds_server_ids', $targetmachines)
        }
        $datahashtable.add('selective_schedule_maintenance', $true)
    }
    $datahashtable.add('snapshot_id', $basesnapshotid)
    $datahashtable.add('stop_on_first_error', $RDS_StopOnError_checkbox.IsChecked)
    try {
        $login_tokens = connect-hvpod -podname $podname
        if ($login_tokens -eq "Failure") {
            send-status -Status "ERROR" -message "failed to connect so can't apply golden image."
            $RDS_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to deploy the image"
            break
        }
        $AccessToken = $login_tokens | Select-Object Access_token
        $RefreshToken = $login_tokens | Select-Object Refresh_token
        $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
        $serverURL = "https://$lastusedserver"
        $RDS_Statusbox_Label.Content = "Status: Connected"
    }
    catch {
        send-status -Status "ERROR" -message  "Error Connecting."
        $RDS_Statusbox_Label.Content = "Status: Error connecting"
    }
    $json = $datahashtable | ConvertTo-Json -Depth 100

    $result = invoke-hvcommand -URL "$serverURL/rest/inventory/v2/farms/$farmid/action/schedule-maintenance" -accesstoken $AccessToken -json $json -Method Post
    
    if ($RDS_secondaryimage_checkbox.IsChecked -eq $true) {
        $resultcount = $result.count
        $success = $result | Where-Object { $_.status_code -eq 200 }
        $successcount = $success.count
        $failures = $result | Where-Object { $_.status_code -ne 200 }
        $failurecount = $failures.count
        if ($successcount -eq 0) {
            send-status -Status "ERROR" -message "Failure starting Golden Image deployment"
            $RDS_Statusbox_Label.Content = "Failure starting Golden Image deployment"
            send-status -Status "ERROR" -message "Error per selected machine to deploy Secondary Image to:"
            foreach ($failure in $failures) {
                $name = ($RDS_Machines_ListBox.SelectedItems | Where-Object { $_.id -eq $failure.id }).name
                $error = $failure.errors.error_message
                send-status -Status "ERROR" -Message "Failed to deploy image for machine $name with error $error"
            }
        }
        elseif ($failurecount -eq 0) {
            send-status -Status "INFORMATIONAL" -message "Started Golden Image deployment"
            $RDS_Apply_Golden_Image_button.IsEnabled = $false
            $RDS_Statusbox_Label.Content = "Started Golden Image Deployment"
        }
        else {
            send-status -Status "ERROR" -message "Partial failure starting Golden Image deployment"
            $RDS_Apply_Golden_Image_button.IsEnabled = $false
            $RDS_Statusbox_Label.Content = "Partial failure starting Golden Image deployment"
            send-status -Status "ERROR" -message "Error per selected machine to deploy Secondary Image to:"
            foreach ($failure in $failures) {
                $name = ($RDS_Machines_ListBox.SelectedItems | Where-Object { $_.id -eq $failure.id }).name
                $error = $failure.errors.error_message
                send-status -Status "ERROR" -Message "Failed to deploy image for machine $name with error $error"
            }
        }
    }
    else {
        $result = $result | ConvertFrom-Json
        if ($result.status -eq "BAD_REQUEST") {
            $errors = ($result.errors).error_key
            send-status -Status "ERROR" -message "Failure applying golden image"
            $RDS_Statusbox_Label.Content = "Failure applying Golden Image"
            send-status -Status "INFORMATIONAL" -message "$errors"
        }
        else {
            send-status -Status "INFORMATIONAL" -message "Started applying Golden Image"
            $RDS_Statusbox_Label.Content = "Started applying Golden Image"
            $RDS_Apply_Golden_Image_button.IsEnabled = $false
        }
    }
    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    store-status
}

function RDS_Farm_Combobox_selectionchanged {
    param($sender, $e)
    if ($null -ne $RDS_Farm_Combobox.SelectedItem) {
        $RDS_Status_Textblock.Text = "
        RDS Farm Status:"
        $RDS_Golden_Image_Combobox.SelectedItem = $null
        $RDS_Snapshot_Combobox.SelectedItem = $null
        $RDS_Memory_ComboBox.SelectedItem = $null
        $RDS_CPUCount_ComboBox.SelectedItem = $null
        $RDS_CoresPerSocket_ComboBox.SelectedItem = $null
        $rdsfarm = $RDS_Farm_Combobox.SelectedItem
        $RDS_Farm_Combobox.IsEnabled = $true
        $rdsfarmname = $rdsfarm.name
        switch ($RDSFarm.enabled) {
            "true" { $rdsfarmenabledstate = "Enabled" }
            "false" { $rdsfarmenabledstate = "Disabled" }
        }
        $rdsfarmId = $rdsfarm.id
        $podname = $rdsfarm.podname
        $automated_farm_settings = $rdsfarm.automated_farm_settings
        $provisioning_settings = $automated_farm_settings.provisioning_settings
        $provisioning_status_data = $automated_farm_settings.provisioning_status_data
        $instant_clone_scheduled_maintenance_data = $provisioning_status_data.instant_clone_scheduled_maintenance_data
        $instant_clone_current_image_state = $provisioning_status_data.instant_clone_current_image_state
        $instant_clone_pending_image_state = $provisioning_status_data.instant_clone_pending_image_state
        $instant_clone_operation = $provisioning_status_data.instant_clone_operation
        $recurring_maintenance_settings = $instant_clone_scheduled_maintenance_data.recurring_maintenance_settings
        switch ($automated_farm_settings.enable_provisioning) {
            "true" { $rdsfarmprovisioningstate = "Enabled" }
            "false" { $rdsfarmprovisioningstate = "Disabled" }
        }
        $basevmid = $provisioning_settings.parent_vm_id
        $dpbasesnapshotid = $provisioning_settings.base_snapshot_id
        $vcenterid = $automated_farm_settings.vcenter_id
        $secondarybasevmid = $provisioning_status_data.instant_clone_pending_image_parent_vm_id
        $secondarybasesnapshotid = $provisioning_status_data.instant_clone_pending_image_snapshot_id
        $instant_clone_pending_image_progress = $provisioning_status_data.instant_clone_pending_image_progress
        $dpbasevm = $script:DataTable.basevms | Where-Object { $_.id -eq $basevmid -and $_.vcenter_id -eq $vcenterid }
        $dpbasesnapshot = $script:DataTable.basesnapshots | Where-Object { $_.id -eq $dpbasesnapshotid -and $_.vcenter_id -eq $vcenterid }
        
        $secondarybasevm = $script:DataTable.basevms | Where-Object { $_.id -eq $secondarybasevmid -and $_.vcenter_id -eq $vcenterid }
        $secondarybasesnapshot = $script:DataTable.basesnapshots | Where-Object { $_.id -eq $secondarybasesnapshotid -and $_.vcenter_id -eq $vcenterid }
        $parentvmname = $dpbasevm.name
        $snapshotname = $dpbasesnapshot.name
        $secondaryvmname = $secondarybasevm.name
        $secondarysnapshotname = $secondarybasesnapshot.name
        if ($null -ne $provisioning_status_data.instant_clone_operation_time) {
            $maintenancescheduledtime = ([datetimeoffset]::FromUnixTimeMilliseconds($provisioning_status_data.instant_clone_operation_time).DateTime).ToLocalTime()
        }
        $RDS_Status_Textblock.Text = "
        RDS Farm Status:
        Poolname = $RDSFarmname
        RDS Farm State = $RDSFarmenabledstate
        Provisioning State = $RDSFarmprovisioningstate
        Current Image State = $instant_clone_current_image_state
        Maintenance Operation = $instant_clone_operation
        Maintenance Scheduled Time = $maintenancescheduledtime
        Base VM = $parentvmname
        Base Snapshot = $snapshotname
        Secondary or Pending VM = $secondaryvmname
        Secondary or Pending Snapshot = $secondarysnapshotname
        Pending Image State = $instant_clone_pending_image_state
        Pending Image Progress = $instant_clone_pending_image_progress %
        "

        send-status -Status "INFORMATIONAL" -message  "Selected: $RDSFarmname"
        $RDS_Apply_Golden_Image_button.IsEnabled = $false
        $RDS_Cancel_Secondary_Image_button.IsEnabled = $false
        $RDS_Promote_Secondary_Image_button.IsEnabled = $false
        $RDS_Enable_datetimepicker_checkbox.IsEnabled = $false
        $RDS_Golden_Image_Combobox.IsEnabled = $false
        $RDS_Snapshot_Combobox.IsEnabled = $false
        $RDS_Resize_checkbox.IsEnabled = $false
        $RDS_StopOnError_checkbox.IsEnabled = $false
        $RDS_LofOffPolicy_Combobox.IsEnabled = $false
        $RDS_secondaryimage_checkbox.IsEnabled = $false
        $RDS_Apply_Secondary_Image_button.IsEnabled = $false
        $RDS_Machines_ListBox.IsEnabled = $false
        if (($provisioning_status_data.instant_clone_operation -eq "NONE" -or ($null -ne $recurring_maintenance_settings -and $provisioning_status_data.instant_clone_operation -eq "RECURRING_SCHEDULED_MAINTENANCE" )) -and ($null -eq $provisioning_status_data.instant_clone_pending_image_state -or $provisioning_status_data.instant_clone_pending_image_state -eq "FAILED")) {
            $RDS_Golden_Image_Combobox.ItemsSource = $null
            $RDS_Snapshot_Combobox.ItemsSource = $null
            [array]$availablebasevms = $script:DataTable.Basevms | Where-Object { $_.vcenter_id -eq ($vcenterid) }
            $RDS_Golden_Image_Combobox.ItemsSource = $availablebasevms
            $RDS_Golden_Image_Combobox.DisplayMemberPath = 'Name'
            $RDS_Golden_Image_Combobox.SelectedValuePath = 'Id'
            $RDS_Golden_Image_Combobox.IsEnabled = $true
            $RDS_Cancel_Secondary_Image_button.IsEnabled = $false
            $RDS_Promote_Secondary_Image_button.IsEnabled = $false
            $RDS_Apply_Secondary_Image_button.IsEnabled = $false
            $RDS_Machines_ListBox.IsEnabled = $false
        }
        elseif ($provisioning_status_data.instant_clone_pending_image_state -eq "READY_HELD" -and $provisioning_status_data.instant_clone_operation -eq "NONE") {
            $RDS_Apply_Golden_Image_button.IsEnabled = $false
            $RDS_Cancel_Secondary_Image_button.IsEnabled = $true
            $RDS_Promote_Secondary_Image_button.IsEnabled = $true
            $RDS_Apply_Secondary_Image_button.IsEnabled = $true
            $RDS_Machines_ListBox.IsEnabled = $true
        }
        send-status -Status "INFORMATIONAL" -message  "Connecting to pod $podname to gather machines"
        try {
            $login_tokens = connect-hvpod -podname $podname
            if ($login_tokens -eq "Failure") {
                send-status -Status "ERROR" -message  "failed to connect so can't gather machines."
                $RDS_Statusbox_Label.Content = "Status: Failed to connect to $podname to gather machine data"
                break
            }
            $AccessToken = $login_tokens | Select-Object Access_token
            $RefreshToken = $login_tokens | Select-Object Refresh_token
            $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
            $serverURL = "https://$lastusedserver"
            send-status -Status "INFORMATIONAL" -message  $serverurl
            $VDI_Statusbox_Label.Content = "Status: Connected"
        }
        catch {
            send-status -Status "ERROR" -message  "Error Connecting."
            $VDI_Statusbox_Label.Content = "Status: Error connecting"
            break
        }
        $machinefilter = [ordered]@{}
        $machinefilter.add('type', 'Equals') 
        $machinefilter.add('name', 'farm_id')
        $machinefilter.add('value', $rdsfarmId)
        [array]$farmmachines = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "inventory/v1/rds-servers" -filteringandpagination -filters $machinefilter -Filtertype "And"
        $farmmachines = $farmmachines | Sort-Object Name
        $RDS_Machines_ListBox.ItemsSource = $null
        $RDS_Machines_ListBox.ItemsSource = $farmmachines
        $RDS_Machines_ListBox.DisplayMemberPath = 'Name'
        $RDS_Machines_ListBox.SelectedValuePath = 'Id'

        Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    }
    else {
        $RDS_Farm_Combobox.IsEnabled = $false
        $RDS_Apply_Golden_Image_button.IsEnabled = $false
        $RDS_Promote_Secondary_Image_button.IsEnabled = $false
        $RDS_Apply_Secondary_Image_button.IsEnabled = $false
        $RDS_Cancel_Secondary_Image_button.IsEnabled = $false
        $RDS_Golden_Image_Combobox.IsEnabled = $false
        $RDS_Snapshot_Combobox.IsEnabled = $false
        $RDS_Machines_ListBox.IsEnabled = $false
        $RDS_Enable_datetimepicker_checkbox.IsEnabled = $false
        $RDS_StopOnError_checkbox.IsEnabled = $false
        $RDS_LofOffPolicy_Combobox.IsEnabled = $false
        $RDS_Resize_checkbox.IsEnabled = $false
        $RDS_secondaryimage_checkbox.IsEnabled = $false
    }
    store-status
}

function RDS_Golden_Image_Combobox_selectionchanged {
    param($sender, $e)
    $RDS_Apply_Golden_Image_button.IsEnabled = $false
    $RDS_Snapshot_Combobox.IsEnabled = $false
    $RDS_Resize_checkbox.IsEnabled = $false
    $RDS_StopOnError_checkbox.IsEnabled = $false
    $RDS_LofOffPolicy_Combobox.IsEnabled = $false
    $RDS_secondaryimage_checkbox.IsEnabled = $false
    $RDS_Memory_ComboBox.IsEnabled = $false
    $RDS_CPUCount_ComboBox.IsEnabled = $false
    $RDS_CoresPerSocket_ComboBox.IsEnabled = $false
    if ($null -ne $RDS_Golden_Image_Combobox.SelectedItem) {
        $basevm = $RDS_Golden_Image_Combobox.SelectedItem
        $BaseVMId = $basevm.Id
        $basevmname = $basevm.name
        $podname = $basevm.podname
        $vcenterid = $basevm.vcenter_id
        send-status -Status "INFORMATIONAL" -message  "Selected: $basevmname"
        $RDS_Snapshot_Combobox.ItemsSource = $null
        $basevm = $script:DataTable.basevms | Where-Object { $_.name -eq $goldenimagename }
        send-status -Status "INFORMATIONAL" -message  "Connecting to pod $podname to gather Snapshots"
        try {
            $login_tokens = connect-hvpod -podname $podname
            if ($login_tokens -eq "Failure") {
                send-status -Status "ERROR" -message  "failed to connect so can't gather snaopshots."
                $RDS_Statusbox_Label.Content = "Status: Failed to connect to $podname to get snapshot data"
                break
            }
            $AccessToken = $login_tokens | Select-Object Access_token
            $RefreshToken = $login_tokens | Select-Object Refresh_token
            $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
            $serverURL = "https://$lastusedserver"
            send-status -Status "INFORMATIONAL" -message  $serverurl
            $RDS_Statusbox_Label.Content = "Status: Connected"
        }
        catch {
            send-status -Status "ERROR" -message  "Error Connecting."
            $RDS_Statusbox_Label.Content = "Status: Error connecting"
            break
        }
        [array]$availablebasesnapshots = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "external/v1/base-snapshots?base_vm_id=$basevmid&vcenter_id=$vcenterid"
        $availablebasesnapshots | Add-Member -membertype NoteProperty -Name "basevmid"  -Value $basevmid
        $RDS_Snapshot_Combobox.ItemsSource = $availablebasesnapshots
        $RDS_Snapshot_Combobox.DisplayMemberPath = 'Name'
        $RDS_Snapshot_Combobox.SelectedValuePath = 'Id'
        $RDS_Snapshot_Combobox.IsEnabled = $true
        Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    }
    store-status
}
    
function RDS_Connect_Button_click {
    $RDS_Connect_Button.IsEnabled = $false
    $RDS_Farm_Combobox.IsEnabled = $false
    $RDS_Apply_Golden_Image_button.IsEnabled = $false
    $RDS_Promote_Secondary_Image_button.IsEnabled = $false
    $RDS_Apply_Secondary_Image_button.IsEnabled = $false
    $RDS_Cancel_Secondary_Image_button.IsEnabled = $false
    $RDS_Golden_Image_Combobox.IsEnabled = $false
    $RDS_Snapshot_Combobox.IsEnabled = $false
    $RDS_Machines_ListBox.IsEnabled = $false
    $RDS_Enable_datetimepicker_checkbox.IsEnabled = $false
    $RDS_StopOnError_checkbox.IsEnabled = $false
    $RDS_LofOffPolicy_Combobox.IsEnabled = $false
    $RDS_Resize_checkbox.IsEnabled = $false
    $RDS_secondaryimage_checkbox.IsEnabled = $false
    $RDS_Statusbox_Label.Content = "Status: Connecting"
    $window.Dispatcher.Invoke([action] {}, "Render") 
    $connectionserveraddress = $config_conserver_combobox.SelectedItem
    $script:serverurl = "https://$connectionserveraddress"
    $podnames = $Configuration.ServerArray | Select-Object -expandproperty podname -unique
    $Script:DataTable = @{
        DesktopPools  = New-Object System.Collections.ArrayList
        RDSFarms      = New-Object System.Collections.ArrayList
        vcenters      = New-Object System.Collections.ArrayList
        datacenters   = New-Object System.Collections.ArrayList
        basevms       = New-Object System.Collections.ArrayList
        basesnapshots = New-Object System.Collections.ArrayList
    }
    foreach ($podname in $podnames) {
        send-status -Status "INFORMATIONAL" -message "Connecting to pod $podname"
        try {
            $login_tokens = connect-hvpod -podname $podname
            if ($login_tokens -eq "Failure") {
                send-status -message "failed to connect so can't gather information." -Status "ERROR"
                $RDS_Statusbox_Label.Content = "Status: Failed to connect to pod $podname to gather data"
                break
            }
            $AccessToken = $login_tokens | Select-Object Access_token
            $RefreshToken = $login_tokens | Select-Object Refresh_token
            $lastusedserver = ($script:Configuration).LastSelectedConnectionServer
            $serverURL = "https://$lastusedserver"
            send-status -Status "INFORMATIONAL" -Message "Using $serverurl"
            $RDS_Statusbox_Label.Content = "Status: Connected"
        }
        catch {
            send-status -Status "ERROR" -message "Error Connecting."
            $RDS_Statusbox_Label.Content = "Status: Error connecting"
            break
        }

        send-status -Status "INFORMATIONAL" -message "Getting RDS Farms"

        $farmfilter = [ordered]@{}
        $farmfilter.add('type', 'Equals') 
        $farmfilter.add('name', 'automated_farm_settings.image_source')
        $farmfilter.add('value', 'VIRTUAL_CENTER')

        [array]$RDSFarms = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "/inventory/v4/farms" -filteringandpagination -filters $farmfilter -Filtertype "And"
        $RDSFarms | add-member -membertype NoteProperty -Name "podname"  -Value $podname
        $script:DataTable.RDSFarms += $RDSFarms
        send-status -Status "INFORMATIONAL" -message "Getting vCenter Servers"
        [array]$vcenters = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "config/v2/virtual-centers" 
        foreach ($vcenter in $vcenters) {
            $vcenterid = $vcenters.id
            $vcenter | add-member -membertype NoteProperty -Name "podname"  -Value $podname
            $Script:DataTable.vcenters += $vcenter
            [array]$datacenters = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "external/v1/datacenters?vcenter_id=$vcenterid"
            foreach ($datacenter in $datacenters) {
                $datacenterid = $datacenter.id
                $datacenter | add-member -membertype NoteProperty -Name "podname"  -Value $podname
                $Script:DataTable.datacenters += $datacenter
                $basevms = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "external/v1/base-vms?datacenter_id=$datacenterid&filter_incompatible_vms=true&vcenter_id=$vcenterid"
                $basevms = $basevms | Where-Object { $_.incompatible_reasons -notcontains "UNSUPPORTED_OS_FOR_FARM" }
                $basevms | Add-Member -membertype NoteProperty -Name "podname"  -Value $podname
                $Script:DataTable.basevms += $basevms
                foreach ($basevm in $basevms) {
                    $basevmid = $basevm.id
                    [array]$availablebasesnapshots = Get-HorizonRestData -accessToken $accesstoken -ConnectionServerURL $serverurl -RestMethod  "external/v1/base-snapshots?base_vm_id=$basevmid&vcenter_id=$vcenterid"
                    $availablebasesnapshots | Add-Member -membertype NoteProperty -Name "basevmid"  -Value $basevmid
                    $Script:DataTable.basesnapshots += $availablebasesnapshots
                }
            }
        }
    }
    $RDS_Farm_Combobox.IsEnabled = $true
    $RDS_Farm_Combobox.ItemsSource = $null
    $RDS_Farm_Combobox.ItemsSource = $Script:DataTable.RDSFarms
    $RDS_Farm_Combobox.DisplayMemberPath = 'Name'
    $RDS_Farm_Combobox.SelectedValuePath = 'Id'
    $RDS_Farm_Combobox.SelectedItem = ($RDS_Farm_Combobox.Items[0])
    send-status -Status "INFORMATIONAL" -message "Closing connection"
    Close-HRConnection -refreshToken $RefreshToken -ConnectionServerURL $serverURL
    $RDS_Connect_Button.Content = "Refresh"
    $RDS_Connect_Button.IsEnabled = $true
    store-status
}

#endregion


$script:verboselogging = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
Write-Output $verboselogging
$Configurationfolder = "$env:appdata\HGIDTool\"
$ConfigurationFileName = "HGIDTool_config.xml"
$LogFileName = "HGIDTool_$(get-date -f dd-MM-yyyy).log"

$ConfigurationFilePath = Join-Path -Path $Configurationfolder -ChildPath $ConfigurationFileName
if (!(test-path -Path $Configurationfolder)) {
    New-Item -Path $Configurationfolder -ItemType Directory | out-null
}
$LogFilePath = Join-Path -Path $Configurationfolder -ChildPath $LogFileName

$script:log = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
send-status -Message "###### NEW LOG STARTS HERE ######" -Status "INFORMATIONAL"
store-status
$window = Import-Xaml

Add-ControlVariables
Set-EventHandler
Load-Configuration

$stdconservertext = $config_conserver_textbox.Text

$VDI_LofOffPolicy_Combobox.Items.Add("FORCE_LOGOFF") | out-null
$VDI_LofOffPolicy_Combobox.Items.Add("WAIT_FOR_LOGOFF") | out-null
$VDI_LofOffPolicy_Combobox.SelectedValue = "WAIT_FOR_LOGOFF"
$RDS_LofOffPolicy_Combobox.Items.Add("FORCE_LOGOFF") | out-null
$RDS_LofOffPolicy_Combobox.Items.Add("WAIT_FOR_LOGOFF") | out-null
$RDS_LofOffPolicy_Combobox.SelectedValue = "WAIT_FOR_LOGOFF"
$memorysizes = @(1024, 2048, 4096, 6192, 8192, 12256, 16384, 32768, 65536, 131072, 262144)
$memorysizes.foreach{
    $VDI_Memory_ComboBox.Items.Add($_) | out-null
    $RDS_Memory_ComboBox.Items.Add($_) | out-null
}
$zerototwentythree = 00..23
$zerotofiftynine = 00..59

$zerototwentythree.foreach{
    $VDI_timepicker_hour_combobox.Items.add($_) | out-null
    $RDS_timepicker_hour_combobox.Items.add($_) | out-null
}

$zerotofiftynine.foreach{
    $VDI_timepicker_minute_combobox.Items.add($_) | out-null
    $RDS_timepicker_minute_combobox.Items.add($_) | out-null
}


$onetosixtyfour = [int64]1..64 | where-object { $_ % 2 -eq 0 -or $_ -eq 1 }
$onetosixtyfour.foreach{
    $VDI_CPUCount_ComboBox.Items.add($_) | out-null
    $VDI_CoresPerSocket_ComboBox.Items.add($_) | out-null
    $RDS_CPUCount_ComboBox.Items.add($_) | out-null
    $RDS_CoresPerSocket_ComboBox.Items.add($_) | out-null
}

$window.Add_closing({
        send-status -Message "Closing Window" -Status "INFORMATIONAL"
        send-status -Message "###### LOG STOPS HERE ######" -Status "INFORMATIONAL"
        store-status
        save_config_click
        [System.GC]::Collect()
    })


send-status -Message "Opening Window" -Status "INFORMATIONAL"
store-status
$window.ShowDialog() | out-null