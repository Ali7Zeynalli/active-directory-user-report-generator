Bu skript Ali Zeynalli tərəfindən yazılıb və Active Directory istifadəçilərinin ətraflı məlumatlarını əldə etmək və vizuallaşdırmaq üçün istifadə edilir. Əsas funksionallıqları aşağıdakılardır:
Get-UserNetworkDetails Funksiyası:

İstifadəçinin son daxil olduğu kompüterləri aşkar edir
Son 5 giriş etdiyi kompüteri və tarixlərini göstərir
İstifadəçinin giriş etdiyi bütün kompüterləri siyahıya alır
İstifadəçinin daxil olduğu paylaşılan qovluqları müəyyən edir

Get-UserIPAddresses Funksiyası (yeni əlavə edilmiş):

Son 7 gün ərzində istifadəçinin istifadə etdiyi IP ünvanlarını tapır
Təkrarlanan IP ünvanlarını aradan qaldırır
Tapılan bütün IP ünvanlarını vergüllə ayrılmış siyahı şəklində qaytarır

HTML Hesabat Yaratma:

Bütün Active Directory istifadəçilərinin məlumatlarını toplayır
Hər bir istifadəçi üçün ətraflı məlumatları HTML formatında təşkil edir
İstifadəçi axtarışı üçün JavaScript funksiyası daxil edir
İstifadəçi detallarını açıb-bağlamaq üçün interaktiv funksionallıq təmin edir

Statistika:

Ümumi istifadəçi sayını hesablayır
Aktiv istifadəçilərin sayını müəyyən edir
Kilidlənmiş hesabların sayını göstərir
Şifrəsi bitmiş hesabların sayını təqdim edir

Ətraflı İstifadəçi Məlumatları:

Əsas məlumatlar (ad, email, istifadəçi adı)
Hesab məlumatları (status, son giriş, yaradılma tarixi)
Təşkilati məlumatlar (şöbə, vəzifə, əlaqə məlumatları)
Son girişlər (son 5 kompüter və tarixləri)
Şəbəkə məlumatları (bütün giriş edilən kompüterlər, paylaşılan qovluqlar, üzv olduğu qruplar)
Əlavə məlumatlar (ev dizini, profil yolu, skript yolu)
IP ünvanları (son istifadə edilən IP ünvanları)

Hesabat Yaratma və Açma:

HTML hesabatı C:\Reports\AD\AD_Users_Comprehensive_Report.html ünvanında yaradır
Hesabatı avtomatik olaraq brauzerdə açır

#>

<#
Active Directory modulunu import edirik
Import-Module ActiveDirectory
Timer və qlobal dəyişənlər
$totalTimer = [System.Diagnostics.Stopwatch]::StartNew()
$script:computerAccessCache = @{}
$script:groupMembershipCache = @{}
$script:htmlBuilder = New-Object System.Text.StringBuilder
Active Directory-dən istifadəçi məlumatlarını əvvəlcədən yükləmək
$requiredProperties = @(
'DisplayName', 'EmailAddress', 'Department', 'LastLogonDate',
'Enabled', 'PasswordExpired', 'PasswordLastSet', 'PasswordNeverExpires',
'Title', 'telephoneNumber', 'mobile', 'MemberOf', 'LockedOut',
'UserAccountControl', 'WhenCreated', 'SamAccountName', 'CN',
'DistinguishedName', 'HomeDirectory', 'ProfilePath', 'ScriptPath'
)
$users = Get-ADUser -Filter * -Properties $requiredProperties | Sort-Object DisplayName
Progress bar
$progressParams = @{
Activity = "AD hesabatı yaradılır"
Status = "İstifadəçi məlumatları yığılır"
PercentComplete = 0
}
Write-Progress @progressParams
Temp fayl
$tempFile = [System.IO.Path]::GetTempFileName()
$currentProgress = 0
Keşləmə funksiyası
function Get-CachedADComputer {
param([string]$userName)
if ([string]::IsNullOrEmpty($userName)) {
Write-Warning "İstifadəçi adı boşdur"
return $null
}
if (-not $script:computerAccessCache.ContainsKey($userName)) {
try {
$script:computerAccessCache[$userName] = Get-ADComputer -LDAPFilter "(&(LastLogonUserName=$userName))"
}
catch {
Write-Warning "Kompüter məlumatları alınarkən xəta: $_"
$script:computerAccessCache[$userName] = $null
}
}
return $script:computerAccessCache[$userName]
}
Köməkçi funksiya - istifadəçinin şəbəkə əlaqələrini müəyyən etmək
function Get-UserNetworkDetails {
param([string]$userName)
if ([string]::IsNullOrEmpty($userName)) {
Write-Warning "İstifadəçi adı boşdur"
return @{
LastComputers = @()
AllComputers = "İstifadəçi adı təyin edilməyib"
SharedFolders = "İstifadəçi adı təyin edilməyib"
}
}
try {
$computerAccess = $null
if ($script:computerAccessCache.ContainsKey($userName)) {
$computerAccess = $script:computerAccessCache[$userName]
}
else {
$computerAccess = Get-ADComputer -LDAPFilter "(&(LastLogonUserName=$userName))" -Properties Name,LastLogonTimeStamp |
Sort-Object LastLogonTimeStamp -Descending
$script:computerAccessCache[$userName] = $computerAccess
}
Copy    $last5Computers = $computerAccess | Select-Object -First 5 | ForEach-Object {
        @{
            Name = $_.Name
            LastLogon = if ($_.LastLogonTimeStamp) {
                [DateTime]::FromFileTime($_.LastLogonTimeStamp).ToString("dd.MM.yyyy HH:mm")
            } else {
                "Bilinmir"
            }
        }
    }

    $sharedFolderKey = "shared_$userName"
    $sharedFolderAccess = $null
    if ($script:groupMembershipCache.ContainsKey($sharedFolderKey)) {
        $sharedFolderAccess = $script:groupMembershipCache[$sharedFolderKey]
    }
    else {
        $sharedFolderAccess = Get-ADObject -LDAPFilter "(&(objectClass=group)(member=$userName)(|(name=*Share*)(name=*Access*)))"
        $script:groupMembershipCache[$sharedFolderKey] = $sharedFolderAccess
    }

    return @{
        LastComputers = $last5Computers
        AllComputers = if ($computerAccess) { ($computerAccess.Name -join ", ") } else { "Kompüter tapılmadı" }
        SharedFolders = if ($sharedFolderAccess) { ($sharedFolderAccess.Name -join ", ") } else { "Paylaşım tapılmadı" }
    }
}
catch {
    Write-Warning "Şəbəkə məlumatları alınarkən xəta: $_"
    return @{
        LastComputers = @()
        AllComputers = "Məlumat alınmadı: $($_.Exception.Message)"
        SharedFolders = "Məlumat alınmadı: $($_.Exception.Message)"
    }
}
}
Yeni funksiya - istifadəçinin IP ünvanlarını almaq
function Get-UserIPAddresses {
param([string]$userName)
if ([string]::IsNullOrEmpty($userName)) {
return "İstifadəçi adı təyin edilməyib"
}
try {
$filterXPath = "*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='$userName']]"
$events = Get-WinEvent -FilterXPath $filterXPath -LogName 'Security' -MaxEvents 1000 -ErrorAction SilentlyContinue
$ipAddresses = @{}
foreach ($event in $events) {
$xml = [xml]$event.ToXml()
$ipAddress = $xml.Event.EventData.Data |
Where-Object { $.Name -eq 'IpAddress' } |
Select-Object -ExpandProperty '#text'
if ($ipAddress -and $ipAddress -ne '-') {
$ipAddresses[$ipAddress] = $true
}
}
return ($ipAddresses.Keys -join ", ")
}
catch {
Write-Warning "IP ünvanları alınarkən xəta: $"
return "Məlumat alınmadı"
}
}
Şifrə statusunu yoxlayan funksiya
function Get-PasswordStatus {
param($user)
if ($null -eq $user) {
return @{
Status = "Məlumat yoxdur"
Class = "status-warning"
Detail = "İstifadəçi məlumatları əldə edilə bilmədi"
}
}
if (-not $user.PasswordLastSet) {
return @{
Status = "Şifrə Təyin edilməyib"
Class = "status-warning"
Detail = "Şifrə heç vaxt təyin edilməyib"
}
}
try {
if ($user.PasswordNeverExpires) {
return @{
Status = "Heç vaxt bitmir"
Class = "status-info"
Detail = "Şifrə heç vaxt bitmır. Son dəyişilmə: $($user.PasswordLastSet)"
}
}
$maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
if ($maxPasswordAge -eq 0) {
return @{
Status = "Müddət təyin edilməyib"
Class = "status-info"
Detail = "Domain səviyyəsində şifrə müddəti təyin edilməyib"
}
}
$passwordSetDate = $user.PasswordLastSet
$expiryDate = $passwordSetDate.AddDays($maxPasswordAge)
$daysUntilExpiry = ($expiryDate - (Get-Date)).Days
if ($daysUntilExpiry -lt 0) {
return @{
Status = "Müddəti bitib"
Class = "status-error"
Detail = "Şifrənin müddəti $($daysUntilExpiry * -1) gün əvvəl bitib"
}
}
else {
return @{
Status = "Aktiv ($daysUntilExpiry gün qalıb)"
Class = "status-success"
Detail = "Şifrə aktiv. Son dəyişilmə: $($user.PasswordLastSet)"
}
}
}
catch {
Write-Warning "Şifrə statusu yoxlanılarkən xəta: $_"
return @{
Status = "Xəta"
Class = "status-error"
Detail = "Şifrə statusu yoxlanılarkən xəta baş verdi"
}
}
}
function Test-PasswordExpired {
param($user)
if (-not $user.PasswordLastSet) { return $false }
if ($user.PasswordNeverExpires) { return $false }
try {
$maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
if ($maxPasswordAge -eq 0) { return $false }
$passwordAge = ((Get-Date) - $user.PasswordLastSet).Days
return $passwordAge -gt $maxPasswordAge
}
catch {
Write-Warning "Şifrə müddətini yoxlayarkən xəta: $_"
return $false
}
}
Batch processing konfiqurasiyası
$batchSize = 50
$userBatches = for ($i = 0; $i -lt $users.Count; $i += $batchSize) {
@{
Users = $users[$i..([Math]::Min($i + $batchSize - 1, $users.Count - 1))]
BatchNumber = [Math]::Floor($i / $batchSize)
}
}
Users array-ni parallel emal etmək
$maxThreads = [int]$env:NUMBER_OF_PROCESSORS
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)
$runspacePool.Open()
$jobs = @()
foreach ($user in $users) {
$powershell = [powershell]::Create().AddScript({
param($user, $networkDetails, $ipAddresses)
# User məlumatlarının emalı
}).AddArgument($user).AddArgument($networkDetails).AddArgument($ipAddresses)
$powershell.RunspacePool = $runspacePool
$jobs += @{
PowerShell = $powershell
Handle = $powershell.BeginInvoke()
}
}
HTML strukturu və başlıq
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Təfərrüatlı Active Directory İstifadəçi Məlumatları</title>
    <meta charset="UTF-8">
    <style>
        /* Burada CSS kodları */
    </style>
    <script>
        /* Burada JavaScript kodları */
    </script>
</head>
<body>
    <div class="container">
        <h1>Təfərrüatlı Active Directory İstifadəçi Məlumatları</h1>
        <!-- Statistika və axtarış -->
        <table>
            <tr>
                <th>Ad</th>
                <th>Email</th>
                <th>Şöbə</th>
                <th>Son Giriş</th>
                <th>Status</th>
                <th>Şifrə Statusu</th>
            </tr>
"@
Statistika dəyişənləri
$totalUsers = 0
$activeUsers = 0
$deactivatedUsers = 0
$expiredPasswords = 0
$noPasswords = 0
Hər bir istifadəçi üçün məlumatları əlavə etmək
foreach ($user in $users) {
$totalUsers++
if ($user.Enabled) { $activeUsers++ } else { $deactivatedUsers++ }
if (Test-PasswordExpired $user) {
$expiredPasswords++
Write-Warning "Şifrəsi bitmiş hesab tapıldı: $($user.SamAccountName)"
}
if (-not $user.PasswordLastSet) { $noPasswords++ }
Copy$userName = $user.SamAccountName
$userId = $user.DistinguishedName.Replace(',', '_').Replace('=', '_')
$lastLogonDate = if($user.LastLogonDate) {
    $logonDiff = (Get-Date) - $user.LastLogonDate
    if ($logonDiff.Days -eq 0) { "Bu gün" }
    elseif ($logonDiff.Days -eq 1) { "Dünən" }
    else { "$($logonDiff.Days) gün əvvəl" }
} else { "Heç vaxt daxil olmayıb" }
$networkDetails = Get-UserNetworkDetails -userName $userName
$ipAddresses = Get-UserIPAddresses -userName $userName
$userGroups = $user.MemberOf | ForEach-Object {
    try {
        $groupName = (Get-ADGroup $_).Name
        $groupName
    } catch {
        $null
    }
} | Where-Object { $_ -ne $null }
$groupNamesList = $userGroups -join ", "
$organizationalUnit = ($user.DistinguishedName -split ",OU=")[1..$($user.DistinguishedName -split ",OU=").Count] -join ", OU="
$userAccountControl = $user.UserAccountControl
$accountStatus = @(
    if ($userAccountControl -band 2) { "Deaktiv" }
    if ($userAccountControl -band 16) { "Normal hesab" }
    if ($userAccountControl -band 512) { "Standart hesab" }
    if ($userAccountControl -band 2048) { "Parol dəyişdirilməlidir" }
    if ($userAccountControl -band 65536) { "Şifrə heç vaxt müddəti bitmir" }
) -join ", "
$statusHtml = if ($user.Enabled) {
    "<span class='status-active'>Aktiv</span>"
} else {
    "<span class='status-inactive'>Deaktiv</span>"
}
$passwordStatus = Get-PasswordStatus -user $user

$currentProgress++
if ($currentProgress % 10 -eq 0) {
    $progressParams.PercentComplete = ($currentProgress / $users.Count) * 100
    $progressParams.Status = "İstifadəçi emal edilir: $($user.DisplayName)"
    Write-Progress @progressParams
    $progressData = @{
        ProcessedUsers = $currentProgress
        LastProcessedUser = $user.SamAccountName
    }
    $progressData | Export-Clixml -Path $tempFile
}

$htmlContent += @"
    <tr class="user-row" onclick="toggleUserDetails('$userId')" data-name="$($user.DisplayName)">
        <td>$($user.DisplayName)</td>
        <td>$($user.EmailAddress)</td>
        <td>$($user.Department)</td>
        <td>$lastLogonDate</t

#>
 

