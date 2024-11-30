# Active Directory modulunu import edirik
Import-Module ActiveDirectory


# Timer və global dəyişənlər
$totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

# Global keş və StringBuilder
$script:computerAccessCache = @{}
$script:groupMembershipCache = @{}
$script:htmlBuilder = New-Object System.Text.StringBuilder






# Active Directory-dən istifadəçi məlumatlarını əvvəlcədən yükləyirik
$requiredProperties = @(
    'DisplayName', 'EmailAddress', 'Department', 'LastLogonDate',
    'Enabled', 'PasswordExpired', 'PasswordLastSet', 'PasswordNeverExpires',
    'Title', 'telephoneNumber', 'mobile', 'MemberOf', 'LockedOut',
    'UserAccountControl', 'WhenCreated', 'SamAccountName', 'CN',
    'DistinguishedName', 'HomeDirectory', 'ProfilePath', 'ScriptPath'
)

$users = Get-ADUser -Filter * -Properties $requiredProperties | Sort-Object DisplayName






# Progress bar
$progressParams = @{
    Activity = "Active Directory hesabatı yaradılır"
    Status = "İstifadəçi məlumatları yığılır"
    PercentComplete = 0
}
Write-Progress @progressParams

# Recovery üçün temp fayl
$tempFile = [System.IO.Path]::GetTempFileName()
$currentProgress = 0


# Keşləmə funksiyası - düzəldilmiş versiya
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






# Köməkçi funksiya - İstifadəçinin şəbəkə əlaqələrini müəyyən etmək üçün
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
        # Keşdən kompüter məlumatlarını almağa çalışırıq
        $computerAccess = $null
        if ($script:computerAccessCache.ContainsKey($userName)) {
            $computerAccess = $script:computerAccessCache[$userName]
        } else {
            # Keşdə yoxdursa, AD-dən alırıq
            $computerAccess = Get-ADComputer -LDAPFilter "(&(LastLogonUserName=$userName))" -Properties Name,LastLogonTimeStamp |
                Sort-Object LastLogonTimeStamp -Descending
            # Keşə əlavə edirik
            $script:computerAccessCache[$userName] = $computerAccess
        }

        # Son 5 kompüteri alırıq
        $last5Computers = $computerAccess | Select-Object -First 5 | ForEach-Object {
            @{
                Name = $_.Name
                LastLogon = if ($_.LastLogonTimeStamp) {
                    [DateTime]::FromFileTime($_.LastLogonTimeStamp).ToString("dd.MM.yyyy HH:mm")
                } else {
                    "Bilinmir"
                }
            }
        }

        # Paylaşılan qovluqları keşləyirik
        $sharedFolderKey = "shared_$userName"
        $sharedFolderAccess = $null
        if ($script:groupMembershipCache.ContainsKey($sharedFolderKey)) {
            $sharedFolderAccess = $script:groupMembershipCache[$sharedFolderKey]
        } else {
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









# Yeni funksiya - İstifadəçinin IP ünvanlarını almaq üçün
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
                Where-Object { $_.Name -eq 'IpAddress' } | 
                Select-Object -ExpandProperty '#text'
            
            if ($ipAddress -and $ipAddress -ne '-') {
                $ipAddresses[$ipAddress] = $true
            }
        }

        return ($ipAddresses.Keys -join ", ")
    }
    catch {
        Write-Warning "IP ünvanları alınarkən xəta: $_"
        return "Məlumat alınmadı"
    }
}





# Şifrə statusunu yoxlayan funksiya
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

#yeni test paswod ucun
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














# Batch processing konfiqurasiyası
$batchSize = 50
$userBatches = for ($i = 0; $i -lt $users.Count; $i += $batchSize) {
    @{
        Users = $users[$i..([Math]::Min($i + $batchSize - 1, $users.Count - 1))]
        BatchNumber = [Math]::Floor($i / $batchSize)
    }
}






# Users array-ni parallel emal etmək üçün
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







# HTML strukturu və başlıq
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Təfərrüatlı Active Directory İstifadəçi Məlumatları</title>
    <meta charset="UTF-8">
    <style>
        .stat-card:hover {
            transform: scale(1.05);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
        }
        
            
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background-color: #f0f2f5; 
                    margin: 0; 
                    padding: 20px;
                }
                .container { 
                    max-width: 1400px;
                    margin: 0 auto;
                    background-color: white; 
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1); 
                    border-radius: 10px; 
                    padding: 30px;
                }
                h1 { 
                    color: #1a73e8; 
                    text-align: center; 
                    border-bottom: 3px solid #1a73e8; 
                    padding-bottom: 15px;
                }
                .stats-container {
                    display: flex;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    justify-content: space-between;
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .stat-card {
                    background: #f8f9fa;
                    padding: 10px 15px;
                    border-radius: 10px;
                    text-align: center;
                    width: 23%;
                    color: #023047;
                }
        
        #userSearch {
            transition: all 0.3s ease;
        }
        
        #userSearch:focus {
            width: 400px;
            border-color: #1a73e8;
            box-shadow: 0 4px 8px rgba(26, 115, 232, 0.2);
        }
        
        
        table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        
        table tr:hover {
            background-color: #e9f5ff;
        }
        
        
        
        
                .stat-number {
                    font-size: 24px;
                    font-weight: bold;
                    color: #1a73e8;
                }
                table { 
                    
                    width: 100%; 
                    border-collapse: collapse; 
                }
                th, td { 
                    padding: 12px; 
                    text-align: left; 
                    border-bottom: 1px solid #e0e0e0; 
                }
                th { 
                    background-color: #1a73e8; 
                    color: white; 
                }
                .user-row { 
                    cursor: pointer; 
                    transition: background-color 0.3s ease;
                }
                .user-row:hover { 
                    background-color: #f1f1f1; 
                }
                .user-details { 
                    display: none; 
                    background-color: #f9f9f9; 
                    border-left: 5px solid #1a73e8; 
                    padding: 20px; 
                    margin-top: 10px;
                }
                .detail-section {
                    margin-bottom: 15px;
                    padding: 15px;
                    background-color: #f4f4f4;
                    border-radius: 5px;
                    border: 1px solid #e0e0e0;
                }
                .detail-label {
                    font-weight: bold;
                    color: #1a73e8;
                    margin-right: 10px;
                }
                .search-container {
                    display: flex;
            justify-content: flex-end; 
                    margin-bottom: 20px;
                    text-align: center;
                }
                #userSearch {
                    width: 300px;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }
                .status-active {
                    color: #28a745;
                    font-weight: bold;
                }
                .status-inactive {
                    color: #dc3545;
                    font-weight: bold;
                }
                .computer-list {
                    list-style: none;
                    padding: 0;
                    margin: 0;
                }
                .computer-list li {
                    padding: 8px;
                    border-bottom: 1px solid #dee2e6;
                }
                .computer-list li:last-child {
                    border-bottom: none;
                }
                .detail-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                }
        




        /* Bu hissəni table tr:hover stilindən sonra əlavə edin */
    .status-warning {
        color: #ffc107;
        font-weight: bold;
    }
    .status-error {
        color: #dc3545;
        font-weight: bold;
    }
    .status-success {
        color: #28a745;
        font-weight: bold;
    }
    .status-info {
        color: #17a2b8;
        font-weight: bold;
    }










        
    </style>
    <script>
        function toggleUserDetails(userId) {
            const detailsDiv = document.getElementById(userId);
            detailsDiv.style.display = detailsDiv.style.display === 'block' ? 'none' : 'block';
        }

        function searchUsers() {
            const searchInput = document.getElementById('userSearch').value.toLowerCase();
            const rows = document.querySelectorAll('.user-row');
            
            rows.forEach(row => {
                const userName = row.getAttribute('data-name').toLowerCase();
                const nextRow = row.nextElementSibling;
                
                if (userName.includes(searchInput)) {
                    row.style.display = '';
                    nextRow.style.display = '';
                } else {
                    row.style.display = 'none';
                    nextRow.style.display = 'none';
                }
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>Təfərrüatlı Active Directory İstifadəçi Məlumatları</h1>
        
        <div class="stats-container">
            <div class="stat-card" style="background: #bde0fe;">
                <div class="stat-number" id="totalUsers">0</div>
                <div>Ümumi İstifadəçilər</div>
            </div>
            <div class="stat-card" style="background: #a2d2ff;">
                <div class="stat-number" id="activeUsers">0</div>
                <div>Aktiv İstifadəçilər</div>
            </div>
            <div class="stat-card" style="background: #cdb4db;">
                <div class="stat-number" id="deactivatedUsers">0</div>
                <div>Deaktiv Hesablar</div>
            </div>
               <div class="stat-card" style="background: #ffc8dd;">
                <div class="stat-number" id="expiredPasswords">0</div>
                <div>Şifrəsi Bitmiş Hesablar</div>
                </div>

                   <div class="stat-card" style="background: #ffc8dd;">
        <div class="stat-number" id="noPasswords">0</div>
        <div>Şifrəsi Təyin Olmayanlar</div>
            
            </div>
        </div>

        <div class="search-container">
            <input type="text" id="userSearch" placeholder="İstifadəçi axtar..." oninput="searchUsers()">
        </div>
        
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

# Statistika dəyişənləri
$totalUsers = 0
$activeUsers = 0
$deactivatedUsers = 0
$expiredPasswords = 0
$noPasswords = 0

# Active Directory-dən istifadəçi məlumatlarını alırıq
$users = Get-ADUser -Filter * -Property * | Sort-Object DisplayName

# Hər bir istifadəçi üçün məlumatları əlavə edirik
foreach ($user in $users) {
    $totalUsers++
    if ($user.Enabled) { $activeUsers++ } else { $deactivatedUsers++ }
 if (Test-PasswordExpired $user) {
    $expiredPasswords++
    Write-Warning "Şifrəsi bitmiş hesab tapıldı: $($user.SamAccountName)"
}
    if (-not $user.PasswordLastSet) { $noPasswords++ } 




    # Əsas istifadəçi məlumatları
    $userName = $user.SamAccountName
    $userId = $user.DistinguishedName.Replace(',', '_').Replace('=', '_')
    
    # Son giriş tarixi
    $lastLogonDate = if($user.LastLogonDate) { 
        $logonDiff = (Get-Date) - $user.LastLogonDate
        if ($logonDiff.Days -eq 0) { "Bu gün" }
        elseif ($logonDiff.Days -eq 1) { "Dünən" }
        else { "$($logonDiff.Days) gün əvvəl" }
    } else { "Heç vaxt daxil olmayıb" }
    
    # Şəbəkə detalları
    $networkDetails = Get-UserNetworkDetails -userName $userName
    
    # IP ünvanları
    $ipAddresses = Get-UserIPAddresses -userName $userName
    
    # Qrupları toplayırıq
    $userGroups = $user.MemberOf | ForEach-Object {
        try {
            $groupName = (Get-ADGroup $_).Name
            $groupName
        } catch {
            $null
        }
    } | Where-Object { $_ -ne $null }
    
    # Qrup adlarını siyahıya çeviririk
    $groupNamesList = $userGroups -join ", "
    
    # Organizasiya vahidini (OU) alırıq
    $organizationalUnit = ($user.DistinguishedName -split ",OU=")[1..$($user.DistinguishedName -split ",OU=").Count] -join ", OU="

    # Səlahiyyətləri müəyyən edirik
    $userAccountControl = $user.UserAccountControl
    $accountStatus = @(
        if ($userAccountControl -band 2) { "Deaktiv" }
        if ($userAccountControl -band 16) { "Normal hesab" }
        if ($userAccountControl -band 512) { "Standart hesab" }
        if ($userAccountControl -band 2048) { "Parol dəyişdirilməlidir" }
        if ($userAccountControl -band 65536) { "Şifrə heç vaxt müddəti bitmir" }
    ) -join ", "

    # Status style
    $statusHtml = if ($user.Enabled) {
        "<span class='status-active'>Aktiv</span>"
    } else {
        "<span class='status-inactive'>Deaktiv</span>"
    }

    # Yeni əlavə - şifrə statusu
$passwordStatus = Get-PasswordStatus -user $user
    
    
    #Mövcud foreach dövrəsində (foreach ($user in $users)) hər 10 istifadəçidən bir əlavə etmək:
    
   
    $currentProgress++
if ($currentProgress % 10 -eq 0) {
    $progressParams.PercentComplete = ($currentProgress / $users.Count) * 100
    $progressParams.Status = "İstifadəçi emal edilir: $($user.DisplayName)"
    Write-Progress @progressParams
    
    # Progress məlumatlarını temp faylda saxlayırıq
    $progressData = @{
        ProcessedUsers = $currentProgress
        LastProcessedUser = $user.SamAccountName
    }
    $progressData | Export-Clixml -Path $tempFile
}
    
    
    
    
    
    
    
    # HTML cədvəlinə istifadəçi məlumatlarını əlavə edirik
    $htmlContent += @"
        <tr class="user-row" onclick="toggleUserDetails('$userId')" data-name="$($user.DisplayName)">
            <td>$($user.DisplayName)</td>
            <td>$($user.EmailAddress)</td>
            <td>$($user.Department)</td>
            <td>$lastLogonDate</td>
            <td>$statusHtml</td>
             <td class="$($passwordStatus.Class)">$($passwordStatus.Status)</td>
            
        </tr>
        <tr>
            <td colspan="5">
                <div id="$userId" class="user-details">
                    <div class="detail-grid">
                        <div class="detail-section">
                            <h3>$($user.DisplayName) - Əsas Məlumatlar</h3>
                            <p><span class="detail-label">İstifadəçi Adı:</span> $($user.SamAccountName)</p>
                            <p><span class="detail-label">Email:</span> $($user.EmailAddress)</p>
                            <p><span class="detail-label">Tam Ad:</span> $($user.CN)</p>
                            <p><span class="detail-label">Təşkilat Vahidi (OU):</span> $organizationalUnit</p>
                        </div>

                        <div class="detail-section">
                            <h4>Hesab Məlumatları</h4>
                            <p><span class="detail-label">Hesab Statusu:</span> $accountStatus</p>
                            <p><span class="detail-label">Son Giriş Tarixi:</span> $($user.LastLogonDate)</p>
                            <p><span class="detail-label">Hesab Yaradılma Tarixi:</span> $($user.WhenCreated.ToString("dd.MM.yyyy HH:mm:ss"))</p>
                            <p><span class="detail-label">Şifrə Son Dəyişilmə:</span> $($user.PasswordLastSet)</p>
                            <p><span class="detail-label">Hesab Kilidlənib:</span> $(if ($user.LockedOut) { "Bəli" } else { "Xeyr" })</p>
                        </div>

                        <div class="detail-section">
                            <h4>Təşkilati Məlumatlar</h4>
                            <p><span class="detail-label">Şöbə:</span> $($user.Department)</p>
                            <p><span class="detail-label">Vəzifə:</span> $($user.Title)</p>
                            <p><span class="detail-label">Telefon:</span> $($user.telephoneNumber)</p>
                            <p><span class="detail-label">Mobil Telefon:</span> $($user.mobile)</p>
                        </div>

                    

                        </div>

                        <div class="detail-section">
                            <h4>Şəbəkə Məlumatları</h4>
                            <p><span class="detail-label">Bütün Giriş Etdiyi Kompüterlər:</span> $($networkDetails.AllComputers)</p>
                            <p><span class="detail-label">Paylaşılan Qovluqlar:</span> $($networkDetails.SharedFolders)</p>
                            <p><span class="detail-label">Üzv Olduğu Qruplar:</span> $groupNamesList</p>
                            <h4>IP Ünvanları</h4>
                            <p><span class="detail-label">Son İstifadə Edilən IP Ünvanları:</span> $ipAddresses</p>
                        </div>

                     
                       
                    </div>
                </div>
            </td>
        </tr>
"@
}

# HTML faylının sonunu əlavə edirik
$htmlContent += @"
        </table>
    </div>
    <script>
        document.getElementById('totalUsers').textContent = '$totalUsers';
        document.getElementById('activeUsers').textContent = '$activeUsers';
        document.getElementById('deactivatedUsers').textContent = '$deactivatedUsers';
        document.getElementById('expiredPasswords').textContent = '$expiredPasswords';
        document.getElementById('noPasswords').textContent = '$noPasswords';  <!-- Yeni əlavə -->
    </script>
</body>
</html>
"@

# HTML faylının adını formalaşdırma
$reportDate = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$outputPath = "C:\Reports\AD\AD_Users_Comprehensive_Report_$reportDate.html"

# Qovluğun mövcudluğunu yoxlayırıq və lazım olduqda yaradırıq
$reportFolder = Split-Path $outputPath -Parent
if (!(Test-Path $reportFolder)) {
    New-Item -Path $reportFolder -ItemType Directory -Force
}


# Performance məlumatlarını loglamaq
$totalTimer.Stop()
Write-Host "Ümumi icra vaxtı: $($totalTimer.Elapsed.TotalSeconds) saniyə" -ForegroundColor Cyan

# Resursları təmizləmək
[System.GC]::Collect()



# Faylı yaradırıq
$htmlContent | Out-File -FilePath $outputPath -Encoding UTF8

# HTML faylını brauzerdə açırıq
Start-Process $outputPath

Write-Host "Hesabat uğurla yaradıldı və brauzerdə açıldı: $outputPath" -ForegroundColor Green

# Müvəqqəti faylları təmizləmək
if (Test-Path $tempFile) {
    Remove-Item $tempFile -Force
}

# Yaddaşı təmizləmək
$users = $null
$htmlContent = $null
[System.GC]::Collect()
