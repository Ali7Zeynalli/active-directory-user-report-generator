#1 Active Directory modulunu import edirik
Import-Module ActiveDirectory
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#2 Timer və global dəyişənlər
#Skriptin ümumi icra müddətini ölçmək üçün istifadə olunur.
$totalTimer = [System.Diagnostics.Stopwatch]::StartNew()
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#3 Global keş və StringBuilder
<# $script:computerAccessCache: Kompüter giriş məlumatlarını saxlamaq üçün keş.
$script:groupMembershipCache: Qrup üzvlüyü məlumatlarını saxlamaq üçün keş.
$script:htmlBuilder: HTML çıxışını yaratmaq üçün istifadə olunacaq StringBuilder obyekti. #>
$script:computerAccessCache = @{}
$script:groupMembershipCache = @{}
$script:htmlBuilder = New-Object System.Text.StringBuilder
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#4 Active Directory-dən istifadəçi məlumatlarını əvvəlcədən yükləyirik
<# $requiredProperties: İstifadəçilərdən əldə etmək istədiyimiz bütün xüsusiyyətləri sadalayırıq.
$users: Bütün Active Directory istifadəçilərini və onların müəyyən edilmiş xüsusiyyətlərini 
əldə edirik. Nəticələr DisplayName-ə görə sıralanır. #>
$requiredProperties = @(
    'DisplayName', 'EmailAddress', 'Department', 'LastLogonDate',
    'Enabled', 'PasswordExpired', 'PasswordLastSet', 'PasswordNeverExpires',
    'Title', 'telephoneNumber', 'mobile', 'MemberOf', 'LockedOut',
    'UserAccountControl', 'WhenCreated', 'SamAccountName', 'CN',
    'DistinguishedName', 'HomeDirectory', 'ProfilePath', 'ScriptPath'
)
$users = Get-ADUser -Filter * -Properties $requiredProperties | Sort-Object DisplayName
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#5 Progress bar
<# $progressParams: Progress bar-ın görünüşünü və məzmununu təyin edən parametrlər.
Write-Progress: PowerShell-də progress bar-ı göstərmək üçün istifadə olunan komanda.#>
$progressParams = @{
    Activity = "Active Directory hesabati yaradilir"
    Status = "Istifadeci melumatlari yigilir"
    PercentComplete = 0
}
Write-Progress @progressParams
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#6 Recovery üçün temp fayl
<# $tempFile: Müvəqqəti bir fayl yaradırıq ki, skript yarıda kəsilsə, proqresi bərpa edə bilək.
$currentProgress: Cari proqresi izləmək üçün sayğac. #>
$tempFile = [System.IO.Path]::GetTempFileName()
$currentProgress = 0
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#6 Keşləmə funksiyası - İstifadəçi adına əsasən kompüter məlumatlarını alır və keşləyir
<# Əgər istifadəçi adı boşdursa, xəbərdarlıq verir və null qaytarır.
Əgər istifadəçi üçün kompüter məlumatları artıq keşdə varsa, birbaşa onu qaytarır.
Əks halda, Active Directory-dən kompüter məlumatlarını alır və keşdə saxlayır.
Xəta baş verərsə, xəbərdarlıq verir və null qaytarır.
Bu funksiya, təkrarlanan sorğuları azaltmaq və performansı artırmaq üçün istifadə olunur. #>
function Get-CachedADComputer {
    param([string]$userName)    
    
    if ([string]::IsNullOrEmpty($userName)) {
        Write-Warning "Istifadeci adi boshdur"
        return $null
    }
    
    if (-not $script:computerAccessCache.ContainsKey($userName)) {
        try {
            $script:computerAccessCache[$userName] = Get-ADComputer -LDAPFilter "(&(LastLogonUserName=$userName))"
        }
        catch {
            Write-Warning "Komputer melumatlari alinarken xeta: $_"
            $script:computerAccessCache[$userName] = $null
        }
    }    
    return $script:computerAccessCache[$userName]
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#7 Köməkçi funksiya - İstifadəçinin şəbəkə əlaqələrini müəyyən etmək üçün
<# stifadəçinin şəbəkə detallarını əldə edir.
İstifadəçinin giriş etdiyi kompüterləri və son 5 giriş tarixini alır.
İstifadəçinin paylaşdığı qovluqları tapır.
Bütün məlumatları keşləyir ki, təkrar sorğular zamanı performans artsın.
Xətalar baş verərsə, uyğun xəbərdarlıqlar verir və standart məlumatlar qaytarır.#>
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
#///////////////////////////////////////
        #7.1 Keşdən kompüter məlumatlarını almağa çalışırıq
        $computerAccess = $null
        if ($script:computerAccessCache.ContainsKey($userName)) {
            $computerAccess = $script:computerAccessCache[$userName]
        } else {
            #///////////////////////////////////////
            #7.2 Keşdə yoxdursa, AD-dən alırıq
            $computerAccess = Get-ADComputer -LDAPFilter "(&(LastLogonUserName=$userName))" -Properties Name,LastLogonTimeStamp |
                Sort-Object LastLogonTimeStamp -Descending
                #///////////////////////////////////////
            #7.3 Keşə əlavə edirik
            $script:computerAccessCache[$userName] = $computerAccess
        }
#///////////////////////////////////////
        #7.4 Son 5 kompüteri alırıq
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
#///////////////////////////////////////
        #7.5 Paylaşılan qovluqları keşləyirik
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
 
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#8 İstifadəçinin IP ünvanlarını almaq üçün
<# Verilmiş istifadəçi adına görə Windows Təhlükəsizlik Jurnalından (Security Log) giriş hadisələrini (Event ID 4624) axtarır.
Tapılan hadisələrdən istifadəçinin giriş etdiyi bütün unikal IP ünvanlarını çıxarır.
Əgər istifadəçi adı boşdursa və ya xəta baş verərsə, müvafiq xəbərdarlıq mesajı qaytarır.
Tapılan IP ünvanlarını vergüllə ayrılmış siyahı şəklində qaytarır.
Bu funksiya, istifadəçinin hansı IP ünvanlarından sistemə daxil olduğunu izləməyə imkan verir,#>
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
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#9 Şifrə statusunu yoxlayan funksiya
<# İstifadəçinin şifrə statusunu yoxlayır və müvafiq məlumatları qaytarır.
Əgər istifadəçi məlumatları yoxdursa və ya şifrə təyin edilməyibsə, müvafiq xəbərdarlıq qaytarır.
Şifrənin heç vaxt bitməyəcəyini yoxlayır.
Domain səviyyəsində şifrə siyasətini yoxlayır.
Şifrənin nə vaxt bitəcəyini hesablayır və müvafiq status qaytarır.
Hər bir status üçün HTML-də istifadə olunacaq CSS sinifini də təyin edir.
Bu funksiya, hər bir istifadəçinin şifrə vəziyyətini vizual olaraq göstərmək üçün istifadə olunur və 
administratorlara şifrə idarəetməsində kömək edir.#>
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
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#10 test paswod ucun (Test-PasswordExpired funksiyası)
<#İstifadəçinin şifrəsinin müddətinin bitib-bitmədiyini yoxlayır.
Əgər şifrə heç vaxt təyin edilməyibsə və ya heç vaxt bitmırsə, false qaytarır.
Domain səviyyəsində şifrə siyasətini yoxlayır və maksimum şifrə müddətini alır.
Şifrənin yaşını hesablayır və maksimum müddətlə müqayisə edir.
Əgər şifrənin yaşı maksimum müddətdən böyükdürsə, true qaytarır (yəni şifrənin müddəti bitib).
Xəta baş verərsə, xəbərdarlıq verir və false qaytarır.Bu funksiya, statistika məqsədləri üçün istifadə olunur 
və şifrəsi bitmiş hesabların sayını müəyyən etməyə kömək edir.#>
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
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#11 Batch processing konfiqurasiyası
<#İstifadəçiləri 50-lik qruplara bölür. Hər qrup üçün bir batch obyekti yaradır.
Bu, böyük sayda istifadəçi olduqda emal prosesini daha effektiv edir.#>
$batchSize = 50
$userBatches = for ($i = 0; $i -lt $users.Count; $i += $batchSize) {
    @{
        Users = $users[$i..([Math]::Min($i + $batchSize - 1, $users.Count - 1))]
        BatchNumber = [Math]::Floor($i / $batchSize)
    }
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#12 Users array-ni parallel emal etmək üçün
<#Sistemdəki prosessor sayına əsasən maksimum thread sayını müəyyən edir.
Runspace pool yaradır ki, paralel emal mümkün olsun.Bu, skriptin performansını əhəmiyyətli dərəcədə artırır.#>
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
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#13  HTML strukturu və başlıq
<#HTML sənədinin başlanğıcını yaradır.
CSS stilləri və JavaScript funksiyalarını əlavə edir.
Hesabatın başlığını və əsas strukturunu formalaşdırır.#>
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Məlumatları</title>
    <meta charset="UTF-8">
    <style>
  /* 13.1 Ümumi stillər */
body {
  font-family: 'Segoe UI', Arial, sans-serif;
  background-color: #f0f2f5;
  margin: 0;
  padding: 20px;
}

.container {
  max-width: 1400px;
  margin: 0 auto;
  background-color: #ffffff;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  border-radius: 10px;
  padding: 30px;
}

/*13.2 Başlıq stilleri */
h1, h3, h4, h5, h6 {
  color: #1a73e8;
  margin: 0 0 15px;
  padding-bottom: 8px;
  border-bottom: 2px solid #e0e0e0;
}

h1 {
  text-align: center;
  border-bottom-width: 3px;
}

/*13.3 Statistika və axtarış */
.stats-container {
  display: flex;
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
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.stat-card:hover {
  transform: scale(1.05);
  box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
}

.stat-number {
  font-size: 24px;
  font-weight: bold;
  color: #1a73e8;
}

.search-container {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 20px;
}

#userSearch {
  width: 300px;
  padding: 10px;
  border: 1px solid #dddddd;
  border-radius: 4px;
  transition: all 0.3s ease;
}

#userSearch:focus {
  width: 400px;
  border-color: #1a73e8;
  box-shadow: 0 4px 8px rgba(26, 115, 232, 0.2);
}

/*13.4 Cədvəl */
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
  color: #ffffff;
}

table tr:nth-child(even), table tr:hover {
  background-color: #f9f9f9;
}

.user-row {
  cursor: pointer;
  transition: background-color 0.3s ease;
}

.user-row:hover {
  background-color: #e9f5ff;
}

table td:first-child {
  text-align: center;
  width: 50px;
  font-weight: bold;
}

/*13.5 İstifadəçi detalları */
.user-details {
  display: none;
  background-color: #ffffff;
  border-left: 5px solid #1a73e8;
  padding: 20px;
  margin: 10px 0;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  border-radius: 8px;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
}

.detail-section {
  background-color: #f8f9fa;
  padding: 15px;
  border-radius: 8px;
  border: 1px solid #e0e0e0;
  margin-bottom: 15px;
}

.detail-label {
  font-weight: bold;
  color: #1a73e8;
  margin-right: 10px;
}

.detail-section p {
  margin: 8px 0;
  line-height: 1.6;
}

/*13.6 Status */
.status-active { color: #28a745; }
.status-inactive { color: #dc3545; }
.status-warning { color: #ffc107; }
.status-error { color: #dc3545; }
.status-success { color: #28a745; }
.status-info { color: #17a2b8; }

.status-active, .status-inactive, .status-warning,
.status-error, .status-success, .status-info {
  font-weight: bold;
}
    </style>
<script>
//13.7 Tarix formatını əldə etmək üçün funksiya
function getFormattedDate() {
            const now = new Date();
            return now.toISOString().slice(0, 10) + '_' +
                now.getHours().toString().padStart(2, '0') + '-' +
                now.getMinutes().toString().padStart(2, '0');
        }
////////////////////////////////////////////////////////////////////////////////////////////////////////
//13.8 İstifadəçi detallarını göstərmək/gizlətmək üçün funksiya
        function toggleUserDetails(userId) {
            const details = document.getElementById(userId);
            if (details) {
                details.style.display = details.style.display === 'none' ? 'block' : 'none';
            }
        }
////////////////////////////////////////////////////////////////////////////////////////////////////////
//13.9 İstifadəçiləri axtarmaq üçün funksiya
        function searchUsers() {
            const searchText = document.getElementById('userSearch').value.toLowerCase();
            document.querySelectorAll('.user-row').forEach(row => {
                const name = row.getAttribute('data-name').toLowerCase();
                const nextRow = row.nextElementSibling;
                const show = name.includes(searchText);
                row.style.display = show ? '' : 'none';
                if (nextRow) nextRow.style.display = show ? '' : 'none';
            });
        }
////////////////////////////////////////////////////////////////////////////////////////////////////////
//13.10 Funksiyaları qlobal miqyasda əlçatan etmək
        window.toggleUserDetails = toggleUserDetails;
        window.searchUsers = searchUsers;
</script>
</head>
<body>
                   
    <!--Bu struktur, Active Directory-dəki istifadəçilər haqqında ətraflı məlumatları göstərmək, 
    statistika təqdim etmək və istifadəçiləri axtarmaq üçün nəzərdə tutulub. JavaScript funksiyaları
    ilə birlikdə, bu interaktiv və informativ bir hesabat təşkil edir  --> 

               <!-- yuxardam bos yer saxlayiram--> 
            <h1></h1>     

                    <!-- Statistika bölməsi: --> 

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
                <div>Şifrəsi Təyin Olunmayanlar</div>
            </div>
    </div>
                                    
                                    <!--Axtarış bölməsi--> 
            <div class="search-container">
              <input type="text" id="userSearch" placeholder="İstifadəçi axtar..." oninput="searchUsers()">

            </div>
                                    
                                    <!--Cədvəl başlığı --> 
            <table>
            <tr>
                <th>№</th>
            <th>Ad</th>
            <th>E-poçt</th>
            <th>Şöbə</th>
            <th>Son Giriş</th>
            <th>Status</th>
            <th>Şifrə Statusu</th> 
            </tr>
"@
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#14 Statistika dəyişənləri
<#Bu dəyişənlər hesabatın əvvəlində göstəriləcək ümumi statistika 
üçün istifadə olunur. Hər bir istifadəçi emal edildikdə bu dəyişənlər yenilənəcək.#>
$totalUsers = 0
$activeUsers = 0
$deactivatedUsers = 0
$expiredPasswords = 0
$noPasswords = 0
$userNumber = 0
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#15 Active Directory-dən istifadəçi məlumatlarını alırıq
$users = Get-ADUser -Filter * -Property * | Sort-Object DisplayName
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#16 Hər bir istifadəçi üçün məlumatları əlavə edirik  (burdan baslayir sonda 16 bitir yazilacaq)
<#Bu hissə hər bir istifadəçi üçün: Statistika dəyişənlərini yeniləyir.
İstifadəçinin bütün lazımi məlumatlarını toplayır. Şəbəkə detallarını və IP ünvanlarını əldə edir.
İstifadəçinin üzv olduğu qrupları tapır. Hesab statusunu və şifrə vəziyyətini müəyyən edir.
Bütün bu məlumatları HTML formatında hazırlayır.
Hər 10 istifadəçidən bir progress bar-ı yeniləyir və müvəqqəti faylda proqresi saxlayır.
Bu, skriptin əsas işləyən hissəsidir və bütün məlumatları toplayıb hesabat üçün hazırlayır.#>
foreach ($user in $users) {
    $totalUsers++
    $userNumber++
    if ($user.Enabled) { $activeUsers++ } else { $deactivatedUsers++ }
 if (Test-PasswordExpired $user) {
    $expiredPasswords++
    Write-Warning "Şifrəsi bitmiş hesab tapıldı: $($user.SamAccountName)"
}
    if (-not $user.PasswordLastSet) { $noPasswords++ } 
#//////////////////////////////////////
    #16.1 Əsas istifadəçi məlumatları
    $userName = $user.SamAccountName
    $userId = $user.DistinguishedName.Replace(',', '_').Replace('=', '_')
#//////////////////////////////////////
    #16.2 Son giriş tarixi
    $lastLogonDate = if ($user.LastLogonDate) { 
        $logonDiff = (Get-Date) - $user.LastLogonDate
        if ($logonDiff.Days -eq 0) { "Bu gün" }
        elseif ($logonDiff.Days -eq 1) { "Dünən" }
        else { "$($logonDiff.Days) gün əvvəl" }
    } else { "Heç vaxt daxil olmayıb" }
#//////////////////////////////////////
    #16.3 Şəbəkə detalları
    $networkDetails = Get-UserNetworkDetails -userName $userName
#//////////////////////////////////////
    #16.4 IP ünvanları
    $ipAddresses = Get-UserIPAddresses -userName $userName
#//////////////////////////////////////
    #16.5 Qrupları toplayırıq
    $userGroups = $user.MemberOf | ForEach-Object {
        try {
            $groupName = (Get-ADGroup $_).Name
            $groupName
        } catch {
            $null
        }
    } | Where-Object { $_ -ne $null }
#//////////////////////////////////////
    #16.6 Qrup adlarını siyahıya çeviririk
    $groupNamesList = $userGroups -join ", "
#//////////////////////////////////////
    #16.7 Organizasiya vahidini (OU) alırıq
    $organizationalUnit = ($user.DistinguishedName -split ",OU=")[1..$($user.DistinguishedName -split ",OU=").Count] -join ", OU="
#//////////////////////////////////////
    #16.8 Səlahiyyətləri müəyyən edirik
    $userAccountControl = $user.UserAccountControl
    $accountStatus = @(
        if ($userAccountControl -band 2) { "Deaktiv" }
        if ($userAccountControl -band 16) { "Normal hesab" }
        if ($userAccountControl -band 512) { "Standart hesab" }
        if ($userAccountControl -band 2048) { "Parol dəyişdirilməlidir" }
        if ($userAccountControl -band 65536) { "Şifrə heç vaxt müddəti bitmir" }
    ) -join ", "
#//////////////////////////////////////
    #16.9 Status style
    $statusHtml = if ($user.Enabled) {
        "<span class='status-active'>Aktiv</span>"
    } else {
        "<span class='status-inactive'>Deaktiv</span>"
    }
#//////////////////////////////////////
    #16.10 password statusu
$passwordStatus = Get-PasswordStatus -user $user
#//////////////////////////////////////
#16.11 Progress bar-ı yeniləyirik (Mövcud foreach dövrəsində (foreach ($user in $users)) hər 10 istifadəçidən bir əlavə etmək: 
    $currentProgress++
if ($currentProgress % 10 -eq 0) {
    $progressParams.PercentComplete = ($currentProgress / $users.Count) * 100
    $progressParams.Status = "İstifadəçi emal edilir: $($user.DisplayName)"
    Write-Progress @progressParams
#//////////////////////////////////////
    #16.12 Progress məlumatlarını temp faylda saxlayırıq
    $progressData = @{
        ProcessedUsers = $currentProgress
        LastProcessedUser = $user.SamAccountName
    }
    $progressData | Export-Clixml -Path $tempFile
}#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
     #17 HTML cədvəlinə istifadəçi məlumatlarını əlavə edirik
     #<!--İstifadəçi sətri (Bu sətir hər bir istifadəçi üçün əsas məlumatları göstərir.onclick eventi ilə istifadəçi detallarını açıb-bağlamaq mümkündür.
     $htmlContent += @"
      
     <tr class="user-row" onclick="toggleUserDetails('$userId')" data-name="$($user.DisplayName)">
      <td style="text-align: center; width: 50px; font-weight: bold;">$userNumber</td>
          <td>$($user.DisplayName)</td>
          <td>$($user.EmailAddress)</td>
          <td>$($user.Department)</td>
          <td>$lastLogonDate</td>
          <td>$statusHtml</td>
           <td class="$($passwordStatus.Class)">$($passwordStatus.Status)</td>
          
      </tr>
      <tr>
          <td colspan="7">
              <div id="$userId" class="user-details">
                  <div class="detail-grid">
                      <div class="detail-section">
                          <h3>$($user.DisplayName) Əsas Məlumatlar</h3>
                          <p><span class="detail-label">Istifadəçi Adı:</span> $($user.SamAccountName)</p>
                          <p><span class="detail-label">Email:</span> $($user.EmailAddress)</p>
                          <p><span class="detail-label">Tam Ad:</span> $($user.CN)</p>
                          <p><span class="detail-label">Teşkilat Vahidi (OU):</span> $organizationalUnit</p>
                      </div>

                      <div class="detail-section">
                          <h4>Hesab Məlumatları</h4>
                          <p><span class="detail-label">Hesab Statusu:</span> $accountStatus</p>
                          <p><span class="detail-label">Son Giriş Tarixi:</span> $($user.LastLogonDate)</p>
                          <p><span class="detail-label">Hesab Yaradılma Tarixi:</span> $($user.WhenCreated.ToString("dd.MM.yyyy HH:mm:ss"))</p>
                          <p><span class="detail-label">Şifrə Son Dəyişilmə:</span> $($user.PasswordLastSet)</p>
                          <p><span class="detail-label">Hesab Kilidlənib:</span> $(if ($user.LockedOut) { "Beli" } else { "Xeyr" })</p>
                      </div>

                      <div class="detail-section">
                          <h4>Teşkilat Məlumatları</h4>
                          <p><span class="detail-label">Şöbə:</span> $($user.Department)</p>
                          <p><span class="detail-label">Vəzifə:</span> $($user.Title)</p>
                          <p><span class="detail-label">Telefon:</span> $($user.telephoneNumber)</p>
                          <p><span class="detail-label">Mobil Telefon:</span> $($user.mobile)</p>
                      </div>

                  

                  

                      <div class="detail-section">
                          <h4>Şəbəkə Məlumatları</h4>
                          <p><span class="detail-label">Bütün Giriş Etdiyi Komputerlər:</span> $($networkDetails.AllComputers)</p>
                          <p><span class="detail-label">Paylaşilan Qovluqlar:</span> $($networkDetails.SharedFolders)</p>
                          <p><span class="detail-label">Üzv Olduğu Qruplar:</span> $groupNamesList</p>
                          
                          <p><span class="detail-label">İP Ünvanları:</span> $ipAddresses</p>
                      </div>

                   
                     
                  </div>
              </div>
          </td>
      </tr>
"@
}

#17.1 HTML faylının sonunu əlavə edirik
<# HTML faylını tamamlayır, statistika məlumatlarını JavaScript vasitəsilə əlavə edir.
Bu son hissə cədvəli bağlayır və JavaScript vasitəsilə statistika məlumatlarını yeniləyir. 
Hər bir statistika elementi müvafiq ID-yə malik elementin mətnini yeniləyir.#> 
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
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#18 HTML faylının adını formalaşdırma (Hesabat faylı üçün ad yaradır (tarix və vaxt əlavə edərək))
$reportDate = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$outputPath = "C:\Reports\AD\AD_Users_Comprehensive_Report_$reportDate.html"
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#19 Qovluğun mövcudluğunu yoxlayırıq və lazım olduqda yaradırıq(Hesabatın saxlanacağı qovluğu yoxlayır və lazım olduqda yaradır.)
$reportFolder = Split-Path $outputPath -Parent
if (!(Test-Path $reportFolder)) {
    New-Item -Path $reportFolder -ItemType Directory -Force
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#20 Performance məlumatlarını loglamaq (Ümumi icra vaxtını hesablayır və göstərir.)
$totalTimer.Stop()
Write-Host "Umumi icra vaxti: $($totalTimer.Elapsed.TotalSeconds) saniye" -ForegroundColor Cyan
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#22 Faylı yaradırıq (HTML faylını yaradır və UTF-8 kodlaşdırması ilə saxlayır.)
$htmlContent | Out-File -FilePath $outputPath -Encoding UTF8
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#23 HTML faylını brauzerdə açırıq(Yaradılmış hesabat faylını avtomatik olaraq brauzerdə açır.)
Start-Process $outputPath
Write-Host "Hesabat ugurla yaradildi ve brauzerde achildi: $outputPath" -ForegroundColor Green
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#24 Müvəqqəti faylları təmizləmək Müvəqqəti faylları silir.
if (Test-Path $tempFile) {
    Remove-Item $tempFile -Force
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#25 Yaddaşı bir daha təmizləyir.
$users = $null
$htmlContent = $null
[System.GC]::Collect()
