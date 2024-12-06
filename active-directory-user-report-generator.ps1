#1 Import the Active Directory module
Import-Module ActiveDirectory
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#2 Timer and global variables
#Used to measure the total execution time of the script.
$totalTimer = [System.Diagnostics.Stopwatch]::StartNew()
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#3 Global cache and StringBuilder
<# $script:computerAccessCache: Cache for storing computer access information.
$script:groupMembershipCache: Cache for storing group membership information.
$script:htmlBuilder: StringBuilder object to be used for creating HTML output. #>
$script:computerAccessCache = @{}
$script:groupMembershipCache = @{}
$script:htmlBuilder = New-Object System.Text.StringBuilder
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#4 Preload user information from Active Directory
<# $requiredProperties: List all the properties we want to retrieve from users.
$users: Retrieve all Active Directory users and their specified properties.
Results are sorted by DisplayName. #>
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
<# $progressParams: Parameters to define the appearance and content of the progress bar.
Write-Progress: Command used to display a progress bar in PowerShell. #>
$progressParams = @{
    Activity = "Creating Active Directory report"
    Status = "Gathering user information"
    PercentComplete = 0
}
Write-Progress @progressParams
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#6 Temporary file for recovery
<# $tempFile: Create a temporary file so that we can restore the progress if the script is interrupted.
$currentProgress: Counter to track the current progress. #>
$tempFile = [System.IO.Path]::GetTempFileName()
$currentProgress = 0
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#6 Caching function - Retrieves computer information based on the user name and caches it
<# If the user name is empty, it displays a warning and returns null.
If the computer information for the user is already in the cache, it directly returns it.
Otherwise, it retrieves the computer information from Active Directory and stores it in the cache.
If an error occurs, it displays a warning and returns null.
This function is used to reduce repeated queries and improve performance. #>
function Get-CachedADComputer {
    param([string]$userName)    
    
    if ([string]::IsNullOrEmpty($userName)) {
        Write-Warning "User name is empty"
        return $null
    }
    
    if (-not $script:computerAccessCache.ContainsKey($userName)) {
        try {
            $script:computerAccessCache[$userName] = Get-ADComputer -LDAPFilter "(&(LastLogonUserName=$userName))"
        }
        catch {
            Write-Warning "Error retrieving computer information:  $_"
            $script:computerAccessCache[$userName] = $null
        }
    }    
    return $script:computerAccessCache[$userName]
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#7 Helper function - Determine the user's network connections
<# Retrieves the user's network details.
Obtains the computers the user has logged in to and the last 5 login dates.
Finds the shared folders the user has access to.
Caches all the information to improve performance for repeated queries.
If errors occur, it displays appropriate warnings and returns default data. #>
function Get-UserNetworkDetails {
    param([string]$userName)
    
    if ([string]::IsNullOrEmpty($userName)) {
        Write-Warning "User name is empty"
        return @{
            LastComputers = @()
            AllComputers = "User name not specified"
            SharedFolders = "User name not specified"
        }
    }
    
    try {
#///////////////////////////////////////
        #7.1 7.1 Attempt to retrieve computer information from the cache
        $computerAccess = $null
        if ($script:computerAccessCache.ContainsKey($userName)) {
            $computerAccess = $script:computerAccessCache[$userName]
        } else {
            #///////////////////////////////////////
            #7.2 If not in the cache, retrieve from AD
            $computerAccess = Get-ADComputer -LDAPFilter "(&(LastLogonUserName=$userName))" -Properties Name,LastLogonTimeStamp |
                Sort-Object LastLogonTimeStamp -Descending
                #///////////////////////////////////////
            #7.3 Add to the cache
            $script:computerAccessCache[$userName] = $computerAccess
        }
#///////////////////////////////////////
        #7.4 Get the last 5 computers
        $last5Computers = $computerAccess | Select-Object -First 5 | ForEach-Object {
            @{
                Name = $_.Name
                LastLogon = if ($_.LastLogonTimeStamp) {
                    [DateTime]::FromFileTime($_.LastLogonTimeStamp).ToString("dd.MM.yyyy HH:mm")
                } else {
                    "Unknown"
                }
            }
        }
#///////////////////////////////////////
        # 7.5 Cache the shared folder information
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
            AllComputers = if ($computerAccess) { ($computerAccess.Name -join ", ") } else { "No computers found" }
            SharedFolders = if ($sharedFolderAccess) { ($sharedFolderAccess.Name -join ", ") } else { "No shared folders found" }
        }
    }
    catch {
        Write-Warning "Error retrieving network information: $_"
        return @{
            LastComputers = @()
            AllComputers = "Data not retrieved: $($_.Exception.Message)"
            SharedFolders = "Data not retrieved: $($_.Exception.Message)"
        }
    }
}   
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#8 Get the user's IP addresses
<# Searches for login events (Event ID 4624) in the Windows Security Log based on the given user name.
Extracts all unique IP addresses the user has logged in from.
If the user name is empty or an error occurs, it returns an appropriate warning message.
Returns the list of IP addresses separated by commas.
This function allows tracking the IP addresses the user has logged in from. #>
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
        Write-Warning "Error retrieving IP addresses: $_"
        return "Data not retrieved"
    }
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#9 Function to check password status
<# Checks the user's password status and returns the corresponding information.
If the user information is not available or the password is not set, it returns an appropriate warning.
Checks if the password will never expire.
Checks the domain-level password policy.
Calculates when the password will expire and returns the appropriate status.
Also defines the CSS class to be used for each status in HTML.
This function is used to visually show the password status of each user and
helps administrators with password management. #>
function Get-PasswordStatus {
    param($user)
    
    if ($null -eq $user) {
        return @{
            Status = "No data"
            Class = "status-warning"
            Detail = "Could not retrieve user information"
        }
    }
    
    if (-not $user.PasswordLastSet) {
        return @{
            Status = "Password Not Set"
            Class = "status-warning"
            Detail = "Password has never been set"
        }
    }

    try {
        if ($user.PasswordNeverExpires) {
            return @{
                Status = "Never Expires"
                Class = "status-info"
                Detail = "Password never expires. Last changed: $($user.PasswordLastSet)"
            }
        }

        $maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
        if ($maxPasswordAge -eq 0) {
            return @{
                Status = "No Expiration Set"
                Class = "status-info"
                Detail = "No password expiration policy set at the domain level"
            }
        }

        $passwordSetDate = $user.PasswordLastSet
        $expiryDate = $passwordSetDate.AddDays($maxPasswordAge)
        $daysUntilExpiry = ($expiryDate - (Get-Date)).Days

        if ($daysUntilExpiry -lt 0) {
            return @{
                Status = "Expired"
                Class = "status-error"
                Detail = "Password expired $($daysUntilExpiry * -1) days ago"
            }
        }
        else {
            return @{
                Status = "Active ($daysUntilExpiry days remaining)"
                Class = "status-success"
                Detail = "Password is active. Last changed: $($user.PasswordLastSet)"
            }
        }
    }
    catch {
        Write-Warning "Error checking password status: $_"
        return @{
            Status = "Error"
            Class = "status-error"
            Detail = "Error occurred while checking password status"
        }
    }
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#10 Test password expiration (Test-PasswordExpired function)
<#Checks if the user's password has expired.
If the password has never been set or never expires, it returns false.
Checks the domain-level password policy and retrieves the maximum password age.
Calculates the age of the password and compares it to the maximum age.
If the password age is greater than the maximum age, it returns true (i.e., the password has expired).
If an error occurs, it displays a warning and returns false.
This function is used for statistical purposes
and helps determine the number of accounts with expired passwords.#>
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
        Write-Warning "Error checking password expiration: $_"
    return $false
    }
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#11 Batch processing configuration
<#Splits the users into groups of 50. Creates a batch object for each group.
This makes the processing more efficient when there are a large number of users.#>
$batchSize = 50
$userBatches = for ($i = 0; $i -lt $users.Count; $i += $batchSize) {
@{
Users = $users[$i..([Math]::Min($i + $batchSize - 1, $users.Count - 1))]
BatchNumber = [Math]::Floor($i / $batchSize)
}
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#12 Parallel processing of the users array
<#Determines the maximum number of threads based on the number of processors in the system.
Creates a runspace pool to enable parallel processing. This significantly improves the script's performance.#>
$maxThreads = [int]$env:NUMBER_OF_PROCESSORS
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)
$runspacePool.Open()
$jobs = @()
foreach ($user in $users) {
    $powershell = [powershell]::Create().AddScript({
        param($user, $networkDetails, $ipAddresses)
# Process user information
    }).AddArgument($user).AddArgument($networkDetails).AddArgument($ipAddresses)
    $powershell.RunspacePool = $runspacePool
    $jobs += @{
        PowerShell = $powershell
        Handle = $powershell.BeginInvoke()
    }
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#13. HTML structure and header
<# Creates the beginning of the HTML document.
Adds CSS styles and JavaScript functions.
Formulates the report title and main structure. #>
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Detailed Active Directory User Information</title>
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
//13.7 Function to get the formatted date
function getFormattedDate() {
            const now = new Date();
            return now.toISOString().slice(0, 10) + '_' +
                now.getHours().toString().padStart(2, '0') + '-' +
                now.getMinutes().toString().padStart(2, '0');
        }
////////////////////////////////////////////////////////////////////////////////////////////////////////
//13.8 Function to show/hide user details
        function toggleUserDetails(userId) {
            const details = document.getElementById(userId);
            if (details) {
                details.style.display = details.style.display === 'none' ? 'block' : 'none';
            }
        }
////////////////////////////////////////////////////////////////////////////////////////////////////////
//13.9 Function to search users
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
//13.10 Make the functions globally accessible
        window.toggleUserDetails = toggleUserDetails;
        window.searchUsers = searchUsers;
</script>
</head>
<body>
<!--This structure is designed to display detailed information about users in Active Directory, 
provide statistics, and enable user search. Along with the JavaScript functions,
this creates an interactive and informative report -->

           <!-- leaving empty space at the top --> 
        <h1></h1>     

               <div class="stats-container">
        <div class="stat-card" style="background: #bde0fe;">
            <div class="stat-number" id="totalUsers">0</div>
            <div>Total Users</div>
        </div>
        <div class="stat-card" style="background: #a2d2ff;">
            <div class="stat-number" id="activeUsers">0</div>
            <div>Active Users</div>
        </div>
        <div class="stat-card" style="background: #cdb4db;">
            <div class="stat-number" id="deactivatedUsers">0</div>
            <div>Deactivated Accounts</div>
        </div>
        <div class="stat-card" style="background: #ffc8dd;">
            <div class="stat-number" id="expiredPasswords">0</div>
            <div>Expired Passwords</div>
        </div>
        <div class="stat-card" style="background: #ffc8dd;">
            <div class="stat-number" id="noPasswords">0</div>
            <div>No Passwords Set</div>
        </div>
    </div>

    <div class="search-container">
        <input type="text" id="userSearch" placeholder="Search users..." oninput="searchUsers()">
    </div>
    
    <table>
        <tr>
            <th>No</th>
            <th>Name</th>
            <th>Email</th>
            <th>Department</th>
            <th>Last Logon</th>
            <th>Status</th>
            <th>Password Status</th> 
        </tr>

"@
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#14. Statistics variables
<# These variables are used to display the overall statistics
at the beginning of the report. They will be updated as each user is processed. #>
$totalUsers = 0
$activeUsers = 0
$deactivatedUsers = 0
$expiredPasswords = 0
$noPasswords = 0
$userNumber = 0
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#15 Retrieve user information from Active Directory
$users = Get-ADUser -Filter * -Property * | Sort-Object DisplayName
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#16 Add information for each user (starts here and ends with #16)
<#This section: Updates the statistics variables for each user.
Gathers all the necessary information for the user. Obtains network details and IP addresses.
Finds the groups the user is a member of. Determines the account status and password status.
Prepares all this information in HTML format.
Updates the progress bar every 10 users and saves the progress in a temporary file.
This is the main working part of the script that collects all the information and prepares it for the report.#>
foreach ($user in $users) {
    $totalUsers++
    $userNumber++
    if ($user.Enabled) { $activeUsers++ } else { $deactivatedUsers++ }
 if (Test-PasswordExpired $user) {
    $expiredPasswords++
    Write-Warning "Account with expired password found: $($user.SamAccountName)"
}
    if (-not $user.PasswordLastSet) { $noPasswords++ } 
#//////////////////////////////////////
#16.1 Main user information
$userName = $user.SamAccountName
$userId = $user.DistinguishedName.Replace(',', '').Replace('=', '')
#//////////////////////////////////////
#16.2 Last login date
$lastLogonDate = if ($user.LastLogonDate) { 
    $logonDiff = (Get-Date) - $user.LastLogonDate
    if ($logonDiff.Days -eq 0) { "Today" }
    elseif ($logonDiff.Days -eq 1) { "Yesterday" }
    else { "$($logonDiff.Days) days ago" }
} else { "Never logged in" }
#//////////////////////////////////////
#16.3 Network details
$networkDetails = Get-UserNetworkDetails -userName $userName
#//////////////////////////////////////
#16.4 IP addresses
$ipAddresses = Get-UserIPAddresses -userName $userName
#//////////////////////////////////////
#16.5 Gather group memberships
$userGroups = $user.MemberOf | ForEach-Object {
    try {
        $groupName = (Get-ADGroup $_).Name
        $groupName
    } catch {
        $null
    }
} | Where-Object { $_ -ne $null }
#//////////////////////////////////////
#16.6 Convert group names to a list
$groupNamesList = $userGroups -join ", "
#//////////////////////////////////////
#16.7 Get the Organizational Unit (OU)
$organizationalUnit = ($user.DistinguishedName -split ",OU=")[1..$($user.DistinguishedName -split ",OU=").Count] -join ", OU="
#//////////////////////////////////////
#16.8 Determine the account permissions
$userAccountControl = $user.UserAccountControl
$accountStatus = @(
    if ($userAccountControl -band 2) { "Disabled" }
    if ($userAccountControl -band 16) { "Normal account" }
    if ($userAccountControl -band 512) { "Standard account" }
    if ($userAccountControl -band 2048) { "Password must be changed" }
    if ($userAccountControl -band 65536) { "Password never expires" }
) -join ", "
#//////////////////////////////////////
#16.9 Status HTML
$statusHtml = if ($user.Enabled) {
"<span class='status-active'>Active</span>"
} else {
"<span class='status-inactive'>Inactive</span>"
}
#//////////////////////////////////////
#16.10 Password status
$passwordStatus = Get-PasswordStatus -user $user
#//////////////////////////////////////
#16.11 Update the progress bar (Add one every 10 users in the current foreach loop ($users):
    $currentProgress++
if ($currentProgress % 10 -eq 0) {
    $progressParams.PercentComplete = ($currentProgress / $users.Count) * 100
    $progressParams.Status = "Processing user: $($user.DisplayName)"
    Write-Progress @progressParams
#//////////////////////////////////////
#16.12 Save progress data in the temporary file
    $progressData = @{
        ProcessedUsers = $currentProgress
         LastProcessedUser = $user.SamAccountName
    }
    $progressData | Export-Clixml -Path $tempFile
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# 17 Add user information to the HTML table
# <!--User row (This row displays the main information for each user. The onclick event allows to open/close the user details.)
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
                   <h3>$($user.DisplayName) Main Information</h3>
                   <p><span class="detail-label">User Name:</span> $($user.SamAccountName)</p>
                   <p><span class="detail-label">Email:</span> $($user.EmailAddress)</p>
                   <p><span class="detail-label">Full Name:</span> $($user.CN)</p>
                   <p><span class="detail-label">Organizational Unit (OU):</span> $organizationalUnit</p>
               </div>
               <div class="detail-section">
                   <h4>Account Information</h4>
                   <p><span class="detail-label">Account Status:</span> $accountStatus</p>
                   <p><span class="detail-label">Last Logon Date:</span> $($user.LastLogonDate)</p>
                   <p><span class="detail-label">Account Created:</span> $($user.WhenCreated.ToString("dd.MM.yyyy HH:mm:ss"))</p>
                   <p><span class="detail-label">Password Last Changed:</span> $($user.PasswordLastSet)</p>
                   <p><span class="detail-label">Account Locked:</span> $(if ($user.LockedOut) { "Yes" } else { "No" })</p>
               </div>
               <div class="detail-section">
                   <h4>Organization Information</h4>
                   <p><span class="detail-label">Department:</span> $($user.Department)</p>
                   <p><span class="detail-label">Title:</span> $($user.Title)</p>
                   <p><span class="detail-label">Phone:</span> $($user.telephoneNumber)</p>
                   <p><span class="detail-label">Mobile:</span> $($user.mobile)</p>
               </div>
               <div class="detail-section">
                   <h4>Network Information</h4>
                   <p><span class="detail-label">All Logged-in Computers:</span> $($networkDetails.AllComputers)</p>
                   <p><span class="detail-label">Shared Folders:</span> $($networkDetails.SharedFolders)</p>
                   <p><span class="detail-label">Group Memberships:</span> $groupNamesList</p>
                   <p><span class="detail-label">IP Addresses:</span> $ipAddresses</p>
               </div>
           </div>
       </div>
   </td>
</tr>

"@
}

# 17.1 Add the end of the HTML file
<# This final part closes the table and updates the statistics elements using JavaScript.
Each statistics element updates the text of the corresponding ID element. #>
$htmlContent += @"
    </table>
  </div>
  <script>
      document.getElementById('totalUsers').textContent = '$totalUsers';
      document.getElementById('activeUsers').textContent = '$activeUsers';
      document.getElementById('deactivatedUsers').textContent = '$deactivatedUsers';
      document.getElementById('expiredPasswords').textContent = '$expiredPasswords';
      document.getElementById('noPasswords').textContent = '$noPasswords';  
  </script>
</body>
</html>
"@

#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#18 Formulate the HTML file name (Creates the name for the report file, adding the date and time)
$reportDate = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$outputPath = "C:\Reports\AD\AD_Users_Comprehensive_Report_$reportDate.html"
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#19 Check the existence of the folder and create it if necessary (Checks if the folder to save the report exists and creates it if necessary.)
$reportFolder = Split-Path $outputPath -Parent
if (!(Test-Path $reportFolder)) {
New-Item -Path $reportFolder -ItemType Directory -Force
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#20 Log performance information (Calculates and displays the total execution time.)
$totalTimer.Stop()
Write-Host "Total execution time: $($totalTimer.Elapsed.TotalSeconds) seconds" -ForegroundColor Cyan
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#22 Create the file (Creates the HTML file and saves it with UTF-8 encoding.)
$htmlContent | Out-File -FilePath $outputPath -Encoding UTF8
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#23 Open the HTML file in the browser (Automatically opens the generated report file in the browser.)
Start-Process $outputPath
Write-Host "Report created successfully and opened in the browser: $outputPath" -ForegroundColor Green
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#24 Clean up temporary files (Deletes the temporary files.)
if (Test-Path $tempFile) {
Remove-Item $tempFile -Force
}
#////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#25 Clean up memory again.
$users = $null
$htmlContent = $null
[System.GC]::Collect()
