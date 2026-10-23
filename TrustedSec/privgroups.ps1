param([ValidateSet('members','pgid')][string]$Mode = 'members')
Import-Module ActiveDirectory -ErrorAction Stop
$d = (Get-ADDomain).DomainSID.Value
# Op SID, zodat Nederlandse groepsnamen geen probleem zijn
$sids = "$d-512","$d-518","$d-519","$d-520",
        'S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551'

if ($Mode -eq 'pgid') {
    # Alles met een afwijkende of onleesbare primaryGroupID
    # 513 Domain Users, 514 Guests, 515 Computers, 516 DCs, 521 RODCs
    $odd = Get-ADObject -LDAPFilter '(objectClass=user)' -Properties primaryGroupID,sAMAccountName |
           Where-Object { $_.primaryGroupID -notin 513,514,515,516,521 }
    ($odd | ForEach-Object { "$($_.sAMAccountName)=$($_.primaryGroupID)" } | Sort-Object) -join ';'
    return
}

$out = foreach ($sid in $sids) {
    $g = Get-ADGroup -Filter "SID -eq '$sid'"
    if (-not $g) { continue }   # Schema/Enterprise Admins alleen in root-domein
    $names = [System.Collections.Generic.List[string]]::new()
    Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue |
        ForEach-Object { $names.Add($_.SamAccountName) }
    # De groep zelf + alle geneste groepen: zoek users die die groep als primary group hebben
    $groups = @($g) + @(Get-ADGroup -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$($g.DistinguishedName))")
    foreach ($grp in $groups) {
        if ($grp.SID.Value -like 'S-1-5-32-*') { continue }  # builtin kan geen primary group zijn
        $rid = $grp.SID.Value.Split('-')[-1]
        Get-ADObject -LDAPFilter "(&(objectClass=user)(primaryGroupID=$rid))" -Properties sAMAccountName |
            ForEach-Object { $names.Add($_.sAMAccountName) }
    }
    "$($g.Name): " + (($names | Sort-Object -Unique) -join ',')
}
$out -join "`n"
