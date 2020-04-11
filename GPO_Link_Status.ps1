function CheckGPOLinkStatus {
    [cmdletbinding()]
    param(
    [parameter(position=1)]
    [ValidateNotNullOrEmpty()]
    [string]$DN,

    [parameter(position=2)]
    [ValidateNotNullOrEmpty()]
    [string]$GPOPolicy

    )
    process {
        Write-Host ""
        Write-Host "Distinguished Name $DN"
            foreach ( $item in ($DN.replace('\,','~').split(","))) {
                switch ($item.TrimStart().Substring(0,2)) {
                    'CN' {$CN = '/' + $item.Replace("CN=","")}
                    'OU' {$OU += ,$item.Replace("OU=","");$OU += '/'}
                    'DC' {$DC += $item.Replace("DC=","");$DC += '.'}
                }
            } 
            $CanonicalName = $DC.Substring(0,$DC.length - 1)

            if($OU)
            {
            for ($i = $OU.count;$i -ge 0;$i -- ){$CanonicalName += $OU[$i]}
            }
            
            if ( $DN.Substring(0,2) -eq 'CN' ) {
                $CanonicalName += $CN.Replace('~','\,')
            }
            
    Write-Host "Canonical Name $CanonicalName"
    Write-Host "GPO Name $GPOPolicy"

	[xml]$report=Get-GPOReport -Name $GPOPolicy -ReportType xml

    $status=($report.GPO.LinksTo | Where-Object {$_.SOMPath -eq $CanonicalName}).Enabled
    Write-Host "GPOLink Status is $status"
    Write-Host ""
    
    }
}

CheckGPOLinkStatus "OU=Domain Controllers,DC=corplab,DC=com" "Internal Policy"
CheckGPOLinkStatus "DC=corplab,DC=com" "Internal Policy 1"
