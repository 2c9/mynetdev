$leases = Get-DhcpServerv4Scope | Get-DhcpServerv4Lease -AllLeases | Where-Object { $_.hostname -ne $null -AND $_.hostname -ne 'BAD_ADDRESS' }

$url = 'http://172.16.3.174:7379'

foreach ($lease in $leases) {
	$name = $lease."hostname"
	$mac = $lease."clientid"
	$mac = $mac -replace "-",""
	$mac = $mac.insert(4,".")
	$mac = $mac.insert(9,".")
	Invoke-RestMethod -Uri "$url/SET/$mac/$name" | Out-Null
	Invoke-RestMethod -Uri "$url/EXPIRE/$mac/604800"  | Out-Null
}

$reservation = Get-DhcpServerv4Scope | Get-DhcpServerv4Reservation | Where-Object { $_.name -ne $null }

foreach ($reserved in $reservation) {
	$name = $reserved."hostname"
	$mac = $reserved."clientid"
	$mac = $mac -replace "-",""
	$mac = $mac.insert(4,".")
	$mac = $mac.insert(9,".")
	Invoke-RestMethod -Uri "$url/SET/$mac/$name" | Out-Null
	Invoke-RestMethod -Uri "$url/EXPIRE/$mac/604800"  | Out-Null
}

