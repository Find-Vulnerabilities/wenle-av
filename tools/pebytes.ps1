# Read a PE's sections, exports and .pdata, then hex-dump chosen RVAs.
#
# Built because `dumpbin` is not on PATH in this shell and WebFetch is blocked, so
# every question about a .sys file on this machine has to be answered by reading
# its bytes. PowerShell 5.1: no `&&`, no ternary, and a function that *returns an
# array* silently poisons arithmetic -- ToOff returns exactly one int.

param(
    [Parameter(Mandatory = $true)][string]$Path,
    # NOT [string[]]: PowerShell would coerce the literal 0x17750 to the decimal
    # string "96080" before binding, and the hex parse below would then read it as
    # 0x96080. Keep it untyped and dispatch on the runtime type.
    [object[]]$At = @(),
    [int]$Len = 64,
    [object[]]$Slots = @(),
    [uint32]$Nearest = 0
)

$b = [System.IO.File]::ReadAllBytes($Path)
$e = [BitConverter]::ToInt32($b, 0x3C)
$numSec = [BitConverter]::ToUInt16($b, $e + 6)
$optSize = [BitConverter]::ToUInt16($b, $e + 20)
$optOff = $e + 24
$secOff = $optOff + $optSize
$magic = [BitConverter]::ToUInt16($b, $optOff)
if ($magic -ne 0x20b) { Write-Output ("magic 0x{0:x} is not PE32+" -f $magic); exit 1 }

$secName = @(); $secVA = @(); $secVS = @(); $secRS = @(); $secRP = @()
for ($i = 0; $i -lt $numSec; $i++) {
    $o = $secOff + $i * 40
    $secName += ([System.Text.Encoding]::ASCII.GetString($b, $o, 8)).TrimEnd([char]0)
    $secVS += [BitConverter]::ToUInt32($b, $o + 8)
    $secVA += [BitConverter]::ToUInt32($b, $o + 12)
    $secRS += [BitConverter]::ToUInt32($b, $o + 16)
    $secRP += [BitConverter]::ToUInt32($b, $o + 20)
}

Write-Output ("{0}: {1} bytes, {2} sections, TimeDateStamp 0x{3:x8}" -f `
        (Split-Path $Path -Leaf), $b.Length, $numSec, [BitConverter]::ToUInt32($b, $e + 8))
for ($i = 0; $i -lt $numSec; $i++) {
    Write-Output ("  {0,-9} VA 0x{1:x6} VSize 0x{2:x6} RawSize 0x{3:x6} Raw 0x{4:x6}" -f `
            $secName[$i], $secVA[$i], $secVS[$i], $secRS[$i], $secRP[$i])
}

function ToOff([uint32]$rva) {
    for ($i = 0; $i -lt $script:numSec; $i++) {
        if ($rva -ge $script:secVA[$i] -and $rva -lt ($script:secVA[$i] + $script:secVS[$i])) {
            return [int]($script:secRP[$i] + ($rva - $script:secVA[$i]))
        }
    }
    return -1
}

# ---- exports (data directory 0) ------------------------------------------
$ddOff = $optOff + 112
$expRva = [BitConverter]::ToUInt32($b, $ddOff)
$expSize = [BitConverter]::ToUInt32($b, $ddOff + 4)
$expRvas = @(); $expNames = @()
if ($expRva -ne 0) {
    $eo = ToOff $expRva
    $nName = [BitConverter]::ToUInt32($b, $eo + 24)
    $aFunc = [BitConverter]::ToUInt32($b, $eo + 28)
    $aName = [BitConverter]::ToUInt32($b, $eo + 32)
    $aOrd = [BitConverter]::ToUInt32($b, $eo + 36)
    $fo = ToOff $aFunc; $no = ToOff $aName; $oo = ToOff $aOrd
    for ($i = 0; $i -lt $nName; $i++) {
        $ord = [BitConverter]::ToUInt16($b, $oo + $i * 2)
        $nrva = [BitConverter]::ToUInt32($b, $no + $i * 4)
        $np = ToOff $nrva
        $nm = ""
        while ($b[$np] -ne 0) { $nm += [char]$b[$np]; $np++ }
        $frva = [BitConverter]::ToUInt32($b, $fo + $ord * 4)
        if ($frva -ge $expRva -and $frva -lt ($expRva + $expSize)) { continue }  # forwarder
        $expRvas += $frva
        $expNames += $nm
    }
    Write-Output ("  {0} named exports" -f $expNames.Count)
}

# ---- .pdata (data directory 3) -------------------------------------------
$pdRva = [BitConverter]::ToUInt32($b, $ddOff + 24)
$pdSize = [BitConverter]::ToUInt32($b, $ddOff + 28)
$fnStart = @(); $fnEnd = @()
if ($pdRva -ne 0) {
    $po = ToOff $pdRva
    $n = [int]($pdSize / 12)
    for ($i = 0; $i -lt $n; $i++) {
        $fnStart += [BitConverter]::ToUInt32($b, $po + $i * 12)
        $fnEnd += [BitConverter]::ToUInt32($b, $po + $i * 12 + 4)
    }
    Write-Output ("  .pdata: {0} functions at RVA 0x{1:x} size 0x{2:x}" -f $n, $pdRva, $pdSize)
}

function Enclosing([uint32]$rva) {
    $best = -1
    for ($i = 0; $i -lt $script:fnStart.Count; $i++) {
        if ($rva -ge $script:fnStart[$i] -and $rva -lt $script:fnEnd[$i]) {
            if ($best -lt 0 -or $script:fnStart[$i] -gt $script:fnStart[$best]) { $best = $i }
        }
    }
    if ($best -lt 0) { return "no function in .pdata contains this RVA" }
    return ("function 0x{0:x}-0x{1:x} (entry +0x{2:x}, {3} bytes into it)" -f `
            $script:fnStart[$best], $script:fnEnd[$best], $script:fnStart[$best], ($rva - $script:fnStart[$best]))
}

function NearestExport([uint32]$rva) {
    $best = -1
    for ($i = 0; $i -lt $script:expRvas.Count; $i++) {
        if ($script:expRvas[$i] -le $rva) {
            if ($best -lt 0 -or $script:expRvas[$i] -gt $script:expRvas[$best]) { $best = $i }
        }
    }
    if ($best -lt 0) { return "no export at or below this RVA" }
    return ("nearest export below: {0} +0x{1:x}" -f $script:expNames[$best], ($rva - $script:expRvas[$best]))
}

# ---- imports (data directory 1), to turn an IAT slot back into a name ------
$slotRva = @(); $slotName = @()
$impRva = [BitConverter]::ToUInt32($b, $ddOff + 8)
if ($impRva -ne 0) {
    $io = ToOff $impRva
    for ($d = 0; ; $d++) {
        $de = $io + $d * 20
        $oft = [BitConverter]::ToUInt32($b, $de)
        $nmRva = [BitConverter]::ToUInt32($b, $de + 12)
        $ft = [BitConverter]::ToUInt32($b, $de + 16)
        if ($oft -eq 0 -and $nmRva -eq 0 -and $ft -eq 0) { break }
        if ($ft -eq 0) { continue }
        $np = ToOff $nmRva
        $dll = ""
        while ($b[$np] -ne 0) { $dll += [char]$b[$np]; $np++ }
        $src = $oft
        if ($src -eq 0) { $src = $ft }
        $so = ToOff $src
        for ($i = 0; ; $i++) {
            $thunk = [BitConverter]::ToUInt64($b, $so + $i * 8)
            if ($thunk -eq 0) { break }
            if (($thunk -band 0x8000000000000000) -ne 0) {
                $slotRva += [uint32]($ft + $i * 8)
                $slotName += ("{0}!#{1}" -f $dll, ($thunk -band 0xffff))
            } else {
                # The `+ 2` MUST be on its own line, i.e. kept out of the
                # ToOff argument list. Written as one expression,
                # `ToOff ([uint32](...)) + 2`, this printed every import as one
                # or two bytes of garbage (`FLTMGR.SYS!e`, `!l`, `!o`) while the
                # slot RVAs stayed exact. Split like this it prints
                # `ntoskrnl.exe!IoGetRequestorProcess` and all 362 of fltMgr's
                # slots read correctly, so the split is the fix.
                #
                # *Why* the one-expression form fails is NOT established. I
                # first wrote here that PowerShell parses `ToOff (x) + 2` as
                # `ToOff(x + 2)` and that this breaks only at a section edge --
                # but that parse would shift the read *later* by 2 bytes, and
                # what was actually printed was shifted *earlier*, by one. So
                # that explanation is wrong and is not replaced by another
                # guess. What is measured: the split form works, on two files
                # and seven slots.
                $imr = ToOff ([uint32]($thunk -band 0xffffffff))
                $bp = $imr + 2
                $fn = ""
                while ($b[$bp] -ne 0) { $fn += [char]$b[$bp]; $bp++ }
                $slotRva += [uint32]($ft + $i * 8)
                $slotName += ("{0}!{1}" -f $dll, $fn)
            }
        }
    }
    Write-Output ("  {0} import slots" -f $slotRva.Count)
}

function SlotName([uint32]$rva) {
    for ($i = 0; $i -lt $script:slotRva.Count; $i++) {
        if ($script:slotRva[$i] -eq $rva) { return $script:slotName[$i] }
    }
    return "<no import at this slot>"
}

foreach ($s in $Slots) {
    if ($s -is [string]) {
        $sr = [uint32]([Convert]::ToUInt32(($s -replace '^0[xX]', ''), 16))
    } else {
        $sr = [uint32]$s
    }
    Write-Output ("IAT slot 0x{0:x} = {1}" -f $sr, (SlotName $sr))
}

if ($Nearest -ne 0) {
    Write-Output ("0x{0:x}: {1}" -f $Nearest, (Enclosing $Nearest))
    Write-Output ("        {0}" -f (NearestExport $Nearest))
}

foreach ($a in $At) {
    if ($a -is [string]) {
        $rva = [uint32]([Convert]::ToUInt32(($a -replace '^0[xX]', ''), 16))
    } else {
        $rva = [uint32]$a
    }
    $off = ToOff $rva
    Write-Output ""
    Write-Output ("=== RVA 0x{0:x} (file 0x{1:x}) ===" -f $rva, $off)
    if ($off -lt 0) { Write-Output "  not in any section"; continue }
    Write-Output ("  {0}" -f (Enclosing $rva))
    Write-Output ("  {0}" -f (NearestExport $rva))
    $start = $off - 32
    if ($start -lt 0) { $start = 0 }
    $stop = $off + $Len
    if ($stop -gt $b.Length) { $stop = $b.Length }
    for ($p = $start; $p -lt $stop; $p += 16) {
        $hex = ""
        $asc = ""
        for ($k = 0; $k -lt 16 -and ($p + $k) -lt $stop; $k++) {
            $hex += ("{0:x2} " -f $b[$p + $k])
            $c = $b[$p + $k]
            if ($c -ge 32 -and $c -lt 127) { $asc += [char]$c } else { $asc += "." }
        }
        $mark = "  "
        if ($p -le $off -and $off -lt ($p + 16)) { $mark = "<=" }
        Write-Output ("  {0:x8}  {1,-48} {2} {3}" -f $p, $hex, $asc, $mark)
    }
}
