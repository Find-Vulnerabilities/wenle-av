# Find a minifilter's FLT_OPERATION_REGISTRATION array in a built image.
#
# `FLT_OPERATION_REGISTRATION` is 0x20 bytes: MajorFunction (UCHAR, +0), Flags
# (ULONG, +4), PreOperation (+8), PostOperation (+0x10), Reserved1 (+0x18). The
# array ends with an entry whose MajorFunction is IRP_MJ_OPERATION_END (0x80),
# and that terminator is what makes a scan for "a 0x20-byte record whose first
# byte is 4 and whose two pointers land in .text" mean something rather than
# merely look plausible.
#
# This exists because the driver exports only DriverEntry, so a callback's
# address is not in the export table; the registration the filter manager reads
# is where the address actually lives.

param([Parameter(Mandatory = $true)][string]$Path)

$b = [System.IO.File]::ReadAllBytes($Path)
$e = [BitConverter]::ToInt32($b, 0x3C)
$numSec = [BitConverter]::ToUInt16($b, $e + 6)
$optSize = [BitConverter]::ToUInt16($b, $e + 20)
$optOff = $e + 24
$secOff = $optOff + $optSize
# PE32+: ImageBase is a ULONGLONG at optional-header offset 24. (offset 28 is
# the PE32 field, and reading it on a PE32+ image yields the high half -- which
# is how this printed "image base 0x1" the first time it ran.)
$imgBase = [BitConverter]::ToUInt64($b, $optOff + 24)

$secName = @(); $secVA = @(); $secVS = @(); $secRS = @(); $secRP = @()
for ($i = 0; $i -lt $numSec; $i++) {
    $o = $secOff + $i * 40
    $secName += ([System.Text.Encoding]::ASCII.GetString($b, $o, 8)).TrimEnd([char]0)
    $secVS += [BitConverter]::ToUInt32($b, $o + 8)
    $secVA += [BitConverter]::ToUInt32($b, $o + 12)
    $secRS += [BitConverter]::ToUInt32($b, $o + 16)
    $secRP += [BitConverter]::ToUInt32($b, $o + 20)
}

# Which section holds a VA, or $null if no section does?
#
# Every variable here is named for this function and nothing outside it, so a
# `$i` in here cannot overwrite a caller's section index.
#
# The bound is spelled `0xffffffffL`, and the `L` is load-bearing: PowerShell
# parses a bare `0xffffffff` as Int32 -1 (it fits 32 bits unsigned and the
# tokenizer keeps the bit pattern signed), so the guard read `$rva -gt -1`,
# which is true for every non-negative RVA. Every candidate was dropped by the
# sanity check, and the scan reported nothing while looking like it had walked
# the whole image.
function SecOf([uint64]$va) {
    if ($va -lt $script:imgBase) { return $null }
    $secofRva = $va - $script:imgBase
    if ($secofRva -gt 0xffffffffL) { return $null }
    for ($secofIdx = 0; $secofIdx -lt $script:numSec; $secofIdx++) {
        if ($secofRva -ge $script:secVA[$secofIdx] -and
            $secofRva -lt ($script:secVA[$secofIdx] + $script:secVS[$secofIdx])) {
            return $script:secName[$secofIdx]
        }
    }
    return $null
}

# Is this 0x20-byte record a registration entry (not the terminator), with a
# callback the image really has? Returns the record, or $null.
function Get-Record([int]$p) {
    if ($p -lt 0 -or $p + 0x20 -gt $script:b.Length) { return $null }
    $rec = @{}
    $rec.major = $script:b[$p]
    $rec.flags = [BitConverter]::ToUInt32($script:b, $p + 4)
    $rec.pre = [BitConverter]::ToUInt64($script:b, $p + 8)
    $rec.post = [BitConverter]::ToUInt64($script:b, $p + 0x10)
    if ([BitConverter]::ToUInt64($script:b, $p + 0x18) -ne 0) { return $null }
    if ($rec.major -eq 0x80) { return $null }
    if ($rec.major -ne 0x04 -and $rec.major -ne 0xff -and $rec.major -ne 0x00) { return $null }
    $rec.preSec = SecOf $rec.pre
    $rec.postSec = SecOf $rec.post
    if ($null -eq $rec.preSec -and $null -eq $rec.postSec) { return $null }
    if ($null -ne $rec.preSec -and $rec.preSec -ne '.text') { return $null }
    if ($null -ne $rec.postSec -and $rec.postSec -ne '.text') { return $null }
    $rec.off = $p
    return $rec
}

"image base 0x{0:x}  sections: {1}" -f $imgBase, ($secName -join ', ')

# The array is a chain of records ending at a terminator, so it is recovered by
# walking back from each terminator instead of by accepting every 0x20-byte
# window that happens to look like a record. The difference is not cosmetic:
# a window opening 0x18 into an entry reads the zero high bytes of a callback
# pointer as `MajorFunction = 0x00` and the next entry's callback as its own
# post-operation, and that phantom CREATE entry used to be printed beside the
# real ones.
for ($i = 0; $i -lt $numSec; $i++) {
    $start = $secRP[$i]
    $end = $start + $secRS[$i]
    if ($end -gt $b.Length) { $end = $b.Length }
    for ($t = $start; $t + 0x20 -le $end; $t += 8) {
        if ($b[$t] -ne 0x80) { continue }
        # Everything after MajorFunction must be zero for this to be the
        # terminator rather than a coincidence.
        if ($b[$t + 1] -ne 0 -or $b[$t + 2] -ne 0 -or $b[$t + 3] -ne 0) { continue }
        if ([BitConverter]::ToUInt64($b, $t + 4) -ne 0) { continue }
        if ([BitConverter]::ToUInt64($b, $t + 0xc) -ne 0) { continue }
        if ([BitConverter]::ToUInt64($b, $t + 0x14) -ne 0) { continue }
        if ([BitConverter]::ToUInt32($b, $t + 0x1c) -ne 0) { continue }
        $chain = @()
        $p = $t - 0x20
        $rec = Get-Record $p
        while ($null -ne $rec) {
            $chain = @($rec) + $chain
            $p -= 0x20
            $rec = Get-Record $p
        }
        if ($chain.Count -eq 0) { continue }
        "array at file 0x{0:x}, {1} entries + terminator at 0x{2:x}" -f $chain[0].off, $chain.Count, $t
        foreach ($r in $chain) {
            "  file 0x{0:x}  major 0x{1:x2} flags 0x{2:x}  pre {3} (+{4})  post {5} (+{6})" -f `
                $r.off, $r.major, $r.flags, `
                $(if ($null -eq $r.preSec) { 'null' } else { "0x{0:x}" -f $r.pre }), `
                $(if ($null -eq $r.preSec) { '-' } else { "0x{0:x}" -f ($r.pre - $imgBase) }), `
                $(if ($null -eq $r.postSec) { 'null' } else { "0x{0:x}" -f $r.post }), `
                $(if ($null -eq $r.postSec) { '-' } else { "0x{0:x}" -f ($r.post - $imgBase) })
        }
    }
}
