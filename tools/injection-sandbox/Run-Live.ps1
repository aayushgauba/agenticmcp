param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Model,
    [switch]$TokenFromClipboard,
    [ValidateSet('coding','repair','hard','readonly','all')][string]$Suite = 'coding',
    [ValidateRange(1,100)][int]$Trials = 1
)
$ErrorActionPreference = 'Stop'
$sandboxPreviousToken = $env:COPILOT_GITHUB_TOKEN
$sandboxExit = 1
try {
    if ($TokenFromClipboard) {
        # Explicit local opt-in: do not print the clipboard or save it to a file.
        $env:COPILOT_GITHUB_TOKEN = [string](Get-Clipboard -Raw)
    } elseif (-not $env:COPILOT_GITHUB_TOKEN) {
        $sandboxSecureToken = Read-Host 'GitHub fine-grained token (Copilot Requests permission)' -AsSecureString
        $sandboxTokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sandboxSecureToken)
        try {
            $env:COPILOT_GITHUB_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($sandboxTokenPointer)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($sandboxTokenPointer)
            $sandboxSecureToken.Dispose()
        }
    }
    $env:COPILOT_GITHUB_TOKEN = ([string]$env:COPILOT_GITHUB_TOKEN).Trim()
    if ($env:COPILOT_GITHUB_TOKEN -cnotmatch '^github_pat_[A-Za-z0-9_]+$') {
        $sandboxInputLength = $env:COPILOT_GITHUB_TOKEN.Length
        $sandboxPrefixPresent = $env:COPILOT_GITHUB_TOKEN.StartsWith('github_pat_')
        $sandboxControlPresent = $env:COPILOT_GITHUB_TOKEN -match '[\x00-\x1F\x7F]'
        if ($TokenFromClipboard) {
            $sandboxInputHelp = 'The clipboard does not contain a single fine-grained token value. Copy only the generated github_pat_ token, then retry. Alternatively omit -TokenFromClipboard to use existing environment credentials or hidden input. Do not paste the token into chat.'
        } else {
            $sandboxInputHelp = 'Provide only the generated github_pat_ token value. If hidden paste failed, copy that value and retry with -TokenFromClipboard. Do not paste the token into chat.'
        }
        throw "Token input did not match the expected format. Characters=$sandboxInputLength; expectedPrefix=$sandboxPrefixPresent; controlCharacters=$sandboxControlPresent. Token value was not printed or sent. $sandboxInputHelp"
    }
    & node (Join-Path $PSScriptRoot 'run.mjs') run --model $Model --suite $Suite --trials $Trials
    $sandboxExit = $LASTEXITCODE
} finally {
    $env:COPILOT_GITHUB_TOKEN = $sandboxPreviousToken
}
exit $sandboxExit
