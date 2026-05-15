$composeFile = "docker-compose.minimal.yml"

function Run-Cmd($cmd) {
    Write-Host "`n>>> $cmd" -ForegroundColor Cyan
    return Invoke-Expression $cmd 2>&1
}

function Get-Logs {
    return Run-Cmd "docker compose -f $composeFile logs --tail=50"
}

function Fix-Bcrypt {
    Write-Host "Fixing bcrypt..." -ForegroundColor Yellow
    Add-Content backend\requirements.txt "`nbcrypt==3.2.2"
    Add-Content backend\requirements.txt "`npasslib[bcrypt]==1.7.4"
}

function Fix-Pandas {
    Write-Host "Fixing pandas..." -ForegroundColor Yellow
    Add-Content backend\requirements.txt "`npandas"
}

function Fix-Kafka {
    Write-Host "Fixing Kafka..." -ForegroundColor Yellow
    Add-Content .env "`nKAFKA_BOOTSTRAP_SERVERS=kafka:29092"
}

function Rebuild {
    Run-Cmd "docker compose -f $composeFile down -v"
    Run-Cmd "docker compose -f $composeFile build --no-cache"
}

function Start-System {
    Run-Cmd "docker compose -f $composeFile up -d"
}

while ($true) {

    Start-System
    Start-Sleep -Seconds 12

    $logs = Get-Logs | Out-String

    Write-Host "`n===== LAST LOGS =====" -ForegroundColor DarkGray
    if ($logs.Length -gt 500) {
        Write-Host $logs.Substring($logs.Length - 500)
    } else {
        Write-Host $logs
    }

    if ($logs -match "pandas") {
        Fix-Pandas
        Rebuild
    }
    elseif ($logs -match "bcrypt" -or $logs -match "__about__" -or $logs -match "72 bytes") {
        Fix-Bcrypt
        Rebuild
    }
    elseif ($logs -match "KAFKA_SASL" -or $logs -match "SASL") {
        Fix-Kafka
        Rebuild
    }
    elseif ($logs -match "MissingGreenlet") {
        Write-Host "Async DB issue detected - fix env.py manually" -ForegroundColor Yellow
        break
    }
    elseif ($logs -match "ModuleNotFoundError") {
        Write-Host "Missing Python module detected" -ForegroundColor Yellow

        if ($logs -match "No module named '(.+?)'") {
            $module = $matches[1]
            Write-Host "Adding module: $module" -ForegroundColor Yellow
            Add-Content backend\requirements.txt "`n$module"
            Rebuild
        }
    }
    elseif ($logs -match "Application startup complete") {
        Write-Host "`nSYSTEM STABLE" -ForegroundColor Green
        break
    }
    else {
        Write-Host "`nUnknown error detected - printing full logs" -ForegroundColor Red
        Write-Host $logs
        break
    }
}