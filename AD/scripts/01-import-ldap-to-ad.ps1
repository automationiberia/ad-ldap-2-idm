# Copyright (C) 2026 BCN Consulting Lab
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

Import-Module ActiveDirectory

# ============================================================
# CONFIGURACION
# ============================================================
#
# Place ldap-users.ldif and ldap-groups.ldif next to this script.
# Export them from OpenLDAP (docs/01-openldap-lab.md). Source DNs may be
# ou=People,dc=bcnconsulting,dc=com — this script matches ou=People / ou=Groups
# regardless of the source domain suffix.
#
# $DryRun = $true  → parse and report only (no AD writes)
# $DryRun = $false → create users, groups, memberships

$DC = "win-01rnsf8ulv3.win.iam.lab"
$UpnSuffix = "win.iam.lab"

$UsersLdif  = Join-Path $PSScriptRoot "ldap-users.ldif"
$GroupsLdif = Join-Path $PSScriptRoot "ldap-groups.ldif"

$UsersOU  = "CN=Users,DC=win,DC=iam,DC=lab"
$GroupsOU = "CN=Users,DC=win,DC=iam,DC=lab"

# LAB - final password for every imported user (Kerberos tests use this)
$Password = "redhat00!"

# TRUE = validate only
# FALSE = import
$DryRun = $true

# Reporte
$ReportFile = Join-Path $PSScriptRoot "ldap-to-ad-report.csv"


# ============================================================
# VARIABLES DE REPORTE
# ============================================================

$Report = @()


function Add-Report {
    param(
        [string]$Type,
        [string]$Object,
        [string]$Status,
        [string]$Detail
    )

    $script:Report += [PSCustomObject]@{
        Type   = $Type
        Object = $Object
        Status = $Status
        Detail = $Detail
    }
}


# ============================================================
# PARSER LDIF
# ============================================================

function Parse-LdifFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "No existe el fichero: $Path"
    }

    $lines = Get-Content -LiteralPath $Path -Encoding UTF8

    $records = @()
    $current = @()

    foreach ($line in $lines) {

        if ([string]::IsNullOrWhiteSpace($line)) {

            if ($current.Count -gt 0) {
                $records += ,@($current)
                $current = @()
            }

            continue
        }

        # Continuación LDIF
        if ($line.StartsWith(" ")) {

            if ($current.Count -gt 0) {
                $current[$current.Count - 1] += $line.Substring(1)
            }

            continue
        }

        $current += $line
    }

    if ($current.Count -gt 0) {
        $records += ,@($current)
    }

    return $records
}


# ============================================================
# ATRIBUTOS LDIF
# ============================================================

function Get-LdifAttributes {
    param(
        [Parameter(Mandatory)]
        [array]$Record
    )

    $obj = [ordered]@{}

    foreach ($line in $Record) {

        if ($line -match '^([^:]+)::\s*(.*)$') {

            $name  = $matches[1]
            $value = $matches[2]

            try {
                $bytes = [Convert]::FromBase64String($value)
                $value = [System.Text.Encoding]::UTF8.GetString($bytes)
            }
            catch {
                # Mantener valor original
            }
        }
        elseif ($line -match '^([^:]+):\s*(.*)$') {

            $name  = $matches[1]
            $value = $matches[2]
        }
        else {
            continue
        }

        if (-not $obj.Contains($name)) {
            $obj[$name] = @()
        }

        $obj[$name] += $value
    }

    [PSCustomObject]$obj
}


function Get-LdifValue {
    param(
        $Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object.PSObject.Properties.Name -contains $Name) {
        return @($Object.$Name)[0]
    }

    return $null
}


function Get-LdifValues {
    param(
        $Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return @()
    }

    if ($Object.PSObject.Properties.Name -contains $Name) {
        return @($Object.$Name)
    }

    return @()
}


# ============================================================
# CABECERA
# ============================================================

Write-Host ""
Write-Host "============================================"
Write-Host " LDAP -> ACTIVE DIRECTORY"
Write-Host "============================================"
Write-Host ""
Write-Host "DC:          $DC"
Write-Host "Users LDIF:  $UsersLdif"
Write-Host "Groups LDIF: $GroupsLdif"
Write-Host "DryRun:      $DryRun"
Write-Host "Report:      $ReportFile"
Write-Host ""


# ============================================================
# LEER LDIF
# ============================================================

Write-Host "Leyendo ldap-users.ldif..."

$UserRecords = @(Parse-LdifFile -Path $UsersLdif)

Write-Host "Registros usuarios: $($UserRecords.Count)"

Write-Host "Leyendo ldap-groups.ldif..."

$GroupRecords = @(Parse-LdifFile -Path $GroupsLdif)

Write-Host "Registros grupos:   $($GroupRecords.Count)"


# ============================================================
# PARSEAR USUARIOS
# ============================================================

$Users = @()

foreach ($record in $UserRecords) {

    $a = Get-LdifAttributes -Record $record

    $dn = Get-LdifValue $a "dn"

    if ($dn -notmatch '(?i)^cn=([^,]+),ou=People,') {
        continue
    }

    $cn            = Get-LdifValue $a "cn"
    $uid           = Get-LdifValue $a "uid"
    $sn            = Get-LdifValue $a "sn"
    $gecos         = Get-LdifValue $a "gecos"
    $uidNumber     = Get-LdifValue $a "uidNumber"
    $gidNumber     = Get-LdifValue $a "gidNumber"
    $homeDirectory = Get-LdifValue $a "homeDirectory"
    $loginShell    = Get-LdifValue $a "loginShell"

    $hostAccess = @(Get-LdifValues $a "hostAccess")

    if ([string]::IsNullOrWhiteSpace($uid)) {
        $uid = $cn
    }

    $Users += [PSCustomObject]@{
        DN            = $dn
        CN            = $cn
        UID           = $uid
        SN            = $sn
        Gecos         = $gecos
        UIDNumber     = $uidNumber
        GIDNumber     = $gidNumber
        HomeDirectory = $homeDirectory
        LoginShell    = $loginShell
        HostAccess    = $hostAccess
    }
}


# ============================================================
# PARSEAR GRUPOS
# ============================================================

$Groups = @()

foreach ($record in $GroupRecords) {

    $a = Get-LdifAttributes -Record $record

    $dn = Get-LdifValue $a "dn"

    if ($dn -notmatch '(?i)^cn=([^,]+),ou=Groups,') {
        continue
    }

    $cn        = Get-LdifValue $a "cn"
    $gidNumber = Get-LdifValue $a "gidNumber"
    $memberUid = @(Get-LdifValues $a "memberUid")

    $Groups += [PSCustomObject]@{
        DN        = $dn
        CN        = $cn
        GIDNumber = $gidNumber
        MemberUID = $memberUid
    }
}


Write-Host ""
Write-Host "Usuarios parseados: $($Users.Count)"
Write-Host "Grupos parseados:   $($Groups.Count)"
Write-Host ""


# ============================================================
# ANALISIS DE DUPLICADOS
# ============================================================

Write-Host "=== ANALISIS DE DUPLICADOS ==="

$dupUID = @(
    $Users |
        Group-Object UID |
        Where-Object Count -gt 1
)

$dupUIDNumber = @(
    $Users |
        Group-Object UIDNumber |
        Where-Object Count -gt 1
)

$dupGroupGID = @(
    $Groups |
        Group-Object GIDNumber |
        Where-Object Count -gt 1
)


if ($dupUID.Count -gt 0) {

    Write-Host ""
    Write-Host "AVISO: UID/sAMAccountName duplicados en LDIF" `
        -ForegroundColor Yellow

    foreach ($d in $dupUID) {

        Write-Host "  $($d.Name) -> $($d.Count) registros" `
            -ForegroundColor Yellow

        foreach ($u in $d.Group) {

            Add-Report `
                -Type "USER" `
                -Object $u.UID `
                -Status "DUPLICADO_LDIF" `
                -Detail "UID/sAMAccountName aparece $($d.Count) veces en el LDIF"
        }
    }
}
else {
    Write-Host "OK: no hay UID duplicados" -ForegroundColor Green
}


if ($dupUIDNumber.Count -gt 0) {

    Write-Host ""
    Write-Host "AVISO: uidNumber duplicados" `
        -ForegroundColor Yellow

    foreach ($d in $dupUIDNumber) {

        Write-Host "  uidNumber $($d.Name) -> $($d.Count) usuarios" `
            -ForegroundColor Yellow
    }
}
else {
    Write-Host "OK: no hay uidNumber duplicados" -ForegroundColor Green
}


if ($dupGroupGID.Count -gt 0) {

    Write-Host ""
    Write-Host "AVISO: gidNumber duplicados entre grupos" `
        -ForegroundColor Yellow

    foreach ($d in $dupGroupGID) {

        Write-Host "  gidNumber $($d.Name) -> $($d.Count) grupos" `
            -ForegroundColor Yellow
    }
}
else {
    Write-Host "OK: no hay gidNumber duplicados entre grupos" `
        -ForegroundColor Green
}


Write-Host ""
Write-Host "Los duplicados NO abortan la importacion."
Write-Host "Cada objeto se intentara importar individualmente."


# ============================================================
# COMPROBAR MEMBERSHIPS
# ============================================================

$KnownUsers = @{}

foreach ($u in $Users) {

    if (-not $KnownUsers.ContainsKey($u.UID)) {
        $KnownUsers[$u.UID] = $true
    }
}


$MissingMembers = @()

foreach ($g in $Groups) {

    foreach ($member in $g.MemberUID) {

        if (-not $KnownUsers.ContainsKey($member)) {

            $MissingMembers += [PSCustomObject]@{
                Group  = $g.CN
                Member = $member
            }
        }
    }
}


Write-Host ""
Write-Host "=== MEMBERSHIPS ==="

if ($MissingMembers.Count -gt 0) {

    Write-Host "AVISO: $($MissingMembers.Count) memberships apuntan a usuarios no presentes en LDIF" `
        -ForegroundColor Yellow

    foreach ($m in $MissingMembers) {

        Add-Report `
            -Type "MEMBERSHIP" `
            -Object "$($m.Member) -> $($m.Group)" `
            -Status "USUARIO_NO_EN_LDIF" `
            -Detail "El memberUid no existe en ldap-users.ldif"
    }

}
else {

    Write-Host "OK: todos los members apuntan a usuarios del LDIF" `
        -ForegroundColor Green
}


# ============================================================
# COMPROBAR OBJETOS EXISTENTES EN AD
# ============================================================

Write-Host ""
Write-Host "=== COMPROBANDO OBJETOS EXISTENTES EN AD ==="

$ExistingUsers = @()
$ExistingGroups = @()


foreach ($u in $Users) {

    $adUser = Get-ADUser `
        -Server $DC `
        -Filter "SamAccountName -eq '$($u.UID)'" `
        -ErrorAction SilentlyContinue

    if ($adUser) {

        $ExistingUsers += $adUser

        Add-Report `
            -Type "USER" `
            -Object $u.UID `
            -Status "YA_EXISTE_AD" `
            -Detail $adUser.DistinguishedName
    }
}


foreach ($g in $Groups) {

    $adGroup = Get-ADGroup `
        -Server $DC `
        -Filter "SamAccountName -eq '$($g.CN)'" `
        -ErrorAction SilentlyContinue

    if ($adGroup) {

        $ExistingGroups += $adGroup

        Add-Report `
            -Type "GROUP" `
            -Object $g.CN `
            -Status "YA_EXISTE_AD" `
            -Detail $adGroup.DistinguishedName
    }
}


Write-Host ""
Write-Host "Usuarios ya existentes en AD: $($ExistingUsers.Count)"
Write-Host "Grupos ya existentes en AD:   $($ExistingGroups.Count)"


# ============================================================
# DRY RUN
# ============================================================

if ($DryRun) {

    Write-Host ""
    Write-Host "============================================"
    Write-Host " DRY-RUN"
    Write-Host "============================================"
    Write-Host ""
    Write-Host "NO SE MODIFICARA AD."
    Write-Host ""

    Write-Host "Primeros usuarios:"
    $Users |
        Select-Object -First 10 UID,SN,UIDNumber,GIDNumber |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "Primeros grupos:"
    $Groups |
        Select-Object -First 10 CN,GIDNumber,@{
            N="Members"
            E={$_.MemberUID.Count}
        } |
        Format-Table -AutoSize

    # Guardar reporte aunque sea DryRun
    $Report |
        Export-Csv `
            -LiteralPath $ReportFile `
            -NoTypeInformation `
            -Encoding UTF8

    Write-Host ""
    Write-Host "Reporte:"
    Write-Host $ReportFile

    exit 0
}


# ============================================================
# CONTRASEÑA
# ============================================================

$SecurePassword = ConvertTo-SecureString `
    $Password `
    -AsPlainText `
    -Force


# ============================================================
# CREAR USUARIOS
# ============================================================

Write-Host ""
Write-Host "============================================"
Write-Host " CREANDO USUARIOS"
Write-Host "============================================"


foreach ($u in $Users) {

    # --------------------------------------------------------
    # Comprobar si ya existe
    # --------------------------------------------------------

    $existing = Get-ADUser `
        -Server $DC `
        -Filter "SamAccountName -eq '$($u.UID)'" `
        -ErrorAction SilentlyContinue


    if ($existing) {

        Write-Host "DUPLICADO - NO SE CREA: $($u.UID)" `
            -ForegroundColor Yellow

        Add-Report `
            -Type "USER" `
            -Object $u.UID `
            -Status "SKIPPED_DUPLICATE_AD" `
            -Detail $existing.DistinguishedName

        continue
    }


    # --------------------------------------------------------
    # Crear
    # --------------------------------------------------------

    $description = $u.Gecos

    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = $u.CN
    }


    try {

        New-ADUser `
            -Server $DC `
            -Name $u.CN `
            -SamAccountName $u.UID `
            -UserPrincipalName "$($u.UID)@$UpnSuffix" `
            -GivenName $u.CN `
            -Surname $u.SN `
            -DisplayName $u.CN `
            -Description $description `
            -Path $UsersOU `
            -AccountPassword $SecurePassword `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -ChangePasswordAtLogon $false `
            -ErrorAction Stop


        # ----------------------------------------------------
        # Atributos POSIX
        # ----------------------------------------------------

        $replace = @{
            uidNumber = [string]$u.UIDNumber
            gidNumber = [string]$u.GIDNumber
        }


        if ($u.HomeDirectory) {
            # unixHomeDirectory is the POSIX home; AD homeDirectory is a Windows UNC path
            $replace["unixHomeDirectory"] = [string]$u.HomeDirectory
        }


        if ($u.LoginShell) {
            $replace["loginShell"] = [string]$u.LoginShell
        }


        if ($u.HostAccess.Count -gt 0) {
            $replace["labeledURI"] = @($u.HostAccess)
        }


        Set-ADUser `
            -Server $DC `
            -Identity $u.UID `
            -Replace $replace `
            -ErrorAction Stop


        Write-Host "CREADO: $($u.UID)" `
            -ForegroundColor Green


        Add-Report `
            -Type "USER" `
            -Object $u.UID `
            -Status "CREADO" `
            -Detail "Usuario creado correctamente"


    }
    catch {

        Write-Host "ERROR: $($u.UID)" `
            -ForegroundColor Red

        Write-Host "       $($_.Exception.Message)" `
            -ForegroundColor Red


        Add-Report `
            -Type "USER" `
            -Object $u.UID `
            -Status "ERROR" `
            -Detail $_.Exception.Message

        # IMPORTANTE:
        # continuar con el siguiente usuario
        continue
    }
}


# ============================================================
# CREAR GRUPOS
# ============================================================

Write-Host ""
Write-Host "============================================"
Write-Host " CREANDO GRUPOS"
Write-Host "============================================"


foreach ($g in $Groups) {

    $existing = Get-ADGroup `
        -Server $DC `
        -Filter "SamAccountName -eq '$($g.CN)'" `
        -ErrorAction SilentlyContinue


    if ($existing) {

        Write-Host "DUPLICADO - NO SE CREA: $($g.CN)" `
            -ForegroundColor Yellow

        Add-Report `
            -Type "GROUP" `
            -Object $g.CN `
            -Status "SKIPPED_DUPLICATE_AD" `
            -Detail $existing.DistinguishedName

        continue
    }


    try {

        New-ADGroup `
            -Server $DC `
            -Name $g.CN `
            -SamAccountName $g.CN `
            -GroupScope Global `
            -GroupCategory Security `
            -Path $GroupsOU `
            -Description "Imported from OpenLDAP" `
            -ErrorAction Stop


        Set-ADGroup `
            -Server $DC `
            -Identity $g.CN `
            -Replace @{
                gidNumber = [string]$g.GIDNumber
            } `
            -ErrorAction Stop


        Write-Host "CREADO: $($g.CN)" `
            -ForegroundColor Green


        Add-Report `
            -Type "GROUP" `
            -Object $g.CN `
            -Status "CREADO" `
            -Detail "Grupo creado correctamente"

    }
    catch {

        Write-Host "ERROR grupo: $($g.CN)" `
            -ForegroundColor Red

        Write-Host "       $($_.Exception.Message)" `
            -ForegroundColor Red


        Add-Report `
            -Type "GROUP" `
            -Object $g.CN `
            -Status "ERROR" `
            -Detail $_.Exception.Message

        continue
    }
}


# ============================================================
# MEMBERSHIPS
# ============================================================

Write-Host ""
Write-Host "============================================"
Write-Host " ASIGNANDO MEMBERSHIPS"
Write-Host "============================================"


foreach ($g in $Groups) {

    # Comprobar que el grupo existe
    $adGroup = Get-ADGroup `
        -Server $DC `
        -Filter "SamAccountName -eq '$($g.CN)'" `
        -ErrorAction SilentlyContinue


    if (-not $adGroup) {

        Write-Host "ERROR: grupo no existe: $($g.CN)" `
            -ForegroundColor Red

        Add-Report `
            -Type "MEMBERSHIP" `
            -Object $g.CN `
            -Status "GROUP_NOT_FOUND" `
            -Detail "No se puede asignar membresía"

        continue
    }


    foreach ($member in $g.MemberUID) {

        try {

            $adUser = Get-ADUser `
                -Server $DC `
                -Filter "SamAccountName -eq '$member'" `
                -ErrorAction Stop


            # Comprobar si ya pertenece
            $alreadyMember = Get-ADGroupMember `
                -Server $DC `
                -Identity $adGroup `
                -ErrorAction Stop |
                Where-Object {
                    $_.SamAccountName -eq $member
                }


            if ($alreadyMember) {

                Write-Host "YA EXISTE: $member -> $($g.CN)" `
                    -ForegroundColor Yellow

                Add-Report `
                    -Type "MEMBERSHIP" `
                    -Object "$member -> $($g.CN)" `
                    -Status "YA_EXISTE" `
                    -Detail "El usuario ya pertenece al grupo"

                continue
            }


            Add-ADGroupMember `
                -Server $DC `
                -Identity $adGroup `
                -Members $adUser `
                -ErrorAction Stop


            Write-Host "MEMBER: $member -> $($g.CN)" `
                -ForegroundColor Green


            Add-Report `
                -Type "MEMBERSHIP" `
                -Object "$member -> $($g.CN)" `
                -Status "CREADO" `
                -Detail "Membership añadido"


        }
        catch {

            Write-Host "ERROR: $member -> $($g.CN)" `
                -ForegroundColor Red

            Write-Host "       $($_.Exception.Message)" `
                -ForegroundColor Red


            Add-Report `
                -Type "MEMBERSHIP" `
                -Object "$member -> $($g.CN)" `
                -Status "ERROR" `
                -Detail $_.Exception.Message

            continue
        }
    }
}


# ============================================================
# REPORTE FINAL
# ============================================================

$Report |
    Export-Csv `
        -LiteralPath $ReportFile `
        -NoTypeInformation `
        -Encoding UTF8


# ============================================================
# RESUMEN
# ============================================================

Write-Host ""
Write-Host "============================================"
Write-Host " IMPORTACION FINALIZADA"
Write-Host "============================================"
Write-Host ""

$Report |
    Group-Object Status |
    Sort-Object Name |
    Select-Object Name,Count |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Reporte completo:"
Write-Host $ReportFile