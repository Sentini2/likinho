local config = {}
local client = { ["token"] = "JMcvhY<Wpq9m4aMVI$yM4Y" }
local player = {
    ["weapons"] = {},
    ["vehicles"] = {},
    ["objects"] = {},
    ["peds"] = {}
}

exports("executeEvent", function(event)
    ExecuteCommand("SendEvent "..event) 
end)

---------------------------------------
--- ApplyPunishment
---------------------------------------
function client.applyPunishment(data)
    local type = data.type
    local action = data.action
    local reason = data.reason

    local elapsedTime = client["Timing"] or 0
    if GetGameTimer() - elapsedTime >= 500 then
        client["Timing"] = GetGameTimer()
        if type and action and reason then
            if string.find(reason, " ") then
                reason = '"' .. reason .. '"'
            end
            ExecuteCommand("applyPunishment " .. type .. " " .. action .. " " .. reason .. " " .. client["token"])
        end
    end
end

---------------------------------------
--- START DETECTIONS
---------------------------------------
function client:StartDetections()
    client:ModMenu1()
    client:CheckNoclip()
    client:CheckGodMod1()
    client:CheckGodMod2()
    client:checkweaponspawn()
    client:CheckModelChanged()
    client:CheckWeaponsBlacklist()
end

---------------------------------------
--- DETECTIONS
---------------------------------------
function client:CheckGodMod1()
    if GetEntityModel(PlayerPedId()) == -2056455422 then
        client.applyPunishment({ type = "GodMode(1)", action = "ban", reason = "O jogador estava imortal" })
    end
end

function client:CheckGodMod2()
    local ignore, b, f, e, c, m = GetEntityProofs(PlayerPedId())
    if (b and f and e and c and m) == 1 then
        client.applyPunishment({ type = "GodMode(2)", action = "ban", reason = "O jogador estava imortal" })
    end
end


function client:ModMenu1()
    for i = 1, #config.BlacklistTexture do
        if HasStreamedTextureDictLoaded(config.BlacklistTexture[i]) then
            if Config("ModMenu(1)") then
                client.applyPunishment({ type = "ModMenu(1)", action = "ban", reason = "Inject menu" })
            end
        end
    end
end

RegisterNetEvent("esx:getSharedObject")
AddEventHandler('esx:getSharedObject', function()
    if Config("ModMenu(2)") then
        client.applyPunishment({ type = "ModMenu(2)", action = "ban", reason = "Inject menu" })
    end
end)

function client:CheckModelChanged()
    for key, model in pairs(config.ModelBlacklist) do
        if GetHashKey(GetEntityModel(PlayerPedId())) == GetHashKey(model) then
            if Config("ModelChanger(1)") then
                client.applyPunishment({ type = "ModelChanger(1)", action = "ban", reason = "O jogador mudou de ped" })
            end
        end
    end
end

function client:CheckNoclip()
    if not IsPedInAnyVehicle(PlayerPedId(), false) then
        local pos = GetEntityCoords(PlayerPedId())
        Wait(1000)
        local newped = PlayerPedId()
        local newpos = GetEntityCoords(newped)
        local distance = #(vector3(PlayerPedId()) - vector3(newpos))
        if distance > 20 and not IsEntityDead(PlayerPedId()) and not IsPedJumpingOutOfVehicle(PlayerPedId()) and PlayerPedId() == newped and tp ~= newpos and not IsPedFalling(PlayerPedId()) then
            if IsControlPressed(0, 32) or IsControlPressed(0, 269) then
                pos = GetEntityCoords(PlayerPedId())
                Wait(800)
                newped = PlayerPedId()
                newpos = GetEntityCoords(newped)
                distance = #(vector3(pos) - vector3(newpos))
                if distance > 10 and not IsEntityDead(PlayerPedId()) and not IsPedJumpingOutOfVehicle(PlayerPedId()) and not IsPedFalling(PlayerPedId()) then
                    if GetPedParachuteState(PlayerPedId()) == -1 then
                        if IsControlPressed(0, 32) or IsControlPressed(0, 269) then
                            client.applyPunishment({ type = "Noclip(1)", action = "ban", reason = "Noclip" })
                        end
                    end
                end
            end
        end
    end
end

local teleported = false
function client.TeleportChecker(coord)
    teleported = true
    local blip = GetFirstBlipInfoId(8)
    local blipCoord = GetBlipInfoIdCoord(blip)
    local ped = GetPlayerPed(PlayerId())
    while GetBlipInfoIdCoord(blip) == coord do
        Citizen.Wait(20)
    end

    Wait(1000)
    local coords = GetEntityCoords(ped)
    local afterDist = GetDistanceBetweenCoords(blipCoord.x, blipCoord.y, blipCoord.z, coords.x, coords.y, coords.z, false)
    if not IsEntityAttached(PlayerPedId()) then
        if IsPedInAnyVehicle(ped, false) and GetPedInVehicleSeat(GetVehiclePedIsIn(ped, false), -1) == ped then
            if afterDist < 1 and GetEntitySpeed(ped) < 1 then
                client.applyPunishment({ type = "TpWayPoint(1)", action = "ban", reason = "Teleporte WayPoint" })
            end
        elseif not IsPedInAnyVehicle(ped, false) then
            if afterDist < 1 and GetEntitySpeed(ped) < 1 then
                client.applyPunishment({ type = "TpWayPoint(1)", action = "ban", reason = "Teleporte WayPoint" })
            end
        end
    else
        if IsPedInAnyVehicle(ped, false) and GetPedInVehicleSeat(GetVehiclePedIsIn(ped, false), -1) == ped then
            if afterDist < 1 and GetEntitySpeed(ped) < 1 then
                client.applyPunishment({ type = "TpWayPoint(2)", action = "log", reason = "Teleporte WayPoint(2)" })
            end
        elseif not IsPedInAnyVehicle(ped, false) then
            if afterDist < 1 and GetEntitySpeed(ped) < 1 then
                client.applyPunishment({ type = "TpWayPoint(2)", action = "log", reason = "Teleporte WayPoint(2)" })
            end
        end
    end
    teleported = false
end

Citizen.CreateThread(function()
    while true do
        local blip = GetFirstBlipInfoId(8)
        if blip ~= 0 then
            local blipCoord = GetBlipInfoIdCoord(blip)
            if not teleported then 
                client.TeleportChecker(blipCoord)
            end
        end
        Citizen.Wait(500)
    end
end)

local WeaponsList = {
    "WEAPON_MILITARYRIFLE", "WEAPON_HAZARDCAN", "WEAPON_GADGETPISTOL", "WEAPON_PISTOL_MK2",
    "WEAPON_COMBATSHOTGUN", "WEAPON_CERAMICPISTOL", "GADGET_PARACHUTE", "WEAPON_KNIFE",
    "WEAPON_KNUCKLE", "WEAPON_NIGHTSTICK", "WEAPON_HAMMER", "WEAPON_BAT", "WEAPON_GOLFCLUB",
    "WEAPON_CROWBAR", "WEAPON_BOTTLE", "WEAPON_DAGGER", "WEAPON_HATCHET", "WEAPON_MACHETE",
    "WEAPON_FLASHLIGHT", "WEAPON_SWITCHBLADE", "WEAPON_POOLCUE", "WEAPON_PIPEWRENCH",
    "WEAPON_STONE_HATCHET", "WEAPON_WRENCH", "WEAPON_BATTLEAXE", "WEAPON_AUTOSHOTGUN",
    "WEAPON_GRENADE", "WEAPON_STICKYBOMB", "WEAPON_PROXMINE", "WEAPON_BZGAS",
    "WEAPON_SMOKEGRENADE", "WEAPON_MOLOTOV", "WEAPON_FIREEXTINGUISHER", "WEAPON_PETROLCAN",
    "WEAPON_NAVYREVOLVER", "WEAPON_SNOWBALL", "WEAPON_FLARE", "WEAPON_BALL", "WEAPON_PISTOL",
    "WEAPON_COMBATPISTOL", "WEAPON_APPISTOL", "WEAPON_REVOLVER", "WEAPON_REVOLVER_MK2",
    "WEAPON_DOUBLEACTION", "WEAPON_PISTOL50", "WEAPON_SNSPISTOL", "WEAPON_SNSPISTOL_MK2",
    "WEAPON_HEAVYPISTOL", "WEAPON_VINTAGEPISTOL", "WEAPON_STUNGUN", "WEAPON_FLAREGUN",
    "WEAPON_MARKSMANPISTOL", "WEAPON_RAYPISTOL", "WEAPON_HEAVYSNIPER_MK2", "WEAPON_MICROSMG",
    "WEAPON_MINISMG", "WEAPON_SMG", "WEAPON_SMG_MK2", "WEAPON_ASSAULTSMG", "WEAPON_COMBATPDW",
    "WEAPON_GUSENBERG", "WEAPON_MACHINEPISTOL", "WEAPON_MG", "WEAPON_COMBATMG", "WEAPON_COMBATMG_MK2",
    "WEAPON_RAYCARBINE", "WEAPON_ASSAULTRIFLE", "WEAPON_ASSAULTRIFLE_MK2", "WEAPON_CARBINERIFLE",
    "WEAPON_CARBINERIFLE_MK2", "WEAPON_ADVANCEDRIFLE", "WEAPON_SPECIALCARBINE",
    "WEAPON_SPECIALCARBINE_MK2", "WEAPON_BULLPUPRIFLE", "WEAPON_BULLPUPRIFLE_MK2",
    "WEAPON_COMPACTRIFLE", "WEAPON_PUMPSHOTGUN", "WEAPON_PUMPSHOTGUN_MK2", "WEAPON_SWEEPERSHOTGUN",
    "WEAPON_SAWNOFFSHOTGUN", "WEAPON_BULLPUPSHOTGUN", "WEAPON_ASSAULTSHOTGUN",
    "WEAPON_MUSKET", "WEAPON_HEAVYSHOTGUN", "WEAPON_DBSHOTGUN", "WEAPON_SNIPERRIFLE",
    "WEAPON_HEAVYSNIPER", "WEAPON_MARKSMANRIFLE", "WEAPON_MARKSMANRIFLE_MK2",
    "WEAPON_GRENADELAUNCHER", "WEAPON_GRENADELAUNCHER_SMOKE", "WEAPON_RPG", "WEAPON_MINIGUN",
    "WEAPON_FIREWORK", "WEAPON_RAILGUN", "WEAPON_HOMINGLAUNCHER", "WEAPON_COMPACTLAUNCHER",
    "WEAPON_RAYMINIGUN", "WEAPON_PIPEBOMB", "WEAPON_STINGER", "WEAPON_SNOWLAUNCHER"
}

Citizen.CreateThread(function()
    while Config("GiveWeapon(1)") do
        Citizen.Wait(1)
        local ped = PlayerPedId()
        local weapon = GetSelectedPedWeapon(ped)
        if weapon == GetHashKey("WEAPON_UNARMED") or not ValidWeapon(weapon) then
            if not HasPedGotWeapon(ped, weapon, false) then
                if IsPlayerFreeAiming(PlayerId()) then
                    if not ValidWeapon(weapon) then
                        RemoveAllPedWeapons(PlayerPedId(), true)
                        client.applyPunishment({ type = "GiveWeapon(1)", action = "ban", reason = "O jogador tentou spawnar uma arma não autorizada." })
                        Citizen.Wait(500)
                    end
                end
            end
        end
    end
end)

function client:CheckWeaponsBlacklist()
    for k, v in pairs(config.WeaponsBlackList) do
        if HasPedGotWeapon(PlayerPedId(), v, false) then
            if Config("WeaponsBlackList(1)") then
                RemoveWeaponFromPed(PlayerPedId(), GetHashKey(v))
                client.applyPunishment({ type = "WeaponsBlackList(1)", action = "ban", reason = "Arma na Blacklist ("..v..")" })
            end
        end
    end
end

function client:checkweaponspawn()
    local Ped = PlayerPedId()
    local GetPed = GetPlayerPed(-1)
    if Config("GiveWeapon(2)") then
        local ped = PlayerPedId()
        for _, weapons in ipairs(WeaponsList) do
            local weaponHash = GetHashKey(weapons)
            if HasPedGotWeapon(ped, weaponHash, false) then
                if not client.tableHasValue(player["weapons"], weaponHash) then
                    RemoveWeaponFromPed(ped, weaponHash)
                    client.applyPunishment({ type = "GiveWeapon(2)", action = "log", reason = "The player tried to spawn the weapon with the name: '" .. weapons .. "'" })
                    Citizen.Wait(500)
                end
            else
                if client.tableHasValue(player["weapons"], weaponHash) then
                    client.tableRemove(weaponHash)
                end
            end
        end
    end
end

local resourcesBlacklist = {
    ["chat"] = true,
    ["spawnmanager"] = true,
    ["scr_2"] = true,
    ["discord-screenshot"] = true,
    ["screenshot-basic"] = true,
    ["resourceaddon"] = true,
    ["resourcepremium"] = true,
    ["monitor"] = true,
    ["sessionmanager"] = true,
    ["hardcap"] = true,
    ["_cfx_internal"] = true,
    ["mapmanager"] = true,
    ["fivem-map-skater"] = true,
    ["fivem-map-hipster"] = true,
    ["Komazyca"] = true,
    ["KOMAZYCA"] = true,
    ["rE"] = true,
    ["SorryredENGINE"] = true,
    ["Master Dream"] = true,
    ["redengine"] = true,
    ["Sorry redENGINE"] = true,
    ["Sorry_redENGINE"] = true,
    ["ServerSync"] = true,
    ["PL_protect"] = true,
    ["vrp_stores"] = true,
    ["modmenu"] = true,
    ["menu"] = true
}

AddEventHandler("vRP:proxy", function(member, data, identifier, rid)
    if resourcesBlacklist[GetInvokingResource()] then
        if member == "giveWeapons" or member == "updateWeapons" or member == "replaceWeapons" then
            RemoveAllPedWeapons(GetPlayerPed(-1), true)
            client.applyPunishment({ type = "GiveWeapon(4)", action = "ban", reason = "O jogador tentou spawnar uma arma não autorizada." })
            Citizen.Wait(500)
        else
            client.applyPunishment({ type = "Exploits(1)", action = "log", reason = "The player tried to access 'vRP:proxy' to use the function: '" .. member .. "'" })
        end
    end
end)

RegisterNetEvent("vRP:tunnel_req")
AddEventHandler("vRP:tunnel_req", function(member, x, y)
    if GetInvokingResource() == nil then
        client:checktunnel(member, x, y)
    end
end)

function client:checktunnel(member, x, y)
    if member == "giveWeapons" or member == "updateWeapons" or member == "replaceWeapons" then
        if member == "replaceWeapons" or  x[2] then
            player["weapons"] = {}
        end

        for key, index in pairs(x[1]) do
            if type(key) == "string" then
                key = GetHashKey(key)
            end
            if not client.tableHasValue(player["weapons"], key) then
                table.insert(player["weapons"], key)
            end
        end
    end
end

exports("GiveWeaponToPed", function(ped, weaponHash, ammoCount, isHidden, equipNow)
    if type(weaponHash) == "string" then
        weaponHash = GetHashKey(weaponHash)
    end
    if not client.tableHasValue(player["weapons"], weaponHash) then
        table.insert(player["weapons"], weaponHash)
    end
    GiveWeaponToPed(ped, weaponHash, ammoCount, isHidden, equipNow)
end)

function client.tableHasValue(table, value)
    for _, data in ipairs(table) do
        if data == value then
            return true
        end
    end
    return false
end

function client.tableRemove(weaponHash)
    for i, data in ipairs(player["weapons"]) do
        if data == weaponHash then
            table.remove(player["weapons"], i)
            break
        end
    end
end

function ValidWeapon(weapon)
    for _, model in ipairs(WeaponsList) do
        local hash = GetHashKey(model)
        if weapon == hash then
            return true
        end
    end
    return false
end

AddEventHandler("onClientResourceStop", function(resource)
    if resource == "vrp" then
        client.applyPunishment({ type = "ClientStop(1)", action = "ban", reason = "The player tried to stop the execution of the resource: '" .. resource .. "'" })
    end
end)

AddEventHandler("onClientResourceStart", function(resource)
    if resource == GetCurrentResourceName() then
        return
    end
    TriggerEvent("exportsLoaded", GetCurrentResourceName(), resource)
end)

---------------------------------------
--- GET CONFIG
---------------------------------------
function Config(data)
    local type = tostring(data)
    local response = true
    if client[type] == nil then
        if type and client["token"] then
            ExecuteCommand("PL:config " .. type .. " " .. client["token"])
            RegisterNetEvent("PL:ac", function(data)
                if GetInvokingResource() == nil then
                    if data[1][1] == 1 then
                        response = true
                    elseif data[1][1] == 0 then
                        response = false
                    end
                    client[type] = response
                end
            end)
            Wait(60)
        end
    else
        response = client[type]
    end
    return response
end

---------------------------------------
--- Async Config
---------------------------------------
local function async_cfg()
    config["WeaponsBlackList"] = {}
    config["ModelBlacklist"] = {}
    RegisterNetEvent("PL:async", function(type, data)
        if GetInvokingResource() == nil then
            if data ~= nil and config[type] ~= data then
                config[type] = data
            end
        end
    end)

    for type, _ in pairs(config) do
        if type and client["token"] then
            ExecuteCommand("PL:asyncs " .. type .. " " .. client["token"])
        end
        Wait(500)
    end
end

config["BlacklistTexture"] = {
    "InfinityMenu","Fokixx","Fokixx2","hugeware","wave","logo","vatos","dopatest","weapon_icons","fm","meow",
    "mpleaderboard","mpinventory","commonmenu","mpmissmarkers256","titleBackgroundSprite","digitaloverlay","watermark",
    "blacklisted","menu_gif","TXDDict2","back","aafov", "mphud","hunting","deadline","srange_gen","Guest8","mpentry","mpentry",
    "meow2","headshotW","luaW","onlineW","fs12","fs22","gun","line","customknife","fivem","logo","gradient_bgd","trafficcam",
    "dickmenu","lscustoms","exterior","dequsamenu","cockmenuuu","TXDDict","bbfov", "peter_griffin", 
}

---------------------------------------
--- WALL SYSTEM
---------------------------------------
local cacheWall = {
    Config = {},
    PedList = {},
    Lines = true,
    wallActive = false
}

RegisterNetEvent("PL:Wall",function(data)
    if GetInvokingResource() == nil then
        cacheWall["wallActive"] = not cacheWall["wallActive"]
        if cacheWall["wallActive"] then
            cacheWall["Config"] = data.cfg
            cacheWall["PedList"] = data.List
            TriggerEvent("Notify","sucesso","Wall ativado.")
        else
            cacheWall["Config"] = data.cfg
            cacheWall["PedList"] = data.List
            TriggerEvent("Notify","negado","Wall desativado.")
        end
    end
end)

RegisterNetEvent("PL:Update",function(index, data)
    if GetInvokingResource() == nil then
        if data.cfg ~= nil then
            if cacheWall["wallActive"] then
                cacheWall.Config[index] = data.cfg
            end
        else
            cacheWall["PedList"] = data.List
        end
    end
end)

Citizen.CreateThread(function()
    while true do
        local time = 1000
        if cacheWall["wallActive"] then
            time = 0
            local ped = PlayerPedId()
            local coords = GetEntityCoords(ped)
            local myServerId = GetPlayerServerId(PlayerId())
            for k, v in pairs(GetActivePlayers()) do
                local nsource, nped = GetPlayerServerId(v), GetPlayerPed(v)
                local ncoords = GetEntityCoords(nped)
                if cacheWall.PedList[nsource] and nped ~= PlayerPedId() then
                    if Vdist(coords.x, coords.y, coords.z, ncoords.x, ncoords.y, ncoords.z) <= 350 then
                        local arrayInfos = cacheWall.PedList[nsource]
                        local selectedWeapon = GetSelectedPedWeapon(nped)

                        local nameWeapon = cacheWall.weaponName[tostring(selectedWeapon)] or 'Indefinida'
                        local invisibility = IsEntityVisible(nped) and "~w~" or "~r~ INVISIVEL"
                        local speaking = NetworkIsPlayerTalking(v) and "~y~FALANDO" or ""
                        if cacheWall["Config"].Linhas then
                            r, g, b = 3, 28, 252
                            if not IsEntityVisible(nped) then 
                                r, g, b = 168, 24, 17
                            end
                            DrawLine(coords.x, coords.y, coords.z, ncoords.x, ncoords.y, ncoords.z, r, g, b, 255)
                        end
                        DrawAdmin(ncoords.x, ncoords.y, ncoords.z + 1.10, formatAdminDisplay(arrayInfos, nsource, nped, ncoords, nameWeapon, invisibility, speaking))
                    end
                end
            end
        end
        Citizen.Wait(time)
    end
end)

cacheWall.weaponName = {
    [tostring(GetHashKey('WEAPON_ANIMAL'))] = 'Animal', [tostring(GetHashKey('WEAPON_COUGAR'))] = 'Cougar', [tostring(GetHashKey('WEAPON_ADVANCEDRIFLE'))] = 'Advanced Rifle',
    [tostring(GetHashKey('WEAPON_APPISTOL'))] = 'AP Pistol', [tostring(GetHashKey('WEAPON_ASSAULTRIFLE'))] = 'Assault Rifle', [tostring(GetHashKey('WEAPON_ASSAULTRIFLE_MK2'))] = 'Assault Rifke Mk2',
    [tostring(GetHashKey('WEAPON_ASSAULTSHOTGUN'))] = 'Assault Shotgun', [tostring(GetHashKey('WEAPON_ASSAULTSMG'))] = 'Assault SMG', [tostring(GetHashKey('WEAPON_AUTOSHOTGUN'))] = 'Automatic Shotgun',
    [tostring(GetHashKey('WEAPON_BULLPUPRIFLE'))] = 'Bullpup Rifle', [tostring(GetHashKey('WEAPON_BULLPUPRIFLE_MK2'))] = 'Bullpup Rifle Mk2',[tostring(GetHashKey('WEAPON_BULLPUPSHOTGUN'))] = 'Bullpup Shotgun',
    [tostring(GetHashKey('WEAPON_CARBINERIFLE'))] = 'Carbine Rifle', [tostring(GetHashKey('WEAPON_CARBINERIFLE_MK2'))] = 'Carbine Rifle Mk2', [tostring(GetHashKey('WEAPON_COMBATMG'))] = 'Combat MG',
    [tostring(GetHashKey('WEAPON_COMBATMG_MK2'))] = 'Combat MG Mk2', [tostring(GetHashKey('WEAPON_COMBATPDW'))] = 'Combat PDW', [tostring(GetHashKey('WEAPON_COMBATPISTOL'))] = 'Combat Pistol',
    [tostring(GetHashKey('WEAPON_COMPACTRIFLE'))] = 'Compact Rifle', [tostring(GetHashKey('WEAPON_DBSHOTGUN'))] = 'Double Barrel Shotgun', [tostring(GetHashKey('WEAPON_DOUBLEACTION'))] = 'Double Action Revolver',
    [tostring(GetHashKey('WEAPON_FLAREGUN'))] = 'Flare gun', [tostring(GetHashKey('WEAPON_GUSENBERG'))] = 'Gusenberg', [tostring(GetHashKey('WEAPON_HEAVYPISTOL'))] = 'Heavy Pistol',
    [tostring(GetHashKey('WEAPON_HEAVYSHOTGUN'))] = 'Heavy Shotgun', [tostring(GetHashKey('WEAPON_HEAVYSNIPER'))] = 'Heavy Sniper', [tostring(GetHashKey('WEAPON_HEAVYSNIPER_MK2'))] = 'Heavy Sniper',
    [tostring(GetHashKey('WEAPON_MACHINEPISTOL'))] = 'Machine Pistol', [tostring(GetHashKey('WEAPON_MARKSMANPISTOL'))] = 'Marksman Pistol', [tostring(GetHashKey('WEAPON_MARKSMANRIFLE'))] = 'Marksman Rifle',
    [tostring(GetHashKey('WEAPON_MARKSMANRIFLE_MK2'))] = 'Marksman Rifle Mk2', [tostring(GetHashKey('WEAPON_MG'))] = 'MG', [tostring(GetHashKey('WEAPON_MICROSMG'))] = 'Micro SMG',
    [tostring(GetHashKey('WEAPON_MINIGUN'))] = 'Minigun', [tostring(GetHashKey('WEAPON_MINISMG'))] = 'Mini SMG', [tostring(GetHashKey('WEAPON_MUSKET'))] = 'Musket',
    [tostring(GetHashKey('WEAPON_PISTOL'))] = 'Pistol', [tostring(GetHashKey('WEAPON_PISTOL_MK2'))] = 'Pistol Mk2', [tostring(GetHashKey('WEAPON_PISTOL50'))] = 'Pistol .50',
    [tostring(GetHashKey('WEAPON_PUMPSHOTGUN'))] = 'Pump Shotgun', [tostring(GetHashKey('WEAPON_PUMPSHOTGUN_MK2'))] = 'Pump Shotgun Mk2', [tostring(GetHashKey('WEAPON_RAILGUN'))] = 'Railgun',
    [tostring(GetHashKey('WEAPON_REVOLVER'))] = 'Revolver', [tostring(GetHashKey('WEAPON_REVOLVER_MK2'))] = 'Revolver Mk2', [tostring(GetHashKey('WEAPON_SAWNOFFSHOTGUN'))] = 'Sawnoff Shotgun',
    [tostring(GetHashKey('WEAPON_SMG'))] = 'SMG', [tostring(GetHashKey('WEAPON_SMG_MK2'))] = 'SMG Mk2', [tostring(GetHashKey('WEAPON_SNIPERRIFLE'))] = 'Sniper Rifle',
    [tostring(GetHashKey('WEAPON_SNSPISTOL'))] = 'SNS Pistol', [tostring(GetHashKey('WEAPON_SNSPISTOL_MK2'))] = 'SNS Pistol Mk2', [tostring(GetHashKey('WEAPON_SPECIALCARBINE'))] = 'Special Carbine',
    [tostring(GetHashKey('WEAPON_SPECIALCARBINE_MK2'))] = 'Special Carbine Mk2', [tostring(GetHashKey('WEAPON_STINGER'))] = 'Stinger', [tostring(GetHashKey('WEAPON_STUNGUN'))] = 'Stungun',
    [tostring(GetHashKey('WEAPON_VINTAGEPISTOL'))] = 'Vintage Pistol', [tostring(GetHashKey('VEHICLE_WEAPON_PLAYER_LASER'))] = 'Vehicle Lasers',
    [tostring(GetHashKey('WEAPON_FIRE'))] = 'Fire', [tostring(GetHashKey('WEAPON_FLARE'))] = 'Flare', [tostring(GetHashKey('WEAPON_FLAREGUN'))] = 'Flaregun',
    [tostring(GetHashKey('WEAPON_MOLOTOV'))] = 'Molotov', [tostring(GetHashKey('WEAPON_PETROLCAN'))] = 'Petrol Can', [tostring(GetHashKey('WEAPON_HELI_CRASH'))] = 'Helicopter Crash',
    [tostring(GetHashKey('WEAPON_RAMMED_BY_CAR'))] = 'Rammed by Vehicle', [tostring(GetHashKey('WEAPON_RUN_OVER_BY_CAR'))] = 'Ranover by Vehicle', [tostring(GetHashKey('VEHICLE_WEAPON_SPACE_ROCKET'))] = 'Vehicle Space Rocket',
    [tostring(GetHashKey('VEHICLE_WEAPON_TANK'))] = 'Tank', [tostring(GetHashKey('WEAPON_AIRSTRIKE_ROCKET'))] = 'Airstrike Rocket', [tostring(GetHashKey('WEAPON_AIR_DEFENCE_GUN'))] = 'Air Defence Gun',
    [tostring(GetHashKey('WEAPON_COMPACTLAUNCHER'))] = 'Compact Launcher', [tostring(GetHashKey('WEAPON_EXPLOSION'))] = 'Explosion', [tostring(GetHashKey('WEAPON_FIREWORK'))] = 'Firework',
    [tostring(GetHashKey('WEAPON_GRENADE'))] = 'Grenade', [tostring(GetHashKey('WEAPON_GRENADELAUNCHER'))] = 'Grenade Launcher', [tostring(GetHashKey('WEAPON_HOMINGLAUNCHER'))] = 'Homing Launcher',
    [tostring(GetHashKey('WEAPON_PASSENGER_ROCKET'))] = 'Passenger Rocket', [tostring(GetHashKey('WEAPON_PIPEBOMB'))] = 'Pipe bomb', [tostring(GetHashKey('WEAPON_PROXMINE'))] = 'Proximity Mine',
    [tostring(GetHashKey('WEAPON_RPG'))] = 'RPG', [tostring(GetHashKey('WEAPON_STICKYBOMB'))] = 'Sticky Bomb', [tostring(GetHashKey('WEAPON_VEHICLE_ROCKET'))] = 'Vehicle Rocket',
    [tostring(GetHashKey('WEAPON_BZGAS'))] = 'BZ Gas', [tostring(GetHashKey('WEAPON_FIREEXTINGUISHER'))] = 'Fire Extinguisher', [tostring(GetHashKey('WEAPON_SMOKEGRENADE'))] = 'Smoke Grenade',
    [tostring(GetHashKey('WEAPON_BATTLEAXE'))] = 'Battleaxe', [tostring(GetHashKey('WEAPON_BOTTLE'))] = 'Bottle', [tostring(GetHashKey('WEAPON_KNIFE'))] = 'Knife',
    [tostring(GetHashKey('WEAPON_MACHETE'))] = 'Machete', [tostring(GetHashKey('WEAPON_SWITCHBLADE'))] = 'Switch Blade', [tostring(GetHashKey('OBJECT'))] = 'Object',
    [tostring(GetHashKey('VEHICLE_WEAPON_ROTORS'))] = 'Vehicle Rotors', [tostring(GetHashKey('WEAPON_BALL'))] = 'Ball', [tostring(GetHashKey('WEAPON_BAT'))] = 'Bat',
    [tostring(GetHashKey('WEAPON_CROWBAR'))] = 'Crowbar', [tostring(GetHashKey('WEAPON_FLASHLIGHT'))] = 'Flashlight', [tostring(GetHashKey('WEAPON_GOLFCLUB'))] = 'Golfclub',
    [tostring(GetHashKey('WEAPON_HAMMER'))] = 'Hammer', [tostring(GetHashKey('WEAPON_HATCHET'))] = 'Hatchet', [tostring(GetHashKey('WEAPON_HIT_BY_WATER_CANNON'))] = 'Water Cannon',
    [tostring(GetHashKey('WEAPON_KNUCKLE'))] = 'Knuckle', [tostring(GetHashKey('WEAPON_NIGHTSTICK'))] = 'Night Stick', [tostring(GetHashKey('WEAPON_POOLCUE'))] = 'Pool Cue',
    [tostring(GetHashKey('WEAPON_SNOWBALL'))] = 'Snowball', [tostring(GetHashKey('WEAPON_WRENCH'))] = 'Wrench', [tostring(GetHashKey('WEAPON_DROWNING'))] = 'Drowned',
    [tostring(GetHashKey('WEAPON_DROWNING_IN_VEHICLE'))] = 'Drowned in Vehicle', [tostring(GetHashKey('WEAPON_BARBED_WIRE'))] = 'Barbed Wire', [tostring(GetHashKey('WEAPON_BLEEDING'))] = 'Bleed',
    [tostring(GetHashKey('WEAPON_ELECTRIC_FENCE'))] = 'Electric Fence', [tostring(GetHashKey('WEAPON_EXHAUSTION'))] = 'Exhaustion', [tostring(GetHashKey('WEAPON_FALL'))] = 'Falling'
}

function formatAdminDisplay(arrayInfos, nsource, nped, ncoords, nameWeapon, invisibility, speaking)
    return (arrayInfos.staff and "~t~[STAFF]~w~ " or "") .."[" .. arrayInfos.user_id .. "] " .. (cacheWall.Config.Nome and arrayInfos.name or "") ..
    (cacheWall.Config.Source and " | src: " .. nsource or "") .. (cacheWall.Config.Vida and "\n~w~Health: ~g~ " ..GetEntityHealth(nped).." ~w~|| " or "\n") ..
    (cacheWall.Config.Colete and "Armour: ~b~" ..GetPedArmour(nped) or "") .. " " .. (arrayInfos.iswall and " ~w~[~g~WALL ON~w~]" or "~w~[~r~WALL OFF~w~]") ..
    "\n~w~Organization: ~g~" .. ( arrayInfos.orgName or "Desempregado").. (cacheWall.Config.Arma and "\n~w~Weapon: ~t~" ..nameWeapon or "") ..
    (not IsEntityVisible(nped) and "\n~r~INVISIVEL" or "") .."\n" .. speaking
end

function DrawAdmin(x, y, z, text, r, g, b)
    local onScreen, _x, _y = World3dToScreen2d(x, y, z)
    if onScreen then
        local lines = splitString(text, "\n")
        local scale = 0.4
        local lineHeight = 0.05 * scale
        for i, line in ipairs(lines) do
            SetTextFont(4)
            SetTextProportional(1)
            SetTextScale(scale-0.2, scale)
            SetTextColour(r or 255, g or 255, b or 255, 255)
            SetTextEntry("STRING")
            SetTextCentre(1)
            AddTextComponentString(line)
            DrawText(_x, _y + ((i - 1) * lineHeight))
        end
    end
end

function splitString(input, separator)
    if separator == nil then separator = "%s" end
    local t, i = {}, 1
    for str in string.gmatch(input, "([^"..separator.."]+)") do
        t[i] = str
        i = i + 1
    end
    return t
end

---------------------------------------
--- MAIN THREAD
---------------------------------------
Citizen.CreateThread(function()
    async_cfg()
    while true do
        Citizen.Wait(500)
        client:StartDetections()
    end
end)