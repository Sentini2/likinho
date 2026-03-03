local server = IsDuplicityVersion()
if server then
    local events = {}
    local _RegisterNetEvent = RegisterNetEvent
    local _RegisterServerEvent = RegisterServerEvent

    RegisterServerEvent = function(event, ...)
        if not string.find(event, "_cfx") then
            events[event] = true   
        end
        return _RegisterServerEvent(event, ...)
    end

    RegisterNetEvent = function(event, ...)
        if not string.find(event, "_cfx") then
            events[event] = true
        end
        return _RegisterNetEvent(event, ...)
    end

    if GetResourceState("PL") == "started" then
        AddEventHandler("init:events", function()
            exports["PL"]:registerEvents(events)
        end)
    end
else
    local _TriggerServerEvent = TriggerServerEvent
    TriggerServerEvent = function(event, ...)
        exports["PL"]:executeEvent(event)
        return _TriggerServerEvent(event, ...)
    end
end