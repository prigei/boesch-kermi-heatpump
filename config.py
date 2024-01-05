boesch = {
    "user" : "xxxxxxxxx",
    "pass" : "xxxxxxxxx",
    "portal" : "https://portal.kermi.com", 
    "portal_DE" : "https://portal.kermi.com/xcenterpro/de-DE/",
    "openid_url" : "https://portal.kermi.com/openid",
    "portal_url" : "https://portal.kermi.com/xcenterpro",
    "home_server_id" : "xxxxxxxxxx",
    "read_value_url" : "https://portal.kermi.com/xcenterpro/api/Datapoint/ReadValues/",
    "write_value_url" : "https://portal.kermi.com/xcenterpro/api/Datapoint/WriteValues/",
    "device_id" : "xxxxxxxxx",
    "monitorDatapoints" : {
        "83a34595-924a-421e-b9c1-44c2a49f97ad" : {
            "description" : "Trinkwassertemperatur",
            "device" : "TWT",
            "type" : "temp",
            "unit" : "C",
            "factor" : 1
        },
        "3576624b-1af4-4406-8e8b-12500acd4840" : {
            "description" : "Verdichteraufnahme",
            "device" : "VA",
            "type" : "eny",
            "unit" : "W",
            "factor" : 1000
        },
        "dbf925c9-f24e-456c-ac49-f7702adeb9d1" : {
            "description" : "Leistungsaufnahme Heizung",
            "device" : "LAH",
            "type" : "eny",
            "unit" : "kWh",
            "factor" : 1
        },
        "b94586b8-1a4c-4c4f-b56c-07895cb71a89" : {
            "description" : "Leistungsaufnahme Trinkwasser",
            "device" : "LATW",
            "type" : "eny",
            "unit" : "kWh",
            "factor" : 1
        },
        "ac0a8989-e55d-4c8d-9550-071cfc57c01c" : {
            "description" : "Leistungsaufnahme Gesamt",
            "device" : "LAG",
            "type" : "eny",
            "unit" : "kWh",
            "factor" : 1
        },
        "e9343511-e130-4fa0-81a8-764a69890f31" : {
            "description" : "Isttemperatur HK",
            "device" : "ITHK",
            "type" : "temp",
            "unit" : "C",
            "factor" : 1
        },
        "34760a09-8f79-424f-a1b0-5f1a9339d864" : {
            "description" : "COP",
            "device" : "COP",
            "type" : "eny",
            "unit" : "kW",
            "factor" : 1000
        },
        "7605e769-5bcf-4e37-97e4-e1cded35dc54" : {
            "description" : "Heizleistung Heizung Faktor 2",
            "device" : "HLHF2",
            "type" : "eny",
            "unit" : "kW",
            "factor" : 1
        }
    },
    "switchDatapoints" : {
        "TWE" : {
            "datapoint" : "b721846e-db37-4d6d-b1ae-7b0eb9b6c2f1",
            "description" : "Trinkwassererwärmung On/Off",
            "values" : [True, False]
        },
        "HK" : {
            "datapoint" : "d5bf0ed9-d35a-4676-907b-4028ba43b6f1",
            "description" : "Heizkreis Auto/Aus",
            "values" : [0,1]
        },
    }
}
