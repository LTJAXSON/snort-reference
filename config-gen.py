# Created by LT.JAX
from prompt_toolkit import prompt
from pprint import pprint

snort_Cheat = {
    "Actions":{
        ".":".",
        "alert: ":"generate an alert using the selected alert method.",
        "log:" :"log the packet",
        "pass: ":"ignore the packet",
        "drop: ":"block and log the packet",
        "reject: ":"block the packet, log it.",
        "sdrop: ":"block the packet but do not log it."
    },
    "Protocoles":{
        ".":".",
        "ICMP":"icmp protocole",
        "TCP":"tcp protocole",
        "UDP":"UDP protocole"
    },
    "IP and Port Numbers Filtering":{
        ".":".",
        "IP Filtering": "192.168.1.56",
        "Filter an IP range":"192.168.1.0/24",
        "Filter multiple IP ranges":"[192.168.1.0/24, 10.1.1.0/24]",
        "Exclude IP addresses/ranges":"!192.168.1.56",
        "Port Filtering":"!22",
        "Filter a port range":":1024, less than or equal",
        "Filter a port range":"1024:, higher than or equal",
    },
    "Payload Detection Rule Options":{
        ".":".",
        "Content":"""Payload data. It matches specific payload data by ASCII,
        HEX or both. It is possible to use this option multiple times in a single rule.
        However, the more you create specific pattern match features,
        the more it takes time to investigate a packet.""",
        ".":".",
        "Content-Example-ASCII":"alert tcp any 80 <> any any(msg:'GET REQ FOUND';content:'GET'.....)",
        ".":".",
        "Content-Example-HEX":"alert tcp any any <> any any (msg:'PNG File Found';content:'|89 50 4E 47 0D 0A 1A 0A|';...)",
        ".":".",
        "Nocase":"Disabling case sensitivity. Used for enhancing the content searches.",
        ".":".",
        "Nocase-Example":"alert tcp any any <> any 80  (msg: 'GET Request Found'; content:'GET'; nocase; sid: 100001; rev:1;)"
    }
}

red = "\033[1;31m"
green = "\033[1;32m"

for key in snort_Cheat.keys():
    print(red + key + green, end='')
    pprint(snort_Cheat[key], indent=4)
    

while True:
    user_input=input("Cmd=> ")
    if user_input == "exit":
        break
    with open('./rules/local.rules', 'a') as file:
        file.write(user_input)
        file.write("\n")
        print("Rule Created")