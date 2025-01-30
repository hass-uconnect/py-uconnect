#!/usr/bin/env python3

from pyfiat import Client
from pyfiat.brands import BRANDS
from sys import argv, exit


if len(argv) < 3:
    print("Incorrect arguments. Pass brand, login and password as arguments.")
    exit(1)

brand, login, password = argv[1], argv[2], argv[3]

brand = BRANDS.get(brand, None)
if brand is None:
    print(f"Incorrect brand. Possible values are: {
        ", ".join([x for x in BRANDS.keys()])}")
    exit(1)

c = Client(login, password, "", brand=brand, debug=len(argv) > 4)
c.refresh()
v = c.get_vehicles()

for veh in v.values():
    print(veh.to_json(indent=2))
