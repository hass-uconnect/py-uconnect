# Python client for accessing FCA/Stellantis cars cloud API

## Installation

`pip3 install py-uconnect`

## Usage

```python
from py_uconnect import brands, Client

# Create client
client = Client('foo@bar.com', 'very_secret', pin='1234', brand=brands.FIAT_EU)
# Fetch the vehicle data into cache
client.refresh()

# List vehicles
vehicles = client.get_vehicles()
for vehicle in vehicles.values():
    print(vehicle.to_json(indent=2))
```

This would emit something similar to:
```json
{
  "vin": "XXXXXXXXXXXXXXXXXXXX",
  "nickname": "500e",
  "make": "FIAT",
  "model": "Neuer 500",
  "year": 2023,
  "region": "EMEA",
  "ignition_on": false,
  "trunk_locked": true,
  "odometer": 1841,
  "odometer_unit": "km",
  "days_to_service": 325,
  "distance_to_service": 13159.0,
  "distance_to_service_unit": "km",
  "distance_to_empty": 134,
  "distance_to_empty_unit": "km",
  "battery_voltage": 14.875,
  "oil_level": null,
  "fuel_low": false,
  "fuel_amount": null,
  "plugged_in": false,
  "ev_running": false,
  "charging": false,
  "charging_level": 0,
  "charging_level_preference": 5,
  "state_of_charge": 63,
  "time_to_fully_charge_l3": 41,
  "time_to_fully_charge_l2": 96,
  "wheel_front_left_pressure": null,
  "wheel_front_left_pressure_unit": "kPa",
  "wheel_front_left_pressure_warning": false,
  "wheel_front_right_pressure": null,
  "wheel_front_right_pressure_unit": "kPa",
  "wheel_front_right_pressure_warning": false,
  "wheel_rear_left_pressure": null,
  "wheel_rear_left_pressure_unit": "kPa",
  "wheel_rear_left_pressure_warning": false,
  "wheel_rear_right_pressure": null,
  "wheel_rear_right_pressure_unit": "kPa",
  "wheel_rear_right_pressure_warning": false,
  "door_driver_locked": true,
  "door_passenger_locked": true,
  "door_rear_left_locked": true,
  "door_rear_right_locked": true,
  "window_driver_closed": true,
  "window_passenger_closed": true,
  "location": {
    "longitude": 1.580266952514648,
    "latitude": 1.36115264892578,
    "altitude": 0,
    "bearing": 0,
    "is_approximate": false,
    "updated": 1738660203.634
  },
  "supported_commands": [
    "RDL",
    "RDU",
    "VF",
    "ROLIGHTS",
    "CNOW",
    "DEEPREFRESH",
    "ROPRECOND",
    "ROTRUNKUNLOCK",
    "ROPRECOND_OFF"
  ]
}
```
