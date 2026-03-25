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
  "sdp": null,
  "image_url": "https://example.com/vehicle/image.png",
  "fuel_type": "E",
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
  "battery_state_of_charge": "normal",
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
  "time_to_fully_charge_l1": null,
  "ev_head_seat": null,
  "ev_cabin_cond": null,
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
  ],
  "enabled_services": [
    "RDL",
    "RDU",
    "VF",
    "ROLIGHTS",
    "CNOW",
    "DEEPREFRESH",
    "ROPRECOND",
    "ROTRUNKUNLOCK",
    "ROPRECOND_OFF",
    "SVLA",
    "BCALL",
    "ECALL"
  ]
}
```

## Additional API methods

```python
# Vehicle health report
report = client.get_vehicle_health_report(vin)

# Maintenance history
history = client.get_maintenance_history(vin)

# Eco-coaching trip data
last_trip = client.get_eco_coaching_last_trip(vin)
trips = client.get_eco_coaching_trips(vin)

# Vehicle image (dedicated endpoint)
image = client.get_vehicle_image(vin)

# EV charge schedules
schedules = client.get_charge_schedules(vin)
client.set_charge_schedule(vin, schedule)

# Remote operation status (check if a command succeeded)
status = client.get_remote_operation_status(vin, correlation_id)

# Stolen vehicle locator status (SiriusXM Guardian / SVLA)
svla = client.get_stolen_vehicle_status(vin)

# Vehicle subscription status
subscription = client.get_vehicle_subscription(vin)

# Set vehicle nickname
client.set_vehicle_nickname(vin, "My Car")

# Trigger a fresh location update (returns correlation ID)
correlation_id = client.update_location(vin)
```

## Service Delivery Platform (SDP)

NAFTA vehicles report a `sdp` field indicating the connected services provider:
- `"SXM"` - SiriusXM Guardian
- `"SPRINT"` - Uconnect Access (Sprint/T-Mobile)
- `null` - EMEA/LATAM/IAP regions (no SDP distinction)

The `enabled_services` field lists all active services on the vehicle, including
non-command services like `SVLA` (Stolen Vehicle Locator), `BCALL`, `ECALL`, etc.
