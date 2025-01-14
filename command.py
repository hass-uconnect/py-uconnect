from dataclasses import dataclass


@dataclass
class Command:
    message: str
    url: str = "remote"


COMMAND_AC_ON = Command(message="ROPRECOND")
COMMAND_AC_OFF = Command(message="ROPRECOND")
COMMAND_BLINK = Command(message="HBLF")
COMMAND_DOORS_UNLOCK = Command(message="RDU")
COMMAND_DOORS_LOCK = Command(message="RDL")
COMMAND_TRUNK_UNLOCK = Command(message="ROTRUNKUNLOCK")
COMMAND_TRUNK_LOCK = Command(message="ROTRUNKUNLOCK")
COMMAND_CHARGE = Command(message="CNOW", url="ev/chargenow")
COMMAND_DEEP_REFRESH = Command(message="DEEPREFRESH", url="ev")
COMMAND_REFRESH_LOCATION = Command(message="VF", url="location")
