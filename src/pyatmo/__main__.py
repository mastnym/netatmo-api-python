import os
import sys

from pyatmo.auth import ClientAuth
from pyatmo.camera import CameraData
from pyatmo.exceptions import NoDevice
from pyatmo.public_data import PublicData
from pyatmo.thermostat import HomeData
from pyatmo.weather_station import WeatherStationData


def main():
    try:
        if (
            os.environ["CLIENT_ID"]
            and os.environ["CLIENT_SECRET"]
            and os.environ["USERNAME"]
            and os.environ["PASSWORD"]
        ):
            client_id = os.environ["CLIENT_ID"]
            client_secret = os.environ["CLIENT_SECRET"]
            username = os.environ["USERNAME"]
            password = os.environ["PASSWORD"]
    except KeyError:
        sys.stderr.write(
            "No credentials passed to pyatmo.py (client_id, client_secret, "
            "username, password)\n"
        )
        sys.exit(1)

    authorization = ClientAuth(
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password,
        scope=(
            "read_station read_camera access_camera read_thermostat "
            "write_thermostat read_presence access_presence read_homecoach "
            "read_smokedetector"
        ),
    )

    try:
        WeatherStationData(authorization)
    except NoDevice:
        if sys.stdout.isatty():
            print("pyatmo.py : warning, no weather station available for testing")

    try:
        CameraData(authorization)
    except NoDevice:
        if sys.stdout.isatty():
            print("pyatmo.py : warning, no camera available for testing")

    try:
        HomeData(authorization)
    except NoDevice:
        if sys.stdout.isatty():
            print("pyatmo.py : warning, no thermostat available for testing")

    PublicData(authorization)

    # If we reach this line, all is OK

    # If launched interactively, display OK message
    if sys.stdout.isatty():
        print("pyatmo: OK")

    sys.exit(0)


if __name__ == "__main__":
    main()
