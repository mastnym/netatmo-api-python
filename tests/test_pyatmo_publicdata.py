"""Define tests for Public weather module."""
# pylint: disable=protected-access
import json

import pytest

import pyatmo


def test_public_data(auth, requests_mock):
    with open("fixtures/public_data_simple.json") as json_file:
        json_fixture = json.load(json_file)
    requests_mock.post(
        pyatmo.public_data._GETPUBLIC_DATA,
        json=json_fixture,
        headers={"content-type": "application/json"},
    )
    public_data = pyatmo.PublicData(auth)
    assert public_data.status == "ok"

    public_data = pyatmo.PublicData(auth, required_data_type="temperature,rain_live")
    assert public_data.status == "ok"


def test_public_data_unavailable(auth, requests_mock):
    requests_mock.post(pyatmo.public_data._GETPUBLIC_DATA, status_code=404)
    with pytest.raises(pyatmo.ApiError):
        pyatmo.PublicData(auth)


def test_public_data_error(auth, requests_mock):
    with open("fixtures/public_data_error_mongo.json") as json_file:
        json_fixture = json.load(json_file)
    requests_mock.post(
        pyatmo.public_data._GETPUBLIC_DATA,
        json=json_fixture,
        headers={"content-type": "application/json"},
    )
    with pytest.raises(pyatmo.NoDevice):
        pyatmo.PublicData(auth)


def test_public_data_count_station_in_area(public_data):
    assert public_data.count_station_in_area() == 8


def test_public_data_get_latest_rain(public_data):
    expected = {
        "70:ee:50:1f:68:9e": 0,
        "70:ee:50:27:25:b0": 0,
        "70:ee:50:36:94:7c": 0.5,
        "70:ee:50:36:a9:fc": 0,
    }
    assert public_data.get_latest_rain() == expected


def test_public_data_get_average_rain(public_data):
    assert public_data.get_average_rain() == 0.125


def test_public_data_get_60min_rain(public_data):
    expected = {
        "70:ee:50:1f:68:9e": 0,
        "70:ee:50:27:25:b0": 0,
        "70:ee:50:36:94:7c": 0.2,
        "70:ee:50:36:a9:fc": 0,
    }
    assert public_data.get_60min_rain() == expected


def test_public_data_get_average_60min_rain(public_data):
    assert public_data.get_average_60min_rain() == 0.05


def test_public_data_get_24h_rain(public_data):
    expected = {
        "70:ee:50:1f:68:9e": 9.999,
        "70:ee:50:27:25:b0": 11.716000000000001,
        "70:ee:50:36:94:7c": 12.322000000000001,
        "70:ee:50:36:a9:fc": 11.009,
    }
    assert public_data.get_24h_rain() == expected


def test_public_data_get_average_24h_rain(public_data):
    assert public_data.get_average_24h_rain() == 11.261500000000002


def test_public_data_get_latest_pressures(public_data):
    expected = {
        "70:ee:50:1f:68:9e": 1007.3,
        "70:ee:50:27:25:b0": 1012.8,
        "70:ee:50:36:94:7c": 1010.6,
        "70:ee:50:36:a9:fc": 1010,
        "70:ee:50:01:20:fa": 1014.4,
        "70:ee:50:04:ed:7a": 1005.4,
        "70:ee:50:27:9f:2c": 1010.6,
        "70:ee:50:3c:02:78": 1011.7,
    }
    assert public_data.get_latest_pressures() == expected


def test_public_data_get_average_pressure(public_data):
    assert public_data.get_average_pressure() == 1010.3499999999999


def test_public_data_get_latest_temperatures(public_data):
    expected = {
        "70:ee:50:1f:68:9e": 21.1,
        "70:ee:50:27:25:b0": 23.2,
        "70:ee:50:36:94:7c": 21.4,
        "70:ee:50:36:a9:fc": 20.1,
        "70:ee:50:01:20:fa": 27.4,
        "70:ee:50:04:ed:7a": 19.8,
        "70:ee:50:27:9f:2c": 25.5,
        "70:ee:50:3c:02:78": 23.3,
    }
    assert public_data.get_latest_temperatures() == expected


def test_public_data_get_average_temperature(public_data):
    assert public_data.get_average_temperature() == 22.725


def test_public_data_get_latest_humidities(public_data):
    expected = {
        "70:ee:50:1f:68:9e": 69,
        "70:ee:50:27:25:b0": 60,
        "70:ee:50:36:94:7c": 62,
        "70:ee:50:36:a9:fc": 67,
        "70:ee:50:01:20:fa": 58,
        "70:ee:50:04:ed:7a": 76,
        "70:ee:50:27:9f:2c": 56,
        "70:ee:50:3c:02:78": 58,
    }
    assert public_data.get_latest_humidities() == expected


def test_public_data_get_average_humidity(public_data):
    assert public_data.get_average_humidity() == 63.25


def test_public_data_get_latest_wind_strengths(public_data):
    expected = {"70:ee:50:36:a9:fc": 15}
    assert public_data.get_latest_wind_strengths() == expected


def test_public_data_get_average_wind_strength(public_data):
    assert public_data.get_average_wind_strength() == 15


def test_public_data_get_latest_wind_angles(public_data):
    expected = {"70:ee:50:36:a9:fc": 17}
    assert public_data.get_latest_wind_angles() == expected


def test_public_data_get_latest_gust_strengths(public_data):
    expected = {"70:ee:50:36:a9:fc": 31}
    assert public_data.get_latest_gust_strengths() == expected


def test_public_data_get_average_gust_strength(public_data):
    assert public_data.get_average_gust_strength() == 31


def test_public_data_get_latest_gust_angles(public_data):
    expected = {"70:ee:50:36:a9:fc": 217}
    assert public_data.get_latest_gust_angles() == expected


def test_public_data_get_locations(public_data):
    expected = {
        "70:ee:50:1f:68:9e": [8.795445200000017, 50.2130169],
        "70:ee:50:27:25:b0": [8.7807159, 50.1946167],
        "70:ee:50:36:94:7c": [8.791382999999996, 50.2136394],
        "70:ee:50:36:a9:fc": [8.801164269110814, 50.19596181704958],
        "70:ee:50:01:20:fa": [8.7953, 50.195241],
        "70:ee:50:04:ed:7a": [8.785034, 50.192169],
        "70:ee:50:27:9f:2c": [8.785342, 50.193573],
        "70:ee:50:3c:02:78": [8.795953681700666, 50.19530139868166],
    }
    assert public_data.get_locations() == expected


def test_public_data_get_time_for_measures(public_data):
    expected = {
        "70:ee:50:36:a9:fc": 1560248184,
        "70:ee:50:1f:68:9e": 1560248344,
        "70:ee:50:27:25:b0": 1560247896,
        "70:ee:50:36:94:7c": 1560248022,
    }
    assert public_data.get_time_for_rain_measures() == expected


def test_public_data_get_time_for_wind_measures(public_data):
    expected = {"70:ee:50:36:a9:fc": 1560248190}
    assert public_data.get_time_for_wind_measures() == expected


@pytest.mark.parametrize(
    "test_input,expected",
    [
        (
            "pressure",
            {
                "70:ee:50:01:20:fa": 1014.4,
                "70:ee:50:04:ed:7a": 1005.4,
                "70:ee:50:1f:68:9e": 1007.3,
                "70:ee:50:27:25:b0": 1012.8,
                "70:ee:50:27:9f:2c": 1010.6,
                "70:ee:50:36:94:7c": 1010.6,
                "70:ee:50:36:a9:fc": 1010,
                "70:ee:50:3c:02:78": 1011.7,
            },
        ),
        (
            "temperature",
            {
                "70:ee:50:01:20:fa": 27.4,
                "70:ee:50:04:ed:7a": 19.8,
                "70:ee:50:1f:68:9e": 21.1,
                "70:ee:50:27:25:b0": 23.2,
                "70:ee:50:27:9f:2c": 25.5,
                "70:ee:50:36:94:7c": 21.4,
                "70:ee:50:36:a9:fc": 20.1,
                "70:ee:50:3c:02:78": 23.3,
            },
        ),
        (
            "humidity",
            {
                "70:ee:50:01:20:fa": 58,
                "70:ee:50:04:ed:7a": 76,
                "70:ee:50:1f:68:9e": 69,
                "70:ee:50:27:25:b0": 60,
                "70:ee:50:27:9f:2c": 56,
                "70:ee:50:36:94:7c": 62,
                "70:ee:50:36:a9:fc": 67,
                "70:ee:50:3c:02:78": 58,
            },
        ),
    ],
)
def test_public_data_get_latest_station_measures(public_data, test_input, expected):
    assert public_data.get_latest_station_measures(test_input) == expected


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ("wind_strength", {"70:ee:50:36:a9:fc": 15}),
        ("wind_angle", {"70:ee:50:36:a9:fc": 17}),
        ("gust_strength", {"70:ee:50:36:a9:fc": 31}),
        ("gust_angle", {"70:ee:50:36:a9:fc": 217}),
        ("wind_timeutc", {"70:ee:50:36:a9:fc": 1560248190}),
    ],
)
def test_public_data_get_accessory_measures(public_data, test_input, expected):
    assert public_data.get_accessory_measures(test_input) == expected


@pytest.mark.parametrize(
    "test_input,expected",
    [
        (
            {
                "70:ee:50:01:20:fa": 1014.4,
                "70:ee:50:04:ed:7a": 1005.4,
                "70:ee:50:1f:68:9e": 1007.3,
                "70:ee:50:27:25:b0": 1012.8,
                "70:ee:50:27:9f:2c": 1010.6,
                "70:ee:50:36:94:7c": 1010.6,
                "70:ee:50:36:a9:fc": 1010,
                "70:ee:50:3c:02:78": 1011.7,
            },
            1010.35,
        ),
        (
            {
                "70:ee:50:01:20:fa": 27.4,
                "70:ee:50:04:ed:7a": 19.8,
                "70:ee:50:1f:68:9e": 21.1,
                "70:ee:50:27:25:b0": 23.2,
                "70:ee:50:27:9f:2c": 25.5,
                "70:ee:50:36:94:7c": 21.4,
                "70:ee:50:36:a9:fc": 20.1,
                "70:ee:50:3c:02:78": 23.3,
            },
            22.725,
        ),
        ({}, 0),
    ],
)
def test_public_data_average_measure(test_input, expected):
    assert pyatmo.public_data.average_measure(test_input) == expected
