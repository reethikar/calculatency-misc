#!/usr/bin/env python3

import sys
import json
import time
import os
import ipaddress
import pathlib
import logging as log
import datetime as dt
import zoneinfo as zi
from typing import Callable, Any, List

import ripe.atlas.cousteau as atlas
from timezonefinder import TimezoneFinder

log.basicConfig(
    format="%(asctime)s %(levelname)s: %(message)s",
    level=log.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)

ID = "id"
OBJECTS = "objects"
COUNTRY_CODE = "country_code"
TAGS = "tags"
STATUS = "status_name"
LATITUDE, LONGITUDE = "latitude", "longitude"

V4_TARGET = "141.212.123.65"
V6_TARGET = "2607:f018:800:1:ec4:7aff:fee1:41c7"
API_KEY = ""  # TODO
GRACE_PERIOD = 60
CC_LEN = 2  # Length of the ISO 3166 country code.
IPV4_ADDR = "address_v4"
IPV6_ADDR = "address_v6"
BAD_TAGS = [
    "system-geoloc-disputed",
    "core",
    "cloud",
    "vps",
    "ixp",
    "ipv6-only",
]
GOOD_TAGS = [
    "deutsche-glasfaser",
    "dn42",
    "fiona",
    "freedom-internet",
    "fttb",
    "fttp",
    "gpnrp",
    "hybrid",
    "makerspace",
    "mesh",
    "openfiber",
    "pon",
    "ukraine",
    "verizon",
    "virgin-media",
    "6in4",
    "fiber",
    "frontier",
    "lxc",
    "swisscom",
    "bell",
    "cox-3",
    "fttp-2",
    "container",
    "fbnh",
    "fttb-2",
    "464xlat",
    "system-wifi",
    "telenet",
    "sixxs",
    "google-fiber",
    "system-flakey-power",
    "o2",
    "system-flakey-connection",
    "xfinity",
    "freifunk",
    "no-ipv4",
    "xs4all",
    "t-mobile",
    "kpn",
    "5g",
    "sfr",
    "ipv6nat",
    "spectrum",
    "att",
    "nat64",
    "wimax",
    "epix",
    "ipv6-only",
    "v5hitron",
    "starlink",
    "fttc",
    "twc",
    "3g",
    "6rd",
    "telekom",
    "system-resolves-aaaa-incorrectly",
    "known-ipv4-issues",
    "satellite",
    "vodafone",
    "ziggo",
    "docsis-31",
    "openwrt-3",
    "ds-lite",
    "6to4",
    "pi-hole",
    "nosi",
    "fios",
    "hackerspace",
    "upc",
    "pppoe",
    "vpn",
    "wi-fi",
    "docker",
    "he",
    "gpon",
    "homelab",
    "orange",
    "4g",
    "comcast",
    "cgn",
    "dtag",
    "mobile",
    "lte",
    "double-nat",
    "wireless-isp",
    "adsl",
    "docsis3",
    "ipv6-tunnel",
    "vdsl",
    "vdsl2",
    "ftth",
    "office",
    "dsl",
    "cable",
    "home",
    "nat",
]
BAD_STATUS_NAMES = ["Disconnected", "Abandoned"]
MEASUREMENT_TIMES = [
    dt.time(hour=0),
    dt.time(hour=3),
    dt.time(hour=6),
    dt.time(hour=9),
    dt.time(hour=12),
    dt.time(hour=15),
    dt.time(hour=18),
    dt.time(hour=21),
]
TZFinder = TimezoneFinder()


def tags_are_bad(tags: List[str]) -> bool:
    """Return True if any of the probe's tags violate our selection criteria."""
    for tag in tags:
        if tag in BAD_TAGS:
            return True
        if tag.startswith("data-center") or tag.startswith("datacenter"):
            return True
    return False


def lat_lon_to_timezone(lat: float, lon: float) -> zi.ZoneInfo:
    """Convert a lat/lon pair to a time zone object (e.g., Europe/Berlin)."""
    assert lat != 0 and lon != 0
    tz = TZFinder.timezone_at(lng=lon, lat=lat)
    assert tz != "" and tz is not None
    return zi.ZoneInfo(tz)


def parse_date_utc14(date_str: str) -> dt.datetime:
    """Turn the given YYYY-MM-DD string into a datetime object."""
    date_str += " +1400"  # Eastern-most UTC offset.
    return dt.datetime.strptime(date_str, "%Y-%m-%d %z")


def pct(numerator: int, denominator: int) -> float:
    """Turn the given ratio into a percentage."""
    assert denominator > 0
    return numerator / denominator * 100


def ready_for_measurement(t1: dt.time) -> bool:
    """Return True if the given time is close to a 'measurement time'."""
    today = dt.date.today()
    for t2 in MEASUREMENT_TIMES:
        dt1 = dt.datetime.combine(today, t1)
        dt2 = dt.datetime.combine(today, t2)
        diff = abs(dt1 - dt2)
        # Are we within a minute of a "measurement time"?
        if diff.total_seconds() < GRACE_PERIOD:
            return True
    return False


def filter_by_time(all_probes: List[dict]) -> List[dict]:
    log.info("Filtering probes by time.")
    subset_probes = []
    num_not_time = 0
    for probe in all_probes:
        # Determine probe's local time from its lat/lon pair.
        probe_tz = lat_lon_to_timezone(probe[LATITUDE], probe[LONGITUDE])
        probe_time = dt.datetime.now(tz=probe_tz)
        if ready_for_measurement(probe_time.time()):
            subset_probes.append(probe)
        else:
            num_not_time += 1

    num_probes = len(all_probes)
    log.info(
        "Skipped {:,} ({:.1f}%) probes because they are not ready for measurements.".format(
            num_not_time, pct(num_not_time, num_probes)
        )
    )
    log.info(
        "Narrowed down {:,} probes to {:,}.".format(num_probes, len(subset_probes))
    )

    return subset_probes


def filter_by_eligibility(all_probes: List[dict]) -> List[dict]:
    """Return the subset of probes that are eligible for measurements."""
    log.info("Filtering probes by eligibility.")
    num_bad_cc, num_bad_tags, num_bad_status, num_addrless, num_ipv6only = 0, 0, 0, 0, 0

    subset_probes = []
    for probe in all_probes:
        if probe[COUNTRY_CODE] is None or len(probe[COUNTRY_CODE]) != CC_LEN:
            num_bad_cc += 1
            continue
        if tags_are_bad(probe[TAGS]):
            num_bad_tags += 1
            continue
        if probe[STATUS] in BAD_STATUS_NAMES:
            num_bad_status += 1
            continue
        if probe[IPV4_ADDR] is None and probe[IPV6_ADDR] is None:
            num_addrless += 1
            continue
        if probe[IPV4_ADDR] is None:
            num_ipv6only += 1
            continue
        if any([t in GOOD_TAGS for t in probe[TAGS]]):
            subset_probes.append(probe)

    num_probes = len(all_probes)
    log.info(
        "Skipped {:,} ({:.1f}%) probes because they have no public addresses.".format(
            num_addrless, pct(num_addrless, num_probes)
        )
    )
    log.info(
        "Skipped {:,} ({:.1f}%) probes because of bad country code.".format(
            num_bad_cc, pct(num_bad_cc, num_probes)
        )
    )
    log.info(
        "Skipped {:,} ({:.1f}%) probes because of bad tags.".format(
            num_bad_tags, pct(num_bad_tags, num_probes)
        )
    )
    log.info(
        "Skipped {:,} ({:.1f}%) probes because of bad status.".format(
            num_bad_status, pct(num_bad_status, num_probes)
        )
    )
    log.info(
        "Skipped {:,} ({:.1f}%) probes because they do not have an ipv4 address".format(
            num_ipv6only, pct(num_ipv6only, num_probes)
        )
    )
    log.info(
        "Narrowed down {:,} probes to {:,}.".format(num_probes, len(subset_probes))
    )

    return subset_probes


def load_probes(probe_file: str) -> List[dict]:
    """Load the probes from the given JSON file."""
    log.info("Reading {}.".format(probe_file))

    with open(probe_file, "r") as f:
        records = json.load(f)
    return records[OBJECTS]


def run_icmp_traceroute(target: str):
    """Run an ICMP traceroute to the given target and save the result in a file."""
    try:
        ip_version = ipaddress.ip_address(target).version
    except ValueError as err:
        log.error("Error parsing IP address: {}".format(err))
        return
    assert ip_version in [4, 6]

    dir = "tr"  # Directory where traceroute data is stored in.
    pathlib.Path(dir).mkdir(parents=True, exist_ok=True)
    file_name = os.path.join(dir, target)
    cmd = "traceroute -{} --icmp -n {} > {}.log 2>{}.err &".format(
        ip_version, target, file_name, file_name
    )
    os.system(cmd)


def create_measurements(target: str, ip_version: int) -> List[atlas.Measurement]:
    """Return a set of measurements for the given target and IP version."""
    # We run three measurements per probe.
    description = "World-wide latency measurements"
    tags = ["geo-latency-measurements"]
    return [
        atlas.Sslcert(
            af=ip_version,
            description=description,
            target=target,
            tags=tags,
        ),
        atlas.Traceroute(
            af=ip_version,
            description=description,
            target=target,
            protocol="ICMP",
            tags=tags,
        ),
        atlas.Traceroute(
            af=ip_version,
            description=description,
            target=target,
            protocol="TCP",
            tags=tags,
        ),
    ]


def schedule_measurements(probes: List[dict]):
    """Schedule RIPE Atlas measurements for the given probes."""
    assert len(probes) > 0

    probe_ids = ",".join([str(p[ID]) for p in probes])

    v4_measurements = create_measurements(V4_TARGET, 4)
    v6_measurements = create_measurements(V6_TARGET, 6)

    source = atlas.AtlasChangeSource(
        value=probe_ids, requested=len(probe_ids), type="probes", action="add"
    )

    atlas_request = atlas.AtlasCreateRequest(
        start_time=dt.datetime.utcnow(),
        key=API_KEY,
        measurements=v4_measurements + v6_measurements,
        sources=[source],
        is_oneoff=True,
    )

    (is_success, response) = atlas_request.create()
    if is_success:
        log.info("Scheduled measurement with IDs {}.".format(response))
    else:
        log.error("Error scheduling measurement: {}", response)

    # Run ICMP traceroutes to each of our probes' publicly-listed addresses.
    for probe in probes:
        if probe[IPV4_ADDR] is not None:
            run_icmp_traceroute(probe[IPV4_ADDR])
        if probe[IPV6_ADDR] is not None:
            run_icmp_traceroute(probe[IPV6_ADDR])


def print_probes(our_probes: List[dict]):
    """Print CSV data, with one ID,addr pair per line."""
    probe_by_id = {p[ID]: p for p in our_probes}
    for id in sorted(probe_by_id.keys()):
        probe = probe_by_id[id]
        addr = probe[IPV4_ADDR]
        if addr is None:  # Probe may only be reachable via IPv6.
            addr = probe[IPV6_ADDR]
            assert addr is not None, probe
        print("{},{}".format(id, addr))


def sleep_until(datetime: dt.datetime):
    """Suspend execution until the given date/time."""
    diff = datetime - datetime.now(tz=datetime.tzinfo)
    num_secs = diff.total_seconds()
    log.info("Sleeping {} until {}.".format(diff, datetime))
    time.sleep(num_secs)


def run_in_batches(probes: List[dict], func: Callable[[List], Any]):
    """Process the given list of probes one batch at a time."""
    batch_size = 50
    for i in range(0, len(probes), batch_size):
        func(probes[i : i + batch_size])


def main(probe_file: str, start_date: dt.datetime):
    """The entry point of this script."""
    all_probes = load_probes(probe_file)

    # Begin a set of measurements lasting 50 hours.
    # We need to cover the Eastern-most time zone (UTC+14) to the Western-most
    # time zone (UTC-12).  These two extreme time zones differ by 26 (!) hours,
    # which is why a measurement run lasts for 24+26=50 hours.
    num_rounds = 50 * 2
    for thirty_mins in range(num_rounds):
        sleep_until(start_date + dt.timedelta(minutes=thirty_mins * 30))
        log.info(
            "Running measurements for 30-minute round {}/{}.".format(
                thirty_mins, num_rounds
            )
        )

        current_probes = filter_by_time(filter_by_eligibility(all_probes))
        if len(current_probes) > 0:
            log.info("Proceeding with {:,} probes.".format(len(current_probes)))
            # We repeat each measurement round three times, five minutes apart.
            num_repeats = 3
            for repeat in range(num_repeats):
                log.info(
                    "Starting measurement run {}/{}.".format(repeat + 1, num_repeats)
                )
                run_in_batches(current_probes, schedule_measurements)
                time.sleep(60 * 5)
        else:
            log.info("No probes meant to run measurements.")

        log.info("Done with current hour.")

    log.info("Done with measurements.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:", sys.argv[0], "PROBE_FILE START_DATE", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1], parse_date_utc14(sys.argv[2]))
