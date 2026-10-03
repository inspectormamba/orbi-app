from datetime import datetime

from orbi.parental import FOREVER, desired_blocks, next_change, profile_state, rule_active

# 2026-09-28 is a Monday (weekday 0).
MON = lambda h, m=0: datetime(2026, 9, 28, h, m)  # noqa: E731
TUE = lambda h, m=0: datetime(2026, 9, 29, h, m)  # noqa: E731
SUN = lambda h, m=0: datetime(2026, 10, 4, h, m)  # noqa: E731

BED = {"label": "Bedtime", "days": "01236", "start": "21:00", "end": "07:00", "enabled": 1}  # Sun–Thu nights
SCHOOL = {"label": "School", "days": "01234", "start": "08:00", "end": "15:00", "enabled": 1}


def test_daytime_rule():
    assert rule_active(SCHOOL, MON(8))
    assert rule_active(SCHOOL, MON(14, 59))
    assert not rule_active(SCHOOL, MON(15))
    assert not rule_active(SCHOOL, MON(7, 59))
    assert not rule_active(SCHOOL, SUN(10))


def test_overnight_rule_belongs_to_the_starting_day():
    assert rule_active(BED, MON(21))
    assert rule_active(BED, TUE(6, 59))  # Monday night continues into Tuesday
    assert not rule_active(BED, TUE(7))
    fri_night = datetime(2026, 10, 2, 22)  # Friday isn't a school night
    assert not rule_active(BED, fri_night)
    sat_morning = datetime(2026, 10, 3, 6)  # ...so Saturday morning is free
    assert not rule_active(BED, sat_morning)
    assert rule_active(BED, SUN(23))
    assert rule_active(BED, datetime(2026, 10, 5, 3))  # Sunday night into Monday (week wrap)


def test_all_day_and_disabled():
    assert rule_active({"days": "0", "start": "00:00", "end": "00:00"}, MON(13))
    assert not rule_active({**SCHOOL, "enabled": 0}, MON(9))


def test_precedence_pause_bonus_schedule():
    now = MON(22)
    p = {"id": 1, "name": "Kid", "paused_until": None, "allow_until": None}
    assert profile_state(p, [BED], now)["reason"] == "Bedtime"
    bonus = {**p, "allow_until": now.timestamp() + 1800}
    st = profile_state(bonus, [BED], now)
    assert not st["blocked"] and st["reason"] == "Extra time"
    expired = {**p, "allow_until": now.timestamp() - 1}
    assert profile_state(expired, [BED], now)["blocked"]
    paused = {**p, "paused_until": FOREVER, "allow_until": now.timestamp() + 1800}
    st = profile_state(paused, [BED], now)
    assert st["blocked"] and st["reason"] == "Paused" and st["until"] is None
    timed = {**p, "paused_until": MON(12).timestamp() + 600}
    assert profile_state(timed, [], MON(12))["blocked"]
    assert not profile_state(timed, [], MON(13))["blocked"]


def test_until_times():
    p = {"id": 1, "name": "Kid", "paused_until": None, "allow_until": None}
    assert profile_state(p, [BED], MON(22))["until"] == TUE(7)
    assert profile_state(p, [BED], MON(18))["until"] == MON(21)
    assert profile_state(p, [], MON(18))["until"] is None
    assert next_change([{**BED, "enabled": 0}], MON(18), False) is None


def test_desired_blocks():
    profiles = [{"id": 1, "name": "Ethan", "paused_until": None, "allow_until": None},
                {"id": 2, "name": "Mia", "paused_until": FOREVER, "allow_until": None}]
    rules = [{**BED, "profile_id": 1}]
    devices = [
        {"mac": "A", "profile_id": 1, "manual_block": 0},
        {"mac": "B", "profile_id": 2, "manual_block": 0},
        {"mac": "C", "profile_id": None, "manual_block": 1},
        {"mac": "D", "profile_id": None, "manual_block": 0},
        {"mac": "PC", "profile_id": 2, "manual_block": 1},
    ]
    assert desired_blocks(profiles, rules, devices, MON(12), {"PC"}) == {"B": "Mia: Paused", "C": "Blocked manually"}
    assert desired_blocks(profiles, rules, devices, MON(22), {"PC"}) == {"A": "Ethan: Bedtime", "B": "Mia: Paused", "C": "Blocked manually"}
