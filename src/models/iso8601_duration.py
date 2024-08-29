# -*- coding: utf-8 -*-
from math import trunc
import re


class Iso8601Duration:
    """
    Class to parse and store ISO 8601 duration strings
    This class will not respect pure ISO standard for following reasons:
    - Allow combining weeks and others units without +- sign
    - Assume work hours and days only, so 1Y = 12M = 52W; 1M = 4W; 1W = 5D; 1D = 8H
    - Will accept non-integer for any units but will convert them to integer when exporting
    Reference: https://en.wikipedia.org/wiki/ISO_8601#Durations
    """

    regex_parse = re.compile(r"""^P
        ([\d\.]+Y)?         # years
        ([\d\.]+M)?         # months
        ([\d\.]+W)?         # weeks
        ([\d\.]+D)?         # days
        (T
            ([\d\.]+H)?     # hours
            ([\d\.]+M)?     # minutes
            ([\d\.]+S)?     # seconds
        )?$""", re.VERBOSE | re.IGNORECASE)
    """
    Regex to parse ISO 8601 duration string
    Will match each part in a group
    """

    regex_validate = re.compile(r"""^P
        (T)?                # is time separator present at start
        [\d\.]+             # at least one digit
        (?(1)               # if time separator is present
            [HMS]           #   must have at least one time unit
            |               # else
            [YMDW]          #   must have at least one date unit
        )""", re.VERBOSE | re.IGNORECASE)
    """
    Regex to validate ISO 8601 duration string
    Will check if at least one digit is present and at least one unit is present
    """

    def __init__(self, duration: str):
        """
        Initialize the class with a ISO 8601 duration string
        Raise ValueError if not valid
        """
        self.years = 0
        self.months = 0
        self.weeks = 0
        self.days = 0
        self.hours = 0
        self.minutes = 0
        self.seconds = 0
        self.total_seconds = 0

        self.parse_duration(duration)

    def parse_duration(self, duration: str):
        """
        Parse the ISO 8601 duration string
        Internal use only, automatically called when creating the object
        Raises ValueError if the duration is not valid
        """
        if type(duration) is not str:
            raise ValueError(f"Can only parse string, received: {duration}")

        match = self.regex_parse.match(duration)
        if not match:
            raise ValueError(f"Invalid ISO 8601 duration: {duration}")

        if not self.regex_validate.match(duration):
            raise ValueError(f"Invalid ISO 8601 duration: {duration}")

        years = float(match.group(1)[:-1]) if match.group(1) else 0
        months = float(match.group(2)[:-1]) if match.group(2) else 0
        weeks = float(match.group(3)[:-1]) if match.group(3) else 0
        days = float(match.group(4)[:-1]) if match.group(4) else 0
        hours = float(match.group(6)[:-1]) if match.group(6) else 0
        minutes = float(match.group(7)[:-1]) if match.group(7) else 0
        seconds = float(match.group(8)[:-1]) if match.group(8) else 0

        months += (years % 1) * 12
        years = trunc(years)
        weeks += (months % 1) * 4
        months = trunc(months)
        days += (weeks % 1) * 5
        weeks = trunc(weeks)
        hours += (days % 1) * 8
        days = trunc(days)
        minutes += (hours % 1) * 60
        hours = trunc(hours)
        seconds += (minutes % 1) * 60
        minutes = trunc(minutes)
        seconds = trunc(seconds)

        if seconds >= 60:
            minutes += seconds // 60
            seconds %= 60
        if minutes >= 60:
            hours += minutes // 60
            minutes %= 60
        if hours >= 8:
            days += hours // 8
            hours %= 8
        if days >= 5:
            weeks += days // 5
            days %= 5
        if weeks >= 4:
            months += weeks // 4
            weeks %= 4
        if months >= 12:
            years += months // 12
            months %= 12

        if years < 0 or months < 0 or weeks < 0 or days < 0 or hours < 0 or minutes < 0 or seconds < 0:
            raise ValueError(f"Negative duration is not allowed: {duration}")

        self.years = int(years)
        self.months = int(months)
        self.weeks = int(weeks)
        self.days = int(days)
        self.hours = int(hours)
        self.minutes = int(minutes)
        self.seconds = int(seconds)
        self.total_seconds = (
            (
                (
                    (
                        (
                            (self.years * 12 + self.months)
                            * 4 + self.weeks)
                        * 5 + self.days)
                    * 8 + self.hours)
                * 60 + self.minutes)
            * 60 + self.seconds)

    def __str__(self):
        """
        Return the ISO 8601 duration as tidy string, removing overloaded or empty parts
        """
        fmt = "P"
        if self.years:
            fmt += f"{self.years}Y"
        if self.months:
            fmt += f"{self.months}M"
        if self.weeks:
            fmt += f"{self.weeks}W"
        if self.days:
            fmt += f"{self.days}D"
        if self.hours or self.minutes or self.seconds:
            fmt += "T"
            if self.hours:
                fmt += f"{self.hours}H"
            if self.minutes:
                fmt += f"{self.minutes}M"
            if self.seconds:
                fmt += f"{self.seconds}S"

        if fmt == "P":
            fmt += "0D"
        return fmt

    def __repr__(self):
        return f"Iso8601Duration({str(self)})"

    def human_readable(self):
        """
        Return the ISO 8601 duration as human readable string
        """
        fmt = ""
        if self.years:
            fmt += f"{self.years}y "
        if self.months:
            fmt += f"{self.months}mo "
        if self.weeks:
            fmt += f"{self.weeks}w "
        if self.days:
            fmt += f"{self.days}d "
        if self.hours:
            fmt += f"{self.hours}h "
        if self.minutes:
            fmt += f"{self.minutes}m "

        if fmt == "":
            fmt += "N/A"
        return fmt.strip()

    @staticmethod
    def try_parse(something):
        """
        Try to parse the input as Iso8601Duration
        Raise ValueError if not possible
        """
        if something == 0:
            return Iso8601Duration("P0D")
        if type(something) is str:
            return Iso8601Duration(something)
        if isinstance(something, Iso8601Duration):
            return something
        raise ValueError(f"Can only compare with 0, Iso8601duration or valid ISO 8601 string, compared to: {something}")

    def __eq__(self, other):
        if other == 0:
            return self.total_seconds == 0
        if other is None:
            return False
        other = Iso8601Duration.try_parse(other)
        return self.total_seconds == other.total_seconds

    def __ne__(self, other):
        return not self == other

    def __bool__(self):
        return self.total_seconds > 0

    def __gt__(self, other):
        if other == 0:
            return self.total_seconds > 0
        if other is None:
            return True
        other = Iso8601Duration.try_parse(other)
        return self.total_seconds > other.total_seconds

    def __ge__(self, other):
        return self == other or self > other

    def __lt__(self, other):
        return not self >= other

    def __le__(self, other):
        return not self > other

    def __add__(self, other):
        other = Iso8601Duration.try_parse(other)
        return Iso8601Duration(f"PT{self.total_seconds + other.total_seconds}S")

    def __sub__(self, other):
        other = Iso8601Duration.try_parse(other)
        if self.total_seconds < other.total_seconds:
            raise ValueError(f"Subtracting larger duration from smaller is not allowed: {self} - {other}")
        return Iso8601Duration(f"PT{self.total_seconds - other.total_seconds}S")

    def __mul__(self, other):
        if type(other) is not float and type(other) is not int:
            raise ValueError(f"Can only multiply with integer or float, received: {other}")
        if other < 0:
            raise ValueError(f"Multiplying with negative number is not allowed: {other}")
        return Iso8601Duration(f"PT{self.total_seconds * other}S")

    def __truediv__(self, other):
        if type(other) is not int:
            raise ValueError(f"Can only divide by integer, received: {other}")
        return Iso8601Duration(f"PT{self.total_seconds // other}S")

    def __floordiv__(self, other):
        return self.__truediv__(other)
