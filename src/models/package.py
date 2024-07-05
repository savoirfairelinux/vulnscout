# -*- coding: utf-8 -*-
import semver


class Package:
    """
    Represent a package composed of a name, a version and identifiers like cpe or purl.
    Packages can be compared, merged and exported or imported as dictionaries.
    """

    def __init__(self, name: str, version: str, cpe=[], purl=[]):
        """
        Create a package by name (str) and version (str).
        Version should be a semver compatible string.
        cpe and purl are optional lists of identifiers.
        """
        self.name = name

        # handle vendor:package format
        if len(name.split(':')) == 2:
            self.name = name.split(':')[1]
            cpe.append(f"cpe:2.3:a:{name}:{version}:*:*:*:*:*:*:*")
            purl.append(f"pkg:generic/{name.replace(':', '/')}@{version}")

        self.version = version.split("+git")[0]
        self.id = f"{self.name}@{self.version}"
        self.cpe = []
        self.purl = []
        for c in cpe:
            self.add_cpe(c)
        for p in purl:
            self.add_purl(p)

    def add_cpe(self, cpe: str):
        """Add a single cpe (str) identifier to the package if not already present."""
        if cpe not in self.cpe:
            self.cpe.append(cpe)

    def add_purl(self, purl: str):
        """Add a single purl (str) identifier to the package if not already present."""
        if purl not in self.purl:
            self.purl.append(purl)

    def generate_generic_cpe(self) -> str:
        """Build a generic cpe string for the package, add it to the cpe list and return it."""
        item = f"cpe:2.3:*:*:{self.name}:{self.version}:*:*:*:*:*:*:*"
        self.add_cpe(item)
        return item

    def generate_generic_purl(self) -> str:
        """Build a generic purl string for the package, add it to the purl list and return it."""
        item = f"pkg:generic/{self.name}@{self.version}"
        self.add_purl(item)
        return item

    def __eq__(self, other) -> bool:
        """
        Compare two package (self == other) by name and version using semver.
        If version is not semver compatible, compare as strings.
        """
        try:
            my_v = semver.Version.parse(self.version, optional_minor_and_patch=True)
            ot_v = semver.Version.parse(other.version, optional_minor_and_patch=True)
            return self.name == other.name and my_v == ot_v
        except:
            return self.name == other.name and self.version == other.version

    def __hash__(self) -> int:
        """Return a hash of the package based on its name and version."""
        return hash((self.name, self.version))

    def __str__(self) -> str:
        """Return a string representation of the package as name@version format."""
        return self.id

    def __lt__(self, other) -> bool:
        """
        Compare two package (self < other) by name and version using semver.
        If version is not semver compatible, compare as strings.
        """
        if self.name != other.name:
            return self.name < other.name
        try:
            my_v = semver.Version.parse(self.version, optional_minor_and_patch=True)
            ot_v = semver.Version.parse(other.version, optional_minor_and_patch=True)
            return my_v < ot_v
        except:
            return self.version < other.version

    def __gt__(self, other) -> bool:
        """
        Compare two package (self > other) by name and version using semver.
        If version is not semver compatible, compare as strings.
        """
        if self.name != other.name:
            return self.name > other.name
        try:
            my_v = semver.Version.parse(self.version, optional_minor_and_patch=True)
            ot_v = semver.Version.parse(other.version, optional_minor_and_patch=True)
            return my_v > ot_v
        except:
            return self.version > other.version

    def __le__(self, other) -> bool:
        """
        Compare two package (self <= other) by name and version using semver.
        If version is not semver compatible, compare as strings.
        """
        return self < other or self == other

    def __ge__(self, other) -> bool:
        """
        Compare two package (self >= other) by name and version using semver.
        If version is not semver compatible, compare as strings.
        """
        return self > other or self == other

    def __ne__(self, other) -> bool:
        """
        Compare two package (self != other) by name and version using semver.
        If version is not semver compatible, compare as strings.
        """
        return not self == other

    def __contains__(self, item) -> bool:
        """
        Check if the item is in the package.
        The item can be a Package class or a string representation of Package.id, cpe or purl.
        """
        if isinstance(item, Package):
            return item.id == self.id
        if isinstance(item, str):
            return item == self.id or item in self.cpe or item in self.purl
        return False

    def to_dict(self) -> dict:
        """Export the package as a dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "cpe": self.cpe,
            "purl": self.purl
        }

    def from_dict(data: dict):
        """Import a package from a dictionary."""
        return Package(data["name"], data["version"], data.get("cpe", []), data.get("purl", []))

    def merge(self, other) -> bool:
        """Merge two packages by adding the cpe and purl identifiers of the other package to the current one."""
        if self == other:
            for c in other.cpe:
                self.add_cpe(c)
            for p in other.purl:
                self.add_purl(p)
            return True
        return False
