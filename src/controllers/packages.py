# -*- coding: utf-8 -*-
from ..models.package import Package


class PackagesController:
    """
    A class to handle a list of packages, de-duplicating them and handling low-level stuff.
    Packages can be added, removed, retrieved and exported or imported as dictionaries.
    """

    def __init__(self):
        self.packages = {}

    def get(self, package_id: str):
        """Return a package by id (str) or None if not found."""
        return self.packages.get(package_id)

    def add(self, package: Package):
        """Add a package to the list, merging it with an existing one if present."""
        if package is None:
            return
        if package.id not in self.packages:
            self.packages[package.id] = package
        else:
            self.packages[package.id].merge(package)

    def remove(self, package_id: str) -> bool:
        """Remove a package by id (str) and return True if removed, False if not found."""
        if package_id in self.packages:
            del self.packages[package_id]
            return True
        return False

    def to_dict(self) -> dict:
        """Export the list of packages as a dictionary of dictionaries."""
        return {k: v.to_dict() for k, v in self.packages.items()}

    def from_dict(data: dict):
        """Import a list of packages from a dictionary of dictionaries."""
        item = PackagesController()
        for k, v in data.items():
            item.add(Package.from_dict(v))
        return item

    def __contains__(self, item) -> bool:
        """
        Check if the item is in the packages list.
        The item can be a Package class or a string representation of Package.id.
        """
        if isinstance(item, str):
            return item in self.packages
        elif isinstance(item, Package):
            return item.id in self.packages
        return False

    def __len__(self) -> int:
        """Return the number of packages in the list."""
        return len(self.packages)

    def __iter__(self):
        """Allow iteration over the list of packages."""
        return iter(self.packages.values())
