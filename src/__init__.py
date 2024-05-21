# -*- coding: utf-8 -*-
"""
Code in this project follow the Model-View-Controller (MVC) pattern.
On the left panel, you can access the models, views, and controllers part of the code.

Classes in `models` folder are used to represent the data of the application. For example, Vulnerability, Package or CVSS classes are here.

Classes in `controller` folder are used to manage list of data reprensented by models. For example, VulnerabilityController or PackageController classes are here. You will interact with them when adding, getting or filtering data.

This app have two kind of views: web view, which are mostly JavaScript on browser side and few Python API code, and files.
Most of the time, this python script will read and write file as I/O operations. So, you will find the file operations (parsing, formating) in the `views` folder.
"""
