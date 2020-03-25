# tetSetup
This application helps to quickly setup a Tetration Analytics Cluster with tenants, root scopes, subscopes, annotation upload, Agent Config Profile, Apply to Scope, redirect telemetry to VRF, create roles and users.

## Table of contents
* [Installation](#Installation)
* [Screenshots](#screenshots)
* [How to Use](#UserGuide)
* [Files](#Files)
* [Steps to run](#Steps)
* [Feedback and Author](#Feedback)

## Installation

From sources

Download the sources from [Github](https://github.com/leeahnduk/TetSetup.git), extract and execute the following commands

```
$ pip3 install -r requirements.txt

```

## Screenshots
![Example screenshot](https://github.com/leeahnduk/TetSetup/blob/master/tetsetup.jpg)

## UserGuide
How to use this application:
To access to the cluster you need to get the API Credentials with the following permissions
* `sensor_management` - option: SW sensor management: API to configure and monitor status of SW sensors
* `hw_sensor_management` - option: HW sensor management: API to configure and monitor status of HW sensors
* `flow_inventory_query` - option: Flow and inventory search: API to query flows and inventory items in Tetration cluster
* `user_role_scope_management` - option: Users, roles and scope management: API for root scope owners to read/add/modify/remove users, roles and scopes
* `app_policy_management` - option: 
 Applications and policy management: API to manage applications and enforce policies

Download the api_credentials.json locally and have it ready to get the information required for the setup.

A quick look for the help will list the current available options.
To start the script, just use: `python3 onboard.py --url https://tet-cluster-ip --credential api_credentials.json`

## Files
Need to have sample annotation file to upload to Tetration. The sample csv file is in the github folder.


## Steps

Step 1: Issue `$ pip3 install -r requirements.txt` to install all required packages.

Step 2: Run the apps: `python3 onboard.py --url https://tet-cluster-ip --credential api_credentials.json`

Step 3: Answer all the questions to finish setting up the cluster.
is the sensors detail: 

Step 4: Run the apps: `python3 clean.py --url https://tet-cluster-ip --credential api_credentials.json` to clean all the objects in the root scope.

## Feedback
Any feedback can send to me: Le Anh Duc (leeahnduk@yahoo.com or anhdle@cisco.com)
