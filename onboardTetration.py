from tetpyclient import RestClient
import tetpyclient
import json
import argparse
import requests.packages.urllib3
from argparse import ArgumentParser
from collections import defaultdict
from datetime import datetime
import sys

from tetpyclient import RestClient
from tqdm import tqdm as progress
import urllib3

CEND = "\33[0m"     #End
CGREEN = "\33[32m"  #Information
CYELLOW = "\33[33m" #Request Input
CRED = "\33[31m"    #Error
URED = "\33[4;31m" 
Cyan = "\33[0;36m"  #Return

# =================================================================================
# See reason below -- why verify=False param is used
# python3 onboardTetration.py --url https://asean-tetration.cisco.com/ --credential jonathan_api_credentials.json
# feedback: Le Anh Duc - anhdle@cisco.com
# =================================================================================

requests.packages.urllib3.disable_warnings()


parser = argparse.ArgumentParser(description='Tetration Get all scopes')
parser.add_argument('--url', help='Tetration URL', required=True)
parser.add_argument('--credential', help='Path to Tetration json credential file', required=True)
args = parser.parse_args()


def CreateRestClient():
    rc = RestClient(args.url,
                    credentials_file=args.credential, verify=False)
    return rc

def GetApplicationScopes(rc):
    #Return all scopes in cluster
    resp = rc.get('/app_scopes')

    if resp.status_code != 200:
        print("Failed to retrieve app scopes")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def GetAppScopeId(scopes,name):
    #return scope ID from scope name
    try:
        return [scope["id"] for scope in scopes if scope["name"] == name][0]
    except:
        print("App Scope {name} not found".format(name=name)) 

def GetVRFs(rc):
    # Get all VRFs in the cluster
    resp = rc.get('/vrfs')

    if resp.status_code != 200:
        print("Failed to retrieve app scopes")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def GetRootScope(vrfs):
    #return list of Root Scopes and its' names
    rootScopes = []
    for vrf in vrfs:
        rootScopes.append([vrf["name"] , vrf["vrf_id"]])
    return rootScopes


def build_root(rc):
    """Build new root scope if required. ie if not existing in validate_current function.
    Returns:
        root_app_scope_id: App scope id as created for the root scope
    """
    root_scopes = defaultdict(str)
    root_ids = defaultdict(str)
    root_app_scope_id = ""

    resp = rc.get("/vrfs")
    parsed_resp = json.loads(resp.content)
    if resp.status_code == 200:
        for vrf in parsed_resp:
            root_scopes[vrf["name"]] = vrf["id"]
            root_ids[vrf["name"]] = vrf["root_app_scope_id"]
    else:
        print("No root scopes have been defined.")

    root_scope = input("Enter the name of the new root scope: ")
    print("Building root scope: "+CYELLOW+root_scope+CEND)
    root_scope_id = input("Enter the root scope id: ")
    for scope_id in root_scopes.items():
        if scope_id == root_scope_id:
            print("This id is already in use.  Please try again with a unique root scope id.")
            sys.exit(0)

# Now build the root scope
    req_payload = {
        "id": root_scope_id,
        "name": root_scope
    }

    resp = rc.post("/vrfs", json_body=json.dumps(req_payload))
    parsed_resp = json.loads(resp.content)

    if resp.status_code == 200:
        print("Root scope "+root_scope+" created with id "+str(parsed_resp["id"]))
        root_app_scope_id = parsed_resp["root_app_scope_id"]
    else:
        print("Error occured during root scope creation")
        print("Error code: "+str(resp.status_code))
        print("Content: ")
        print(resp.content)
        sys.exit(3)

    return root_scope, root_app_scope_id  

def defineRoot(rc):
    """Validate existing root scopes and identify target root if existing.
    If target root does not exist, build it via build_root function

    Returns:
        root_scope: Root scope name for scope build
        root_app_scope_id: App scope id for root scope
    """

    root_scopes = defaultdict(str)
    root_ids = defaultdict(str)
    root_app_scope_id = ""

    resp = rc.get("/vrfs")
    parsed_resp = json.loads(resp.content)
    if resp.status_code == 200:
        for vrf in parsed_resp:
            root_scopes[vrf["name"]] = vrf["id"]
            root_ids[vrf["name"]] = vrf["root_app_scope_id"]
    if root_scopes:
        print("\nYou have the following "+str(len(root_scopes))+" root scopes configured.")
        print(*root_scopes, sep="\n")
        print(CGREEN)
        root_scope = input("Enter the name of the root scope to use for scope definition: "+CEND)

        if root_scope in root_scopes:
            print("Using root scope "+root_scope+" with id "+str(root_scopes[root_scope])+
                  " for scope definition")
            root_app_scope_id = str(root_ids[root_scope])
        else:
            print("That root scope does not exist.")
            while True:
                response = input("Would you like to create a new root scope? [y/n]: ").lower()
                if response == "n":
                    print("Okay.  Please validate the inputs and try again.")
                    sys.exit(0)
                elif response == "y":
                    root_scope, root_app_scope_id = build_root(rc)
                    break
                else:
                    print("Invalid entry, please try again...")
    else:
        print("No root scopes have been defined.")

        while True:
            response = input("Would you like to define a new root scope? [y/n]: ").lower()
            if response == "n":
                print("Okay.  Please validate the inputs and try again.")
                sys.exit(0)
            elif response == "y":
                root_scope, root_app_scope_id = build_root(rc)
                break
            else:
                print("Invalid entry, please try again...")

    return root_scope, root_app_scope_id  


def build_subscope(rc):
    """Build sub scope under root scope

    Returns:
        sub_scope: Sub scope name for scope build
        sub_cope_id: App scope id for sub scope
    """
    root_scope, root_scope_vrf_id = defineRoot(rc)
    scopes = GetApplicationScopes(rc)
    root_scope_id = GetAppScopeId(scopes,root_scope)
    sub_scope = input("Name of the sub scope under Root Scope " + root_scope + " you want to create: ")
    subnet = input("Which subnet or IP you want your query is (X.X.X.X/Y): ")
    print("Building sub scope: "+CYELLOW+sub_scope+ " under Root Scope " +CYELLOW+root_scope)
    
    # Now build the sub scope
    req_payload = {
        "short_name": sub_scope,
            "short_query": {
                "type": "subnet",
                "field": "ip",
                "value": subnet
            },
        "parent_app_scope_id": root_scope_id
    }
    
    resp = rc.post("/app_scopes", json_body=json.dumps(req_payload))
    parsed_resp = json.loads(resp.content)
    if resp.status_code == 200:
        sub_scope_id = str(parsed_resp["id"])
        print("Sub scope: "+CYELLOW+sub_scope+ "with scope ID " +CYELLOW+sub_scope_id +" has been created")
    else:
        print("Error occured during sub scope creation")
        print("Error code: "+str(resp.status_code))
        print("Content: ")
        print(resp.content)
        sys.exit(3)

    return sub_scope, sub_scope_id

def commit_scopes(rc):
    #Commit scope changes
    scopes = GetApplicationScopes(rc)
    vrfs = GetVRFs(rc)
    RootScopesList = GetRootScope(vrfs)
    print (Cyan + "\nHere are the names and VRF ID of all the root scopes in your cluster: ")
    print (*RootScopesList, sep ="\n")
    scope = input (CGREEN + "\nWhat is the Root scope you want to commit all the scope changes: ")
    scope_id = GetAppScopeId(scopes,scope)
    
    # commit scope changes
    req_payload = {
        "root_app_scope_id": scope_id
    }
    
    resp = rc.post("/app_scopes/commit_dirty", json_body=json.dumps(req_payload))
    parsed_resp = json.loads(resp.content)
    if resp.status_code == 202:
        print("Scope commits are undergoing ")
    else:
        print("Error occured during scope changes commit")
        print("Error code: "+str(resp.status_code))
        print("Content: ")
        print(resp.content)
        sys.exit(3)


def uploadAnnotation(rc):
    #Upload Annotation Tags to Tetration root Scope. Sample csv: need to have IP as anchor point, can add upto 32 annotations.
    vrfs = GetVRFs(rc)
    RootScopesList = GetRootScope(vrfs)
    print (Cyan + "\nHere are the names and VRF ID of all the root scopes in your cluster: ")
    print(*RootScopesList, sep="\n")
    root_scope_name = input(CGREEN +"\nWhat is the root scope you want to upload annotations: ")
    file_path = "sampleAnnotationUpload.csv"
    req_payload = [tetpyclient.MultiPartOption(key='X-Tetration-Oper', val='add')]
    resp= rc.upload(file_path, "/assets/cmdb/upload/" + root_scope_name, req_payload)
    if resp.status_code == 200:
        print("\nUploaded sucessful!" + CEND)
    else:
        print("Error occured during upload annotation file")
        print("Error code: "+str(resp.status_code))
        sys.exit(3)

def getRoles(rc):
    #Get all roles in the cluster
    resp = rc.get('/roles')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve inventories list")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()


def GetRolesNamewithID(roles):
    #Get list of Roles and their names
    RolesList = []
    for role in roles:
        RolesList.append([role["name"] , role["id"]])
    return RolesList  

def GetRoleId(roles, name):
    #Return Role ID from its' name
    try:
        for role in roles:
            if name == role["name"]:
                print ("Here is your Role ID: " + role["id"])
                return role["id"]
            else: continue
    except:
        print(URED + "Role {name} not found".format(name=name))


def CreateRole(rc):
    #Create new Role. Return Role name and ID
    name = input (CGREEN + "\nKey in the name of the Role you want to create: ")
    Roles = getRoles (rc)
    for role in Roles:
        if name == role["name"]:
            print(URED + "\nRole {name} is conflict with existing Role filter. Please choose different name".format(name=name))
        else:
            scopes = GetApplicationScopes(rc)
            vrfs = GetVRFs(rc)
            RootScopesList = GetRootScope(vrfs)
            print (Cyan + "\nHere are the names and VRF ID of all the root scopes in your cluster: ")
            for elem in RootScopesList:
                print (elem)
            scope = input (CGREEN + "\nWhat is the Root scope you want your filter belong to: ")
            scope_id = GetAppScopeId(scopes,scope)
            print(CGREEN + "\nBuilding Role: "+CYELLOW+name+ CGREEN + " under Scope " +CYELLOW+scope)
            req_payload = {
            "app_scope_id": scope_id,
            "description": "Created by Python",
            "name": name
            }
            resp = rc.post("/roles", json_body=json.dumps(req_payload))
            parsed_resp = json.loads(resp.content)
            if resp.status_code == 200:
                Role_id = parsed_resp["id"]
                print(Cyan + "\nRole: "+CYELLOW+name+ Cyan + " with Role ID: " + CYELLOW + Role_id + Cyan + " has been created")
            else:
                print("Error occured during sub scope creation")
                print("Error code: "+str(resp.status_code))
                print("Content: ")
                print(resp.content)
                sys.exit(3)
            return name, Role_id

def role2Scope(rc):
    #Apply role to scope. Return role ID and Scope ID
    roles = getRoles(rc)
    scopes = GetApplicationScopes(rc)
    RolesList = GetRolesNamewithID(roles)
    print (CGREEN + "\nHere is the list of Roles in Tetration cluster: " + Cyan)
    for elem in RolesList:
        print (elem)
    role_name = input (CGREEN + "\nKey in the name of the Role you want to assign to scope: ")
    role_id = GetRoleId(roles,role_name)
    scope_name = input (CGREEN + "\nWhich scope (Root:Sub) you want to assign the Role to: ")
    scope_id = GetAppScopeId (scopes,scope_name)
    ability = input (CGREEN + "\nWhich ability (SCOPE_READ, SCOPE_WRITE, EXECUTE, ENFORCE, SCOPE_OWNER, DEVELOPER) you want to assign for this role: ")
    print(CGREEN + "\nAssigning Role: "+CYELLOW+role_name+ CGREEN + " into Scope " +CYELLOW+scope_name)
    req_payload = {
    "app_scope_id": scope_id,
    "ability": ability
    }
    resp = rc.post("/roles/" + role_id + "/capabilities", json_body=json.dumps(req_payload))
    parsed_resp = json.loads(resp.content)
    if resp.status_code == 200:
        print(Cyan + "\nRole: "+CYELLOW+role_name+ Cyan + " with " +CYELLOW+ability+ Cyan+ " assigned to " + CYELLOW + scope_name + Cyan)
    else:
        print("Error occured during assigning role to scope")
        print("Error code: "+str(resp.status_code))
        print("Content: ")
        print(resp.content)
        sys.exit(3)
    return role_id, scope_id

def getUsers(rc):
    #Get all users in cluster
    resp = rc.get('/users')

    if resp.status_code != 200:
        print(CRED + "Failed to retrieve users list")
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()


def CreateUser(rc):
    #Create new User and assign Role to this user. Return email and User_ID
    email = input (CGREEN + "\nKey in the email of the User you want to create: ")
    Users = getUsers (rc)
    for User in Users:
        if email == User["email"]:
            print(CRED + "\nUser with {email} is conflict with existing User filter. Please choose different email".format(email=email))
        else:
            scopes = GetApplicationScopes(rc)
            scope_name = input (CGREEN + "\nWhat is the scope (Root:Sub) you want your user belong to: ")
            scope_id = GetAppScopeId(scopes,scope_name)
            first_name = input (CGREEN + "\nWhat is the firstname of your user: ")
            last_name = input (CGREEN + "\nWhat is the lastname of your user: ")
            Roles = getRoles(rc)
            RolesList = GetRolesNamewithID(Roles)
            print (CGREEN + "\nHere are the names and ID of all Roles in your cluster: ")
            for elem in RolesList:
                print (elem)
            role_name = input (CGREEN + "\nWhich role above you want your user has: ")
            role_id = GetRoleId(Roles, role_name)
            print(CGREEN + "\nCreating User: "+CYELLOW+first_name+ CGREEN + " under Scope " +CYELLOW+scope_name+ CGREEN + " and Role " + CYELLOW+role_name)
            req_payload = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "app_scope_id": scope_id,
            "role_ids": role_id
            }
            resp = rc.post("/users", json_body=json.dumps(req_payload))
            parsed_resp = json.loads(resp.content)
            if resp.status_code == 200:
                User_id = parsed_resp["id"]
                print(Cyan + "\nUser: "+CYELLOW+first_name+ Cyan + " with User ID: " + CYELLOW + User_id + Cyan + " has been created")
            else:
                print("Error occured during user creation")
                print("Error code: "+str(resp.status_code))
                print("Content: ")
                print(resp.content)
                sys.exit(3)
            return email, User_id

def GetAgentProfiles(rc):
    #Get all Agent config profiles in cluster
    resp = rc.get('/inventory_config/profiles')

    if resp.status_code != 200:
        print(URED + "Failed to retrieve Agent Profiles list" + CEND)
        print(resp.status_code)
        print(resp.text)
    else:
        return resp.json()

def GetProfilesId(Profiles, name):
    #Get all Profile ID from its' name.
    try:
        for prof in Profiles:
            if name == prof["name"]:
                print (Cyan +"Here is your Profile ID: " + prof["id"])
                return prof["id"]
            else: continue
    except:
        print(URED + "Profile {name} not found".format(name=name)+ CEND)


def Createprofile(rc):
    #Create new Agent config profile. Return Poofile name and ID
    name = input (CYELLOW + "\nKey in the name of the Agent Config Profile you want to create: ")
    profiles = GetAgentProfiles (rc)
    for prof in profiles:
        if name == prof["name"]:
            print(URED + "\nProfile {name} is conflict with existing Agent Config profile. Please choose different name".format(name=name) + CEND)
        else:
            scopes = GetApplicationScopes(rc)
            vrfs = GetVRFs(rc)
            RootScopesList = GetRootScope(vrfs)
            print (Cyan + "\nHere are the names and VRF ID of all the root scopes in your cluster: ")
            print(*RootScopesList, sep = "\n")
            root_scope = input (CYELLOW + "\nWhich Root Scope above you want to get your orchestrator: ")
            scope_id = GetAppScopeId(scopes,root_scope)
            print (CGREEN + "Here is some config you need to define: ")
            
            auto_upgrade = input (CYELLOW + "Auto upgrade agents (y/n?): ")
            if auto_upgrade == 'y': auto_upgrade = False
            else: auto_upgrade = True
            
            pid_lookup = input (CYELLOW + "Allow Process ID Lookup (y/n?): ")
            if pid_lookup == 'y': pid_lookup = True
            else: pid_lookup = False

            enforcement = input (CYELLOW + "Allow Agent enforcement - Host Based FW (y/n?): ")
            if enforcement == 'y': enforcement = False
            else: enforcement = True

            forensics = input (CYELLOW + "Enable Secure Forensics Security Events for servers (y/n?): ")
            if forensics == 'y': forensics = True
            else: forensics = False

            meltdown = input (CYELLOW + "Enable Meltdown detection for servers (y/n?): ")
            if meltdown == 'y': meltdown = True
            else: meltdown = False

            sidechannel = input (CYELLOW + "Enable SideChannel Attack detection for servers (y/n?): ")
            if sidechannel == 'y': sidechannel = True
            else: sidechannel = False

            print(CGREEN + "\nBuilding profile: "+CYELLOW+name+ CGREEN + " under Scope " +CYELLOW+root_scope + CEND)
            req_payload = {
            "name": name,
            "root_app_scope_id": scope_id,
            "data_plane_disabled": False,
            "auto_upgrade_opt_out": auto_upgrade,
            "enable_pid_lookup": pid_lookup,
            "enforcement_disabled": enforcement,
            "enable_forensics": forensics,
            "enable_meltdown": meltdown,
            "enable_cache_sidechannel": sidechannel,
            "allow_broadcast": True,
            "allow_multicast": True,
            "allow_link_local": True
            }

            resp = rc.post("/inventory_config/profiles", json_body=json.dumps(req_payload))
            parsed_resp = json.loads(resp.content)
            if resp.status_code == 200:
                sub_scope_id = str(parsed_resp["id"])
                print(Cyan + "\nProfile: "+CYELLOW+name+ Cyan + " with ID" + parsed_resp["id"]+" has been created"+ CEND)
            else:
                print("Error occured during Agent Config Profile creation")
                print("Error code: "+str(resp.status_code))
                print("Content: ")
                print(resp.content)
                sys.exit(3)
            return parsed_resp["name"], parsed_resp["id"]

def ApplyProfile2Filter(rc, profile_id):
    #Apply Agent profile into filter
    filter_id =""
    choice = input (CYELLOW + "\nDo you want to apply your profile to Scope (S) or Filter (F)? ")
    if choice == ("Scope" or "scope" or "s" or "S"):
        scope_choice = input (CYELLOW + "\nDo you want to apply your profile to Root Scope (R) or sub scope (S)? ")
        if scope_choice == ("R" or "r"):
            vrfs = GetVRFs(rc)
            scopes = GetApplicationScopes(rc)
            RootScopesList = GetRootScope(vrfs)
            print (Cyan + "\nHere are the names and VRF ID of all the root scopes in your cluster: ")
            print(*RootScopesList, sep="\n")
            root_scope_name = input(CGREEN +"\nWhat is the root scope you want to apply your Agent Profile to? ")
            filter_id = GetAppScopeId(scopes,root_scope_name)
        if scope_choice == ("S" or "s"):
            scope_name = input(CGREEN +"\nWhat is the sub scope (Root:Subscope) you want to apply your Agent Profile to? ")
            scopes = GetApplicationScopes(rc)
            filter_id = GetAppScopeId(scopes,scope_name)
        print(CGREEN + "\nApplying profile with ID : "+CYELLOW+profile_id+ CGREEN + " into " +CYELLOW+filter_id + CEND)
        req_payload = {
            "inventory_config_profile_id": profile_id,
            "inventory_filter_id": filter_id
            }
        resp = rc.post("/inventory_config/intents", json_body=json.dumps(req_payload))
        parsed_resp = json.loads(resp.content)
        if resp.status_code == 200:
            Agent_Config_intent_id = str(parsed_resp["id"])
            print(Cyan + "\nAgent Config Intent with ID : "+CYELLOW+Agent_Config_intent_id+ Cyan +" has just been created"+ CEND)
        else:
            print("Error occured during apply Agent Config Profile to Filter")
            print("Error code: "+str(resp.status_code))
            print("Content: ")
            print(resp.content)
            sys.exit(3)
        return Agent_Config_intent_id
    if choice == ("Filter" or "filter" or "f" or "F"):
        inventories = GetInventories(rc)
        inventoriesList = GetInventoriesNamewithID(inventories)
        print (CGREEN + "\nHere are the names and ID of all inventories in your cluster: ")
        print (*inventoriesList, sep = "\n")
        inv_name = input (CYELLOW + "\nWhich inventory name you want to apply your agent profile: ")
        filter_id = GetInventoriesId(inventories, inv_name)
        print(CGREEN + "\nApplying profile with ID : "+CYELLOW+profile_id+ CGREEN + " into " +CYELLOW+filter_id + CEND)
        req_payload = {
            "inventory_config_profile_id": profile_id,
            "inventory_filter_id": filter_id
            }
        resp = rc.post("/inventory_config/intents", json_body=json.dumps(req_payload))
        parsed_resp = json.loads(resp.content)
        if resp.status_code == 200:
            Agent_Config_intent_id = str(parsed_resp["id"])
            print(Cyan + "\nAgent Config Intent with ID : "+CYELLOW+Agent_Config_intent_id+ Cyan +" has just been created"+ CEND)
        else:
            print("Error occured during apply Agent Config Profile to Filter")
            print("Error code: "+str(resp.status_code))
            print("Content: ")
            print(resp.content)
        return Agent_Config_intent_id


def remoteVRF(rc):
    #This endpoint is used to specify criteria for VRF tagging for hosts based on their source IP and source port as seen by Tetration appliance.
    vrfs = GetVRFs(rc)
    RootScopesList = GetRootScope(vrfs)
    print (Cyan + "\nHere are the names and VRF ID of all the root scopes in your cluster: ")
    print (*RootScopesList, sep ="\n")
    vrf_id = input (CGREEN + "\nWhich VRF_ID above you want to organize your telemetry: ")
    src_subnet = input (CGREEN + "\nWhat is the source subnet (Ex. 192.168.1.0/24): ")
    src_port_range_start = input (CGREEN + "\nWhat is the source port range start(Ex. 0): ")
    src_port_range_end = input (CGREEN + "\nWhat is the source port range end (Ex. 65535): ")
    print(CGREEN + "\nMoving your telemetry to VRF " + vrf_id + CEND)
    req_payload = {
    "src_subnet": src_subnet,
    "src_port_range_start": int(src_port_range_start),
    "src_port_range_end": int(src_port_range_end),
    "vrf_id": int(vrf_id)}


    resp = rc.post("/agentnatconfig", json_body=json.dumps(req_payload))
    if resp.status_code == 201 or resp.status_code == 200 :
        print(Cyan + "Your telemetry has been moved to VRF " + vrf_id + CEND)
    else:
        print("Error occured during moving telemetry to VRF")
        print("Error code: "+str(resp.status_code))
        print("Content: ")
        print(resp.content)

def main():
    rc = CreateRestClient()
    print(CGREEN +"\nHere are basic steps to fresh start Tetration:")
    print(CGREEN +"\nStep 1: Creating new Tenant and Root Scope:")
    build_root(rc)
    print(CGREEN +"\nStep 2: Creating subscopes: ")
    print(CGREEN +"\nStep 2a: Build Sub Scope")
    build_subscope(rc)
    print(CGREEN +"\nStep 2b: Commit scope changes")
    commit_scopes(rc)
    print(CGREEN +"\nStep 3: Upload annotation for inventories tagging: ")
    uploadAnnotation(rc)
    print(CGREEN +"\nStep 4: Create Agent Config Profile: ")
    print(CGREEN +"\nStep 4a: Create Agent Profile:")
    profile_id = Createprofile (rc)[1]
    print(CGREEN +"\nStep 4b: Create Agent Config Intent - Applying Agent Profile to Scope/Filter")
    ApplyProfile2Filter (rc, profile_id)
    print(CGREEN +"\nStep 4c: Move telemetry to Tenant VRF")
    remoteVRF(rc)
    print(CGREEN +"\nStep 5: Create Role for your scopes: ")
    print(CGREEN +"\nStep 5a: Create Role")
    CreateRole (rc)
    print(CGREEN +"\nStep 5b: Apply Role to Scope")
    role2Scope(rc)
    print(CGREEN +"\nStep 6: Create User for your scopes: ")
    CreateUser (rc)

if __name__ == "__main__":
    main()