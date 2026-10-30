"""
    Name: 
        AzRoleWatcher

    Author: 
        Emilien Socchi

    Description:
        AzRoleWatcher verifies if the following assets have been updated with additions and/or removals based on local snapshots:
            - Azure roles
            - Entra roles
            - MS Graph application permissions

    Requirements:
        - A service principal with the following granted application permissions:
            1. 'RoleManagement.Read.Directory' (to read Entra role definitions)
            2. 'Application.Read.All' (to read the definitions of application permissions)
        - Valid access tokens for MS Graph and ARM are expected to be available to AzRoleWatcher via the following environment variables:
            - 'ARM_ACCESS_TOKEN'
            - 'MSGRAPH_ACCESS_TOKEN'

    Note:
        The service principal does **not** require any explicit Azure role. 
        In a tenant with a default configuration, service principals have permissions to read Azure role definitions by default.

"""
import copy
import datetime
import json
import os
import re
import requests
import sys


DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# Microsoft APIs (ARM in particular) are subject to regional replication, caching and backend rollouts,
# which can make assets temporarily disappear from responses. An asset is only reported as removed
# once it has been continuously missing for this number of days.
REMOVAL_DEBOUNCE_DAYS = 7

# ARM routes 'management.azure.com' to the nearest region, which varies with the location of the GitHub runner.
# Pinning a regional endpoint makes successive runs query the same ARM region.
ARM_PINNED_REGION = 'eastus'


def get_builtin_msgraph_app_permissions_from_documentation():
    """
        Retrieves the current built-in Microsoft Graph application permissions from Microsoft's documentation.

        Returns:
            list(str): list of built-in application permissions

    """
    documentation_uri = 'https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/main/concepts/permissions-reference.md'
    response = requests.get(documentation_uri)

    if response.status_code != 200:
        print('FATAL ERROR - The documentation could not be retrieved.')
        exit()

    response_content = response.text
    regex = r"### ([a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+)"
    builtin_roles = re.findall(regex, response_content)
    builtin_roles.sort()

    return builtin_roles


def get_builtin_entra_roles_from_documentation():
    """
        Retrieves the current built-in Entra roles from the Microsoft's documentation.

        Returns:
            list(str): list of built-in Entra roles

    """
    documentation_uri = 'https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/docs/identity/role-based-access-control/permissions-reference.md'
    response = requests.get(documentation_uri)

    if response.status_code != 200:
        print('FATAL ERROR - The documentation could not be retrieved.')
        exit()

    response_content = response.text
    regex = r"> \| \[([a-zA-Z ]+)\]"
    builtin_roles = re.findall(regex, response_content)
    builtin_roles.sort()

    return builtin_roles


def get_builtin_azure_roles_from_documentation():
    """
        Retrieves the current built-in Azure roles from the Microsoft's documentation.

        Returns:
            list(str): list of built-in Azure roles

    """
    documentation_uri = 'https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/main/articles/role-based-access-control/built-in-roles.md'
    response = requests.get(documentation_uri)

    if response.status_code != 200:
        print('FATAL ERROR - The documentation could not be retrieved.')
        exit()

    response_content = response.text
    regex = r"</a>\[([a-zA-Z ]+)"
    builtin_roles = re.findall(regex, response_content)
    builtin_roles.sort()

    return builtin_roles


def log_graph_datacenter(response, category):
    """
        Prints the MS Graph datacenter that served the passed response, for troubleshooting inconsistencies.

        Args:
            response (requests.Response): a response from MS Graph
            category (str): the category of assets retrieved with the response

        Returns:
            None

    """
    try:
        datacenter = json.loads(response.headers.get('x-ms-ags-diagnostic', '{}'))['ServerInfo']['DataCenter']
    except (ValueError, KeyError, TypeError):
        datacenter = 'unknown'

    print(f"{category}: served by MS Graph datacenter '{datacenter}' (HTTP {response.status_code})")


def get_builtin_msgraph_app_permission_objects_from_graph(token):
    """
        Retrieves the current built-in Microsoft Graph application permission objects from MS Graph.

        Args:
            str: a valid access token for MS Graph

        Returns:
            list(str): list of built-in MS Graph application permission objects

    """
    endpoint = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')"
    headers = {'Authorization': f"Bearer {token}"}
    response = requests.get(endpoint, headers = headers)
    log_graph_datacenter(response, 'MS Graph app permissions')

    if response.status_code != 200:
        print('FATAL ERROR - The MS Graph application permissions could not be retrieved from Graph.')
        exit()

    response_content = response.json()['appRoles']
    return response_content


def get_builtin_entra_role_objects_from_graph(token):
    """
        Retrieves the current built-in Entra role objects from MS Graph.

        Args:
            str: a valid access token for MS Graph

        Returns:
            list(str): list of built-in Entra-role objects

    """
    endpoint = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=isBuiltIn eq true'
    headers = {'Authorization': f"Bearer {token}"}
    response = requests.get(endpoint, headers = headers)
    log_graph_datacenter(response, 'Entra roles')

    if response.status_code != 200:
        print('FATAL ERROR - The Entra roles could not be retrieved from Graph.')
        exit()

    response_content = response.json()['value']
    return response_content


def get_builtin_azure_role_objects_from_arm(token):
    """
        Retrieves the current built-in Azure role objects from ARM.

        Args:
            str: a valid access token for ARM

        Returns:
            list(str): list of built-in Azure-role objects

    """
    endpoint_path = "/providers/Microsoft.Authorization/roleDefinitions?$filter=type+eq+'BuiltInRole'&api-version=2022-04-01"
    headers = {'Authorization': f"Bearer {token}"}
    response = None

    for base_uri in [f"https://{ARM_PINNED_REGION}.management.azure.com", 'https://management.azure.com']:
        try:
            response = requests.get(f"{base_uri}{endpoint_path}", headers = headers)
        except requests.exceptions.RequestException as error:
            print(f"WARNING - ARM request to '{base_uri}' failed: {error}")
            continue

        # The routing header has the form 'REGION:timestamp:guid'
        serving_region = response.headers.get('x-ms-routing-request-id', 'unknown').split(':')[0]
        print(f"Azure roles: served by ARM region '{serving_region}' via '{base_uri}' (HTTP {response.status_code})")

        if response.status_code == 200:
            break

    if response is None or response.status_code != 200:
        print('FATAL ERROR - The Azure roles could not be retrieved from ARM.')
        exit()

    response_content = response.json()['value']
    return response_content


def read_json_file(json_file):
    """
         Retrieves the content of the passed JSON file as a dictionary.

        Args:
            json_file(str): path to the local JSON file from which the content is to be retrieved

        Returns:
            dict(): the content of the passed JSON file
    """
    try:
        with open(json_file, 'r') as file:
            file_content = file.read()
            return json.loads(file_content)
    except FileNotFoundError:
        print('FATAL ERROR - The JSON file could not be retrieved.')
        exit()


def update_file(local_file, content):
    """
        Updates the content of the passed local file with the passed content. 

        Args:
            local_file (str): full path to the file to update
            content (str): content to update the passed file with

        Returns:
            None

    """
    try:
        with open(local_file, "w", encoding="utf-8") as file:
            file.write(content)

    except FileNotFoundError:
        print(f"FATAL ERROR - '{local_file}' could not be opened for writing.")
        exit()


def find_history_entry(history, asset_id):
    """
        Retrieves the history entry of the passed asset.

        Args:
            history (list(dict())): the history of assets
            asset_id (str): the id of the asset to look up

        Returns:
            dict(): the history entry of the asset, or None if the asset has no history

    """
    entries = [entry for entry in history if entry['id'] == asset_id]

    if not entries:
        return None

    # Legacy history files may contain duplicates: prefer the entry that is not marked as deleted
    active_entries = [entry for entry in entries if entry.get('deleted') != 'true']
    return (active_entries or entries)[-1]


def compare_assets(current_assets, snapshoted_assets, history_assets, asset_label, now):
    """
        Compares the current assets with the snapshoted ones, and updates the passed history in place.

        Removals are debounced: an asset missing from the current assets is kept in the snapshot,
        and only reported as removed once it has been continuously missing for REMOVAL_DEBOUNCE_DAYS.
        Assets reappearing after a reported removal are reported as re-added, not as new.

        Args:
            current_assets (list(dict())): the assets currently returned by Microsoft APIs
            snapshoted_assets (list(dict())): the assets from the local snapshot
            history_assets (list(dict())): the assets from the local history (updated in place)
            asset_label (str): the label of the asset type used in RSS titles (e.g. 'Azure role')
            now (datetime.datetime): the current time

        Returns:
            tuple(list(dict()), list(dict())): the new snapshot and the RSS items to publish

    """
    now_str = now.strftime(DATETIME_FORMAT)
    current_by_id = {asset['id']: asset for asset in current_assets}
    snapshoted_by_id = {asset['id']: asset for asset in snapshoted_assets}
    new_snapshot = [copy.deepcopy(asset) for asset in current_assets]
    rss_items = []

    # Additions
    for asset_id, asset in current_by_id.items():
        history_entry = find_history_entry(history_assets, asset_id)

        if history_entry is not None:
            # The asset is (back) in the API response: reset any pending removal
            history_entry.pop('missing_since', None)

        if asset_id in snapshoted_by_id:
            continue

        if history_entry is None:
            title = f"🆕 ADDED {asset_label}"
            new_history_entry = copy.deepcopy(asset)
            new_history_entry['detected'] = now_str
            new_history_entry['deleted'] = 'false'
            history_assets.append(new_history_entry)
        elif history_entry.get('deleted') == 'true':
            title = f"♻️ RE-ADDED {asset_label}"
            history_entry['deleted'] = 'false'
        else:
            # Already known and never reported as removed: do not announce it again
            continue

        rss_item = { 'title': title }
        rss_item.update(copy.deepcopy(asset))
        rss_items.append(rss_item)

    # Removals
    for asset_id, asset in snapshoted_by_id.items():
        if asset_id in current_by_id:
            continue

        history_entry = find_history_entry(history_assets, asset_id)

        if history_entry is None:
            # Asset predating the history files
            history_entry = copy.deepcopy(asset)
            history_entry['detected'] = ''
            history_entry['deleted'] = 'false'
            history_assets.append(history_entry)

        missing_since = history_entry.setdefault('missing_since', now_str)
        missing_days = (now - datetime.datetime.strptime(missing_since, DATETIME_FORMAT)).days

        if missing_days < REMOVAL_DEBOUNCE_DAYS:
            new_snapshot.append(copy.deepcopy(asset))
            continue

        history_entry.pop('missing_since', None)
        history_entry['deleted'] = 'true'

        rss_item = { 'title': f"❌ REMOVED {asset_label}" }
        rss_item.update(copy.deepcopy(asset))
        rss_items.append(rss_item)

    return new_snapshot, rss_items


def generate_rss(items):
    """
        Generates an rss-feed string with the passed items.

        Args:
            items (list(dict())): the items to be added to the rss feed

        Returns:
            str: the generated rss feed
    
    """
    rss_feed_title = 'AzRoleWatcher'
    rss_feed_description = 'Continuously monitor roles and permissions in Microsoft Entra ID and Azure.'
    rss_feed_language = 'en'
    now = datetime.datetime.now()
    rss_feed_last_updated = now.strftime("%a, %d %b %Y %X")

    rss = '<rss version="2.0"><channel>'
    rss += f"<title>{rss_feed_title}</title>"
    rss += f"<description>{rss_feed_description}</description>"
    rss += f"<language>{rss_feed_language}</language>"

    for item in items:
        title = item['title']
        id = item['id']
        name = item['name']
        description = item['description']
        link = item['link']

        rss += '<item>'
        rss += f"<title>{title}</title>"
        rss += f"<pubDate>{rss_feed_last_updated}</pubDate>"
        rss += f"<description><![CDATA[<b>Id:</b> {id} <br><b>Display name:</b> {name} <br><b>Description:</b> {description} <br><b>Link:</b> {link}]]></description>"
        rss += '</item>'

    rss +="</channel></rss>"

    return rss


if __name__ == "__main__":
    # Get ARM and MS Graph access token from environment variable
    arm_access_token = os.environ['ARM_ACCESS_TOKEN']
    graph_access_token = os.environ['MSGRAPH_ACCESS_TOKEN']

    if not graph_access_token:
        print('FATAL ERROR - A valid access token for MS Graph is required.')
        exit()

    if not arm_access_token:
        print('FATAL ERROR - A valid access token for ARM is required.')
        exit()

    # Get current built-in roles/permissions from online documentation
    #current_builtin_msgraph_app_permissions = sorted(get_builtin_msgraph_app_permissions_from_documentation())
    #current_builtin_entra_roles = sorted(get_builtin_entra_roles_from_documentation())
    #current_builtin_azure_roles = sorted(get_builtin_azure_roles_from_documentation())

    # Set Microsoft APIs info
    graph_role_template_base_uri = 'https://graph.microsoft.com/v1.0/directoryRoleTemplates/'
    arm_role_template_base_uri = 'https://management.azure.com/'
    arm_role_template_api_version = '2022-04-01'

    # Get current built-in Azure roles
    current_builtin_azure_roles = []
    current_builtin_azure_role_objects = get_builtin_azure_role_objects_from_arm(arm_access_token)

    for current_builtin_azure_role_object in current_builtin_azure_role_objects:
        current_builtin_azure_roles.append({
            'id': current_builtin_azure_role_object['name'],
            'name': current_builtin_azure_role_object['properties']['roleName'],
            'description': current_builtin_azure_role_object['properties']['description'],
            'link': f"{arm_role_template_base_uri}{current_builtin_azure_role_object['name']}?api-version={arm_role_template_api_version}"
        })

    # Get current built-in Entra roles
    current_builtin_entra_roles = []
    current_builtin_entra_role_objects = get_builtin_entra_role_objects_from_graph(graph_access_token)

    for current_builtin_entra_role_object in current_builtin_entra_role_objects:
        current_builtin_entra_roles.append({
            'id': current_builtin_entra_role_object['id'],
            'name': current_builtin_entra_role_object['displayName'],
            'description': current_builtin_entra_role_object['description'],
            'link': f"{graph_role_template_base_uri}{current_builtin_entra_role_object['id']}"
        })

    # Get current built-in MS Graph application permissions
    current_builtin_msgraph_app_permissions = []
    current_builtin_msgraph_app_permission_objects = get_builtin_msgraph_app_permission_objects_from_graph(graph_access_token)

    for current_builtin_msgraph_app_permission_object in current_builtin_msgraph_app_permission_objects:
        current_builtin_msgraph_app_permissions.append({
            'id': current_builtin_msgraph_app_permission_object['id'],
            'name': current_builtin_msgraph_app_permission_object['value'],
            'description': current_builtin_msgraph_app_permission_object['displayName'],
            'link': f"{graph_role_template_base_uri}{current_builtin_msgraph_app_permission_object['id']}"
        })
  

    # Set local rss file
    github_action_dir_name = '.github'
    absolute_path_to_script = os.path.abspath(sys.argv[0])
    root_dir = absolute_path_to_script.split(github_action_dir_name)[0]
    rss_file = root_dir + 'latest.rss'

    # Set local snapshot files
    snapshot_dir = root_dir + 'snapshots'
    entra_roles_snapshot_file = f"{snapshot_dir}/entra_roles.json"
    azure_roles_snapshot_file = f"{snapshot_dir}/azure_roles.json"
    msgraph_app_permissions_snapshot_file = f"{snapshot_dir}/msgraph_app_permissions.json"

    # Set local history files
    history_dir = root_dir + 'history'
    entra_roles_history_file = f"{history_dir}/entra_roles_history.json"
    azure_roles_history_file = f"{history_dir}/azure_roles_history.json"
    msgraph_app_permissions_history_file = f"{history_dir}/msgraph_app_permissions_history.json"

    # Get snapshoted built-in roles/permissions from local files
    snapshoted_builtin_msgraph_app_permissions = read_json_file(msgraph_app_permissions_snapshot_file)
    snapshoted_builtin_entra_roles = read_json_file(entra_roles_snapshot_file)
    snapshoted_builtin_azure_roles = read_json_file(azure_roles_snapshot_file)

    # Get historic built-in roles/permissions from local files
    history_builtin_entra_roles = read_json_file(entra_roles_history_file)
    history_builtin_azure_roles = read_json_file(azure_roles_history_file)
    history_builtin_msgraph_app_permissions = read_json_file(msgraph_app_permissions_history_file)


    # Compare snapshoted built-in roles/permissions with those from Microsoft APIs
    now = datetime.datetime.now()
    rss_items = []
    comparisons = [
        ('Azure roles', 'Azure role', current_builtin_azure_roles, snapshoted_builtin_azure_roles, history_builtin_azure_roles, azure_roles_snapshot_file),
        ('Entra roles', 'Entra role', current_builtin_entra_roles, snapshoted_builtin_entra_roles, history_builtin_entra_roles, entra_roles_snapshot_file),
        ('MS Graph app permissions', 'Graph app permission', current_builtin_msgraph_app_permissions, snapshoted_builtin_msgraph_app_permissions, history_builtin_msgraph_app_permissions, msgraph_app_permissions_snapshot_file),
    ]

    for category, asset_label, current_assets, snapshoted_assets, history_assets, snapshot_file in comparisons:
        new_snapshot, category_rss_items = compare_assets(current_assets, snapshoted_assets, history_assets, asset_label, now)
        rss_items.extend(category_rss_items)

        if category_rss_items:
            print(f"{category}: changes have been detected!")
        else:
            print(f"{category}: no changes")

        # Update local snapshot with latest content from APIs (including assets pending removal)
        update_file(snapshot_file, json.dumps(sorted(new_snapshot, key = lambda x: x['name']), indent = 4))

    # Generate RSS feed and update local rss file
    rss_feed = generate_rss(rss_items)
    update_file(rss_file, rss_feed)

    # Update local history with latest content from APIs
    update_file(azure_roles_history_file, json.dumps(sorted(history_builtin_azure_roles, key = lambda x: x['name']), indent = 4))
    update_file(entra_roles_history_file, json.dumps(sorted(history_builtin_entra_roles, key = lambda x: x['name']), indent = 4))
    update_file(msgraph_app_permissions_history_file, json.dumps(sorted(history_builtin_msgraph_app_permissions, key = lambda x: x['name']), indent = 4))
