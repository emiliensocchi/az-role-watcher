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
import datetime
import json
import os
import re
import requests
import sys


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
    endpoint = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?$filter=type+eq+'BuiltInRole'&api-version=2022-04-01"
    headers = {'Authorization': f"Bearer {token}"}
    response = requests.get(endpoint, headers = headers)

    if response.status_code != 200:
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
        with open(local_file, "w") as file:
            file.write(content)

    except FileNotFoundError:
        print(f"FATAL ERROR - '{local_file}' could not be opened for writing.")
        exit()


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


    # Compare snapshoted built-in roles/permissions with those from MS Graph 
    rss_items = []

    # Compare Azure roles
    current_builtin_azure_roles_sorted = sorted(current_builtin_azure_roles, key=lambda x: x['id'])
    snapshoted_builtin_azure_roles_sorted = sorted(snapshoted_builtin_azure_roles, key=lambda x: x['id'])

    current_role_ids = [role['id'] for role in current_builtin_azure_roles_sorted]
    snapshoted_role_ids = [role['id'] for role in snapshoted_builtin_azure_roles_sorted]
    added_role_ids = [role_id for role_id in current_role_ids if role_id not in snapshoted_role_ids]
    removed_role_ids = [role_id for role_id in snapshoted_role_ids if role_id not in current_role_ids]

    if added_role_ids or removed_role_ids:
        print('Azure roles: changes have been detected!')

        for added_role_id in added_role_ids:
            azure_role_list = [role for role in current_builtin_azure_roles_sorted if role['id'] == added_role_id]
            history_role_list = [role for role in history_builtin_azure_roles if role['id'] == added_role_id]

            if not len(azure_role_list) == 1:
                print ('FATAL ERROR - Something is wrong with the addition of Azure roles.')
                exit()

            # Add to RSS feed
            azure_role = azure_role_list[0]
            title = '🆕 ADDED Azure role'
            rss_item = { 'title': title }
            rss_item.update(azure_role)
            rss_items.append(rss_item)

            # Add to history
            history_role_list = [role for role in history_builtin_azure_roles if role['id'] == added_role_id]
            if not history_role_list:
                azure_role['detected'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                azure_role['deleted'] = 'false'               
                history_builtin_azure_roles.append(azure_role)

        for removed_role_id in removed_role_ids:
            azure_role_list = [role for role in snapshoted_builtin_azure_roles_sorted if role['id'] == removed_role_id]
            history_role_list = [role for role in history_builtin_azure_roles if role['id'] == removed_role_id]

            if not len(azure_role_list) == 1:
                print ('FATAL ERROR - Something is wrong with the removal of Azure roles.')
                exit()

            if len(history_role_list) == 1:
                # The ARM API is subject to regional replication, caching, and backend updates that can cause temporary inconsistencies
                # Check if the role was added recently
                history_role = history_role_list[0]
                threshold_days = 7
                if (datetime.datetime.now() - datetime.datetime.strptime(history_role['detected'], "%Y-%m-%dT%H:%M:%SZ")).days < threshold_days:
                    # The role was added for less than a week ago, skip its removal for now
                    history_role.pop('detected', None)
                    history_role.pop('deleted', None) 
                    current_builtin_azure_roles.append(history_role)
                    continue

            # Add to RSS feed
            azure_role = azure_role_list[0]
            title = '❌ REMOVED Azure role'
            rss_item = { 'title': title }
            rss_item.update(azure_role)
            rss_items.append(rss_item)

            # Add to history
            history_role = history_role_list[0]
            history_builtin_azure_roles.remove(history_role)
            history_role['deleted'] = 'true'
            history_builtin_azure_roles.append(history_role)
    else:
        print ('Azure roles: no changes')


    # Compare Entra roles 
    current_role_ids = [role['id'] for role in current_builtin_entra_roles]
    snapshoted_role_ids = [role['id'] for role in snapshoted_builtin_entra_roles]
    added_role_ids = [role_id for role_id in current_role_ids if role_id not in snapshoted_role_ids]
    removed_role_ids = [role_id for role_id in snapshoted_role_ids if role_id not in current_role_ids]

    if added_role_ids or removed_role_ids:
        print('Entra roles: changes have been detected!')

        for added_role_id in added_role_ids:
            entra_role_list = [role for role in current_builtin_entra_roles if role['id'] == added_role_id]

            if not len(entra_role_list) == 1:
                print ('FATAL ERROR - Something is wrong with the addition of Entra roles.')
                exit() 

            # Add to RSS feed
            entra_role = entra_role_list[0]
            title = '🆕 ADDED Entra role'
            rss_item = { 'title': title }
            rss_item.update(entra_role)         
            rss_items.append(rss_item)

            # Add to history
            entra_role['detected'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            entra_role['deleted'] = 'false'               
            history_builtin_azure_roles.append(entra_role)

        for removed_role_id in removed_role_ids:
            entra_role_list = [role for role in snapshoted_builtin_entra_roles if role['id'] == added_role_id]
            history_role_list = [role for role in history_builtin_entra_roles if role['id'] == added_role_id]

            if not len(entra_role_list) == 1 or not len(history_role) == 1:
                print ('FATAL ERROR - Something is wrong with the addition of Entra roles.')
                exit() 

            # Add to RSS feed
            entra_role = entra_role_list[0]
            title = '❌ REMOVED Entra role'
            rss_item = { 'title': title }
            rss_item.update(entra_role)         
            rss_items.append(rss_item)

            # Add to history
            history_role = history_role_list[0]
            history_builtin_entra_roles.remove(history_role)
            history_role['deleted'] = 'true'
            history_builtin_entra_roles.append(history_role)
    else:
        print ('Entra roles: no changes')


    # Compare MS Graph application permissions
    current_permission_ids = [permission['id'] for permission in current_builtin_msgraph_app_permissions]
    snapshoted_permission_ids = [permission['id'] for permission in snapshoted_builtin_msgraph_app_permissions]
    added_permission_ids = [permission_id for permission_id in current_permission_ids if permission_id not in snapshoted_permission_ids]
    removed_permission_ids = [permission_id for permission_id in snapshoted_permission_ids if permission_id not in current_permission_ids]

    if added_permission_ids or removed_permission_ids:
        print('MS Graph app permissions: changes have been detected!')

        for added_permission_id in added_permission_ids:
            msgraph_app_permissions_list = [permission for permission in current_builtin_msgraph_app_permissions if permission['id'] == added_permission_id]

            if not len(msgraph_app_permissions_list) == 1:
                print ('FATAL ERROR - Something is wrong with the addition of MS Graph app permissions.')
                exit() 

            # Add to RSS feed
            msgraph_app_permission = msgraph_app_permissions_list[0]
            title = '🆕 ADDED Graph app permission'
            rss_item = { 'title': title }
            rss_item.update(msgraph_app_permission)
            rss_items.append(rss_item)

            # Add to history
            msgraph_app_permission['detected'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            msgraph_app_permission['deleted'] = 'false'               
            history_builtin_azure_roles.append(msgraph_app_permission)

        for removed_permission_id in removed_permission_ids:
            msgraph_app_permissions_list = [permission for permission in snapshoted_builtin_msgraph_app_permissions if permission['id'] == removed_permission_id]
            history_permission_list = [permission for permission in history_builtin_msgraph_app_permissions if permission['id'] == removed_permission_id]

            if not len(msgraph_app_permissions_list) == 1 or not len(history_permission_list) == 1:
                print ('FATAL ERROR - Something is wrong with the removal of MS Graph app permissions.')
                exit() 

            # Add to RSS feed
            msgraph_app_permission = msgraph_app_permissions_list[0]
            title = '❌ REMOVED Graph app permission'
            rss_item = { 'title': title }
            rss_item.update(msgraph_app_permission)         
            rss_items.append(rss_item)

            # Add to history
            history_permission = history_permission_list[0]
            history_builtin_msgraph_app_permissions.remove(history_permission)
            history_permission['deleted'] = 'true'
            history_builtin_msgraph_app_permissions.append(history_permission)
    else:
        print ('MS Graph app permissions: no changes')


    # Generate RSS feed and update local rss file
    rss_feed = generate_rss(rss_items)
    update_file(rss_file, rss_feed)

    # Update local snapshots with latest content from APIs
    update_file(azure_roles_snapshot_file, json.dumps(sorted(current_builtin_azure_roles, key = lambda x: x['name']), indent = 4))
    update_file(entra_roles_snapshot_file, json.dumps(sorted(current_builtin_entra_roles, key = lambda x: x['name']), indent = 4))
    update_file(msgraph_app_permissions_snapshot_file, json.dumps(sorted(current_builtin_msgraph_app_permissions, key = lambda x: x['name']), indent = 4))

    # Update local history with latest content from APIs
    update_file(azure_roles_history_file, json.dumps(sorted(history_builtin_azure_roles, key = lambda x: x['name']), indent = 4))
    update_file(entra_roles_history_file, json.dumps(sorted(history_builtin_entra_roles, key = lambda x: x['name']), indent = 4))
    update_file(msgraph_app_permissions_history_file, json.dumps(sorted(history_builtin_msgraph_app_permissions, key = lambda x: x['name']), indent = 4))
