"""
    Name: 
        AzRoleWatcher

    Author: 
        Emilien Socchi

    Description:
        AzRoleWatcher verifies if the following assets have been updated with additions and/or removals based on local snapshots:
            - MS Graph application permissions
            - Entra roles
            - Azure roles

    Requirements:
        - A service principal with the following granted application permissions:
            1. 'RoleManagement.Read.Directory' (to read Entra role definitions)
            2. 'Application.Read.All' (to read the definitions of application permissions)
        - The credentials are expected to be available to AzRoleWatcher via an environment variable with the following name and value:
            SP_CREDENTIALS_ENTRA = {"tenant_id": "__ID__", "client_id": "__ID__", "client_secret": "__SECRET__"}

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
    endpoint = 'https://graph.microsoft.com/v1.0/directoryRoleTemplates'
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
    endpoint = 'https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01'
    headers = {'Authorization': f"Bearer {token}"}
    response = requests.get(endpoint, headers = headers)

    if response.status_code != 200:
        print('FATAL ERROR - The Azure roles could not be retrieved from ARM.')
        exit()

    response_content = response.json()['value']
    return response_content


def get_builtin_from_snapshot(snapshot_file):
    """
         Retrieves the built-in roles or permissions from the passed snapshot file.

        Args:
            snapshot_file(str): the local file from which roles/permissions are to be retrieved

    """
    try:
        with open(snapshot_file) as file:
            file_content = [line.rstrip('\n') for line in file]
            return file_content
    except FileNotFoundError:
        print('FATAL ERROR - The snapshot file could not be retrieved.')
        exit()


def update_file(local_file, content):
    """
        Updates the content of the passed local file with the passed content. 

        Args:
            local_file (str): full path to the file to update
            content (str): content to update the passed file with

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
    rss_feed_last_updated = now.strftime("%a, %d %b %Y %X %z +0200")

    rss = '<rss version="2.0"><channel>'
    rss += f"<title>{rss_feed_title}</title>"
    rss += f"<description>{rss_feed_description}</description>"
    rss += f"<language>{rss_feed_language}</language>"
    rss += f"<pubDate>{rss_feed_last_updated}</pubDate>"

    for item in items:
        title = item['title']
        id = item['id']
        name = item['name']
        description = item['description']
        link = item['link']

        rss += '<item>'
        rss += f"<title>{title}</title>"
        rss += f"<description><![CDATA[<b>Id:</b> {id} <br><b>Display name:</b> {name} <br><b>Description:</b> {description} <br><b>Link:</b> {link}]]></description>"
        rss += '</item>'

    rss +="</channel></rss>"

    return rss


def request_access_token(resource, tenant_id, client_id, client_secret):
    """
        Requests an access token for the passed resource on behalf of the service principal with the passed information.

        Args:
            resource (str): the resource to authenticate to (only valid values are: 'arm', 'graph')
            tenant_id (str): the id of the service principal's home tenant
            client_id (str): the application id of the service principal
            client_secret (str): a valid secret for the service principal
        
        Returns:
            str: a valid access token for the requested resource

    """
    valid_resources = ['arm', 'graph']

    if resource not in valid_resources:
        return

    endpoint = f"https://login.microsoftonline.com/{tenant_id}"
    body = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }

    if resource == 'arm':
        endpoint += '/oauth2/token'
        body['resource'] = 'https://management.azure.com/'
    else:
        endpoint += '/oauth2/v2.0/token'
        body['scope'] = 'https://graph.microsoft.com/.default'

    response = requests.post(endpoint, body)

    if response.status_code != 200:
        print(f"FATAL ERROR - A token for {resource} could not be retrieved.")
        exit()

    access_token = response.json()['access_token']
    return access_token


if __name__ == "__main__":
    raw_sp_credentials = os.environ['SP_CREDENTIALS_ENTRA']

    if not raw_sp_credentials:
        print('FATAL ERROR - A service principal with valid access to ARM and MS Graph is required.')
        exit()

    sp_credentials = json.loads(raw_sp_credentials)
    tenant_id = sp_credentials['tenant_id']
    client_id = sp_credentials['client_id']
    client_secret = sp_credentials['client_secret']

    arm_access_token = request_access_token('arm', tenant_id, client_id, client_secret)
    graph_access_token = request_access_token('graph', tenant_id, client_id, client_secret)

    if not arm_access_token or not graph_access_token:
        print('FATAL ERROR - A valid access token for ARM and GRAPH is required.')
        exit()

    # Get current built-in roles/permissions from online documentation
    #current_builtin_msgraph_app_permissions = sorted(get_builtin_msgraph_app_permissions_from_documentation())
    #current_builtin_entra_roles = sorted(get_builtin_entra_roles_from_documentation())
    #current_builtin_azure_roles = sorted(get_builtin_azure_roles_from_documentation())
    
    # Get current built-in roles/permissions from APIs
    current_builtin_msgraph_app_permission_objects = get_builtin_msgraph_app_permission_objects_from_graph(graph_access_token)
    current_builtin_entra_role_objects = get_builtin_entra_role_objects_from_graph(graph_access_token)
    current_builtin_azure_role_objects = get_builtin_azure_role_objects_from_arm(arm_access_token)
    current_builtin_msgraph_app_permissions = sorted([permission_object['value'] for permission_object in current_builtin_msgraph_app_permission_objects])
    current_builtin_entra_roles = sorted([role_object['displayName'] for role_object in current_builtin_entra_role_objects])
    current_builtin_azure_roles = sorted([role_object['properties']['roleName'] for role_object in current_builtin_azure_role_objects])

    # Set local rss file
    github_action_dir_name = '.github'
    absolute_path_to_script = os.path.abspath(sys.argv[0])
    root_dir = absolute_path_to_script.split(github_action_dir_name)[0]
    rss_file = root_dir + 'latest.rss'

    # Set local snapshot files
    snapshot_dir = root_dir + 'snapshots'
    entra_roles_snapshot_file = f"{snapshot_dir}/entra_roles.txt"
    azure_roles_snapshot_file = f"{snapshot_dir}/azure_roles.txt"
    msgraph_app_permissions_snapshot_file = f"{snapshot_dir}/msgraph_app_permissions.txt"

    # Get snapshoted built-in roles/permissions from local files
    snapshoted_builtin_entra_roles = sorted(get_builtin_from_snapshot(entra_roles_snapshot_file))
    snapshoted_builtin_azure_roles = sorted(get_builtin_from_snapshot(azure_roles_snapshot_file))
    snapshoted_builtin_msgraph_app_permissions = sorted(get_builtin_from_snapshot(msgraph_app_permissions_snapshot_file))

    # Compare snapshoted built-in roles/permissions with those from MS Graph 
    rss_items = []

    # Compare MS Graph application permissions
    current_permissions = set(current_builtin_msgraph_app_permissions)
    snapshoted_permissions = set(snapshoted_builtin_msgraph_app_permissions)
    added_permissions= [permission for permission in current_builtin_msgraph_app_permissions if permission not in snapshoted_permissions]
    removed_permissions = [permission for permission in snapshoted_builtin_msgraph_app_permissions if permission not in current_permissions]

    if added_permissions or removed_permissions:
        print('MS Graph app permissions: changes have been detected!')

        for added_permission in added_permissions:
            msgraph_app_permission_object_list = [permission_object for permission_object in current_builtin_msgraph_app_permission_objects if permission_object['value'] == added_permission]

            if not len(msgraph_app_permission_object_list) == 1:
                print ('FATAL ERROR - Something is wrong with the addition of MS Graph app permissions.')
                exit() 

            msgraph_app_permission_object = msgraph_app_permission_object_list[0]
            title = '🆕 ADDED Graph app permission'
            link = f"https://graph.microsoft.com/v1.0/directoryRoleTemplates/{msgraph_app_permission_object['id']}"
            rss_item = {
                'title': title,
                'id': msgraph_app_permission_object['id'],
                'name': msgraph_app_permission_object['value'],
                'description': msgraph_app_permission_object['description'],
                'link': link
            }

            rss_items.append(rss_item)
  
        for removed_permission in removed_permissions:
            title = '❌ REMOVED Graph app permission'
            rss_item = {
                'title': title,
                'id': '',
                'name': removed_permission,
                'description': '',
                'link': ''
            }
            
            rss_items.append(rss_item)
    else:
        print ('MS Graph app permissions: no changes')

    # Compare Entra roles 
    current_roles = set(current_builtin_entra_roles)
    snapshoted_roles = set(snapshoted_builtin_entra_roles)
    added_roles = [role for role in current_builtin_entra_roles if role not in snapshoted_roles]
    removed_roles = [role for role in snapshoted_builtin_entra_roles if role not in current_roles]

    if added_roles or removed_roles:
        print('Entra roles: changes have been detected!')

        for added_role in added_roles:
            entra_role_object_list = [role_object for role_object in current_builtin_entra_role_objects if role_object['displayName'] == added_role]

            if not len(entra_role_object_list) == 1:
                print ('FATAL ERROR - Something is wrong with the addition of Entra roles.')
                exit() 

            entra_role_object = entra_role_object_list[0]
            title = '🆕 ADDED Entra role'
            link = f"https://graph.microsoft.com/v1.0/directoryRoleTemplates/{entra_role_object['id']}"
            rss_item = {
                'title': title,
                'id': entra_role_object['id'],
                'name': entra_role_object['displayName'],
                'description': entra_role_object['description'],
                'link': link
            }

            rss_items.append(rss_item)
  
        for removed_role in removed_roles:
            title = '❌ REMOVED Entra role'
            rss_item = {
                'title': title,
                'id': '',
                'name': removed_role,
                'description': '',
                'link': ''
            }
            
            rss_items.append(rss_item)
    else:
        print ('Entra roles: no changes')

    # Compare Azure roles 
    current_roles = set(current_builtin_azure_roles)
    snapshoted_roles = set(snapshoted_builtin_azure_roles)
    added_roles = [role for role in current_builtin_azure_roles if role not in snapshoted_roles]
    removed_roles = [role for role in snapshoted_builtin_azure_roles if role not in current_roles]

    if added_roles or removed_roles:
        print('Azure roles: changes have been detected!')

        for added_role in added_roles:
            azure_role_object_list = [role_object for role_object in current_builtin_azure_role_objects if role_object['properties']['roleName'] == added_role]

            if not len(azure_role_object_list) == 1:
                print ('FATAL ERROR - Something is wrong with the addition of Azure roles.')
                exit()

            azure_role_object = azure_role_object_list[0]
            title = '🆕 ADDED Azure role'
            link = f"https://management.azure.com{azure_role_object['id']}?api-version=2022-04-01"
            rss_item = {
                'title': title,
                'id': azure_role_object['name'],
                'name': azure_role_object['properties']['roleName'],
                'description': azure_role_object['properties']['description'],
                'link': link
            }

            rss_items.append(rss_item)
  
        for removed_role in removed_roles:
            title = '❌ REMOVED Azure role'
            rss_item = {
                'title': title,
                'id': '',
                'name': removed_role,
                'description': '',
                'link': ''
            }

            rss_items.append(rss_item) 
    else:
        print ('Azure roles: no changes')

    # Generate RSS feed and update local rss file
    rss_feed = generate_rss(rss_items)
    update_file(rss_file, rss_feed)

    # Update local snapshots with latest content from APIs
    update_file(entra_roles_snapshot_file, "\n".join(current_builtin_entra_roles))
    update_file(azure_roles_snapshot_file, "\n".join(current_builtin_azure_roles))
    update_file(msgraph_app_permissions_snapshot_file, "\n".join(current_builtin_msgraph_app_permissions))
