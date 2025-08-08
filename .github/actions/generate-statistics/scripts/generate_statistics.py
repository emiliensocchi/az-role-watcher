"""
    Name:
        generate-statistics

    Author:
        Emilien Socchi
        
    Description:
        generate-statistics generates statistics about Azure roles, Entra roles, and MS Graph app permissions from historical data.
        It creates a Markdown table summarizing the number of roles added and removed each year.

    Requirements:
        None

"""
import datetime
import json
import os
import sys


def get_occurences_per_year(local_file):
    """
    Get occurrences of detected roles per year from a local JSON file.

    Args:
        local_file (str): Path to the local JSON file containing role history.
        
    Returns:
        dict: A dictionary with years as keys and a count of added and removed roles as values.

    """
    occurrences_per_year = {}

    with open(local_file, 'r', encoding = 'utf-8') as file:
        data = json.load(file)

        for d in data:
            detected = d.get('detected', '')
            deleted = d.get('deleted', 'false')

            if detected:
                year = datetime.datetime.strptime(detected, "%Y-%m-%dT%H:%M:%SZ").year

                if year not in occurrences_per_year:
                    occurrences_per_year[year] = {'added': 0, 'removed': 0}

                if deleted == "true":
                    occurrences_per_year[year]['removed'] += 1
                else:
                    occurrences_per_year[year]['added'] += 1

    return occurrences_per_year


def stats_to_markdown_table(stats_dict):
    """
        Convert statistics dictionary to a Markdown table format.

        Args:
            stats_dict (dict): Dictionary containing statistics with years as keys and counts of added/removed roles.

        Returns:
            str: Markdown formatted table as a string.

    """
    all_years = set()

    for stat in stats_dict.values():
        all_years.update(stat.keys())

    years = sorted(all_years, reverse = True)
    categories = [
        ("Azure Roles", "☁️ Azure roles"),
        ("Entra Roles", "👤 Entra roles"),
        ("MS Graph App Permissions", "🤖 MS Graph app permissions"),
    ]
    table_blocks = []

    for year in years:
        header = f"### {year}\n\n| 🏷️ Category | ➕ Added | ❌ Removed |\n|----------|-------|---------|"
        rows = []

        for key, label in categories:
            added = stats_dict.get(key, {}).get(year, {}).get("added", 0)
            removed = stats_dict.get(key, {}).get(year, {}).get("removed", 0)
            # Color: green for added>0, red for removed>0, black for 0
            if added > 0:
                added_str = f'<span style="color:#009E73;font-weight:bold">{added}</span>'
            else:
                added_str = f'{added}'
            if removed > 0:
                removed_str = f'<span style="color:#D55E00;font-weight:bold">{removed}</span>'
            else:
                removed_str = f'{removed}'
            rows.append(f"| {label} | {added_str} | {removed_str} |")

        table_blocks.append(header + "\n" + "\n".join(rows) + "\n")

    return "\n".join(table_blocks)


def stats_to_markdown_table_current_year(stats_dict):
    """
        Convert statistics dictionary to a Markdown table format for the current year only.

        Args:
            stats_dict (dict): Dictionary containing statistics with years as keys and counts of added/removed roles.

        Returns:
            str: Markdown formatted table as a string for the current year.

    """
    current_year = datetime.datetime.now().year
    current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    categories = [
        ("Azure Roles", "☁️ Azure roles"),
        ("Entra Roles", "👤 Entra roles"),
        ("MS Graph App Permissions", "🤖 MS Graph app permissions"),
    ]
    header = f"### 🔔 Detected changes this year ({current_year}) \n\n> last updated: {current_time} \n\n| 🏷️ Category | ➕ Added | ❌ Removed |\n|----------|-------|---------|"
    rows = []

    for key, label in categories:
        added = stats_dict.get(key, {}).get(current_year, {}).get("added", 0)
        removed = stats_dict.get(key, {}).get(current_year, {}).get("removed", 0)

        if added > 0:
            added_str = f'<span style="color:#009E73;font-weight:bold">{added}</span>'
        else:
            added_str = f'{added}'
        if removed > 0:
            removed_str = f'<span style="color:#D55E00;font-weight:bold">{removed}</span>'
        else:
            removed_str = f'{removed}'

        rows.append(f"| {label} | {added_str} | {removed_str} |")

    return header + "\n" + "\n".join(rows) + "\n"


def update_readme(readme_path, table_md):
    """
        Update the README file with a Markdown table of role statistics.
        
        Args:
            readme_path (str): Path to the README file.
            table_md (str): Markdown formatted table string to insert.

        Returns:
            None

    """
    new_content = ''

    with open(readme_path, 'r', encoding = 'utf-8') as file:
        file_content = file.read()
        splitted_content = file_content.split('##')
        intro = splitted_content[0]
        new_content = intro + table_md + '\n\n##' + "##".join(splitted_content[2:])

    with open(readme_path, 'w', encoding = 'utf-8') as file:
        file.write(new_content)


def update_history(history_path, table_md):
    """
        Update the README file with a Markdown table of role statistics.
        
        Args:
            history_path (str): Path to the history file.
            table_md (str): Markdown formatted table string to insert.

        Returns:
            None

    """
    new_content = ''

    with open(history_path, 'r', encoding = 'utf-8') as file:
        file_content = file.read()
        splitted_content = file_content.split('###')
        intro = splitted_content[0]
        new_content = intro + table_md

    with open(history_path, 'w', encoding = 'utf-8') as file:
        file.write(new_content)


if __name__ == "__main__":
    github_action_dir_name = '.github'
    absolute_path_to_script = os.path.abspath(sys.argv[0])
    root_dir = absolute_path_to_script.split(github_action_dir_name)[0]
    history_dir = os.path.join(root_dir, 'history')
    readme_file = os.path.join(root_dir, 'README.md')
    history_file = os.path.join(history_dir, 'History.md')
    history_files = {
        "Azure Roles": os.path.join(history_dir, "azure_roles_history.json"),
        "Entra Roles": os.path.join(history_dir, "entra_roles_history.json"),
        "MS Graph App Permissions": os.path.join(history_dir, "msgraph_app_permissions_history.json"),
    }

    stats = {name: get_occurences_per_year(path) for name, path in history_files.items() if os.path.exists(path)}
    table_md_current_year = stats_to_markdown_table_current_year(stats)
    table_md = stats_to_markdown_table(stats)
    update_readme(readme_file, table_md_current_year)
    update_history(history_file, table_md)
