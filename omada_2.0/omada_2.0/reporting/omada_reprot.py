from omada.omada_api import Omada
import json
import yaml
import gc
import html
import re
from datetime import datetime


def getTimeData():
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]  # remove last 3 digits to get milliseconds

##########################################################
def getConfig(config_file):
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            return  yaml.safe_load(f)
    except:
        print(f"{getTimeData()} Omada Report Config {config_file} file error")
        return {}
    
def getAPIconfig(api_config_file):
    try:
        with open(api_config_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"{getTimeData()} Omada Report Config {api_config_file} file error: {e}")
        return {}
###########################################################

def resolve_omada_placeholders(data, omada_obj):
 
    pattern = re.compile(r"omada\.(\w+)")
    if isinstance(data, dict):
        return {k: resolve_omada_placeholders(v, omada_obj) for k, v in data.items()}
    elif isinstance(data, list):
        return [resolve_omada_placeholders(item, omada_obj) for item in data]
    elif isinstance(data, str):
        match = pattern.fullmatch(data)
        if match:
            attr_name = match.group(1)
            return getattr(omada_obj, attr_name, data)
    return data

################################ HTML +++++++++++++++++++++++++++++++++++++++

import html

def json_to_html_table(data, mapping=None):
    """
    Converts JSON (list of dicts or single dict) into an HTML table.
    Automatically handles nested dictionaries and lists by creating sub-tables.
    """

    # --- Configuration & Styles ---
    TABLE_STYLE = (
        "border-collapse: collapse; "
        "margin: 4px; "
        "font-family: Arial, sans-serif; "
        "font-size: 13px; "
        "width: auto;"
    )

    HEADER_STYLE = (
        "background-color: #003366; "
        "color: white; "
        "padding: 8px; "
        "border: 1px solid #444; "
        "text-align: left; "
        "white-space: nowrap;"
    )

    CELL_STYLE = (
        "padding: 8px; "
        "border: 1px solid #ccc; "
        "color: #333; "
        "vertical-align: top;" # Crucial for aligning IDs with nested tables
    )

    ROW_COLORS = ["#ffffff", "#f9f9f9"]

    # --- Internal Helper Functions ---
    def unwrap_data(input_obj):
        """Dives into 'data', 'results', or 'test' keys if they wrap the main list."""
        wrapper_keys = ["data", "test", "results"]
        temp = input_obj
        while isinstance(temp, dict):
            found_key = next((k for k in wrapper_keys if k in temp), None)
            if found_key:
                temp = temp[found_key]
            else:
                break
        return temp

    def render_value(value):
        """Decides how to render a cell: as a sub-table, a list, or text."""
        # CASE 1: It's a single dictionary (like clientNode)
        # We wrap it in a list [value] so json_to_html_table can process it as a row
        if isinstance(value, dict):
            return json_to_html_table([value]) 

        # CASE 2: It's a list of dictionaries (like apChannelDetailList)
        elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
            return json_to_html_table(value)

        # CASE 3: It's a simple list of strings/numbers
        elif isinstance(value, list):
            return ", ".join(map(str, value)) if value else "&nbsp;"

        # CASE 4: Standard values (Strings, Bools, Ints)
        if value is None: return "&nbsp;"
        return html.escape(str(value))

    # --- Processing Logic ---
    
    # 1. Standardize input: Unwrap wrappers and ensure it's a list
    processed_data = unwrap_data(data)
    if isinstance(processed_data, dict):
        processed_data = [processed_data]
    elif not isinstance(processed_data, list):
        processed_data = []

    if not processed_data:
        return ""

    # 2. Determine Columns (Keys)
    if mapping:
        # Show only keys that are in the mapping AND present in the data
        all_data_keys = {k for row in processed_data for k in row.keys()}
        keys = [k for k in mapping.keys() if k in all_data_keys]
        
        # Filter rows: Remove rows that don't have ANY of our mapped keys
        processed_data = [row for row in processed_data if any(k in row for k in keys)]
    else:
        # Auto-detect all unique keys in the list
        keys = sorted({k for row in processed_data for k in row.keys()})

    if not processed_data:
        return ""

    # --- HTML Building ---
    output = [f"<table style='{TABLE_STYLE}'>"]
    
    # Header
    output.append("  <tr>")
    for key in keys:
        display_name = mapping.get(key, key) if mapping else key
        output.append(f"    <th style='{HEADER_STYLE}'>{display_name}</th>")
    output.append("  </tr>")

    # Body
    for i, row in enumerate(processed_data):
        bg = ROW_COLORS[i % 2]
        output.append(f"  <tr style='background-color: {bg};'>")
        for key in keys:
            val = row.get(key, None)
            # Recursively render the value
            rendered = render_value(val)
            output.append(f"    <td style='{CELL_STYLE}'>{rendered}</td>")
        output.append("  </tr>")

    output.append("</table>")
    return "\n".join(output)

# # #############################################################################

def main(config_file, api_config_file):
    try:

        valid_keys = ["headers", "json", "params", "timeout", "data", "payload"]

        config = getConfig(config_file)
        api_config = getAPIconfig(api_config_file)
        arguments = api_config.get("arguments")

        api =  api_config.get("api")
        api = api.replace("omadacId","omada.omadacId").replace("siteId","omada.siteId")

        for k,v in list(arguments.items()):
            if k in valid_keys: continue
            api = api.replace(k,v)
            arguments.pop(k,None)

        omada = Omada(**config)
        omada._logger.info("[ MG Omada Reports ]")
        api = api.format(omada=omada)

        if  debug:
            omada._logger.info(f"{omada.baseurl}{api}")

        mod = omada.mod[api_config.get("mod")]
        args = api_config.get("arguments", {})

        kwargs = {}

        for key in valid_keys:
            value = args.get(key)
            if value:
                # If it's a dictionary (like headers), resolve placeholders
                if isinstance(value, dict):
                    kwargs[key] = resolve_omada_placeholders(value, omada)
                else:
                    kwargs[key] = value

        if debug:
            omada._logger.info(f"Arguments: {kwargs}")

        try:
            # This is where it currently crashes
            result = omada.Command(mod, api, **kwargs)
        except Exception as api_err:
            omada._logger.error(f"API Command Failed: {api_err}")
            result = {"errorCode": -1, "msg": str(api_err), "result": {}}

        if debug:    
            omada._logger.info(result)

        if api_config.get("mapping"):
            mapping = api_config.get("mapping")
        else:
            mapping = None

        nested_key = next((k for k in ["data", "test", "results"] if k in result), None)

        if nested_key:
            result = result[nested_key]

        html = json_to_html_table(result,mapping=mapping)

        omada._logger.info("[ MG Omada Reports end]")
        omada.Logout()
       
        with open(api_config.get("report_output"), "w", encoding="utf-8") as f:
            f.write(html)
        gc.collect()

    except Exception as e:
        omada._logger.error(f"Critical error: {e}")

if __name__ == "__main__":
    debug = False
    path = "/opt/LMG-local-services/omada_2.0/reporting"
    config_file = f"{path}/config.yaml"
    #api_config_file = f"{path}/report_config-01.yaml"
    api_config_file = f"{path}/report_config-07.yaml"
    main(config_file, api_config_file)
