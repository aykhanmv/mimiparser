import argparse
import os
import re
import json


def gather_files_from_folders(methodstr):
    base_path = os.path.dirname(os.path.abspath(__file__))
    all_results = []

    for folder_name in os.listdir(base_path):
        folder_path = os.path.join(base_path, folder_name)
        if os.path.isdir(folder_path) and folder_name != os.path.basename(__file__):
            for file_name in os.listdir(folder_path):
                if methodstr in file_name.lower() and file_name.endswith('.txt'):
                    file_path = os.path.join(folder_path, file_name)
                    all_results.append(file_path)
    return all_results


def logon_extract(file_path):
    results = []
    computer_name = os.path.basename(os.path.dirname(file_path))
    parent_folder_name = os.path.basename(os.path.dirname(file_path))
    source = f"{parent_folder_name}/{os.path.basename(file_path)}"

    with open(file_path, 'r') as file:
        mimikatz_output = file.read()

    user_pattern = re.compile(r"User Name\s+:\s+([^\r\n]+)")
    domain_pattern = re.compile(r"(?<!\*\s)Domain\s+:\s+([^\r\n]+)")
    sid_pattern = re.compile(r"SID\s+:\s+([^\r\n]+)")
    sid_null_pattern = re.compile(r"SID\s+:\s")
    msv_pattern = re.compile(r"msv\s+:\s")
    tspkg_pattern = re.compile(r"tspkg\s+:\s")
    wdigest_pattern = re.compile(r"wdigest\s+:\s")
    kerberos_pattern = re.compile(r"kerberos\s+:\s")
    ssp_pattern = re.compile(r"ssp\s+:\s")
    credman_pattern = re.compile(r"credman\s+:\s")
    cloudap_pattern = re.compile(r"cloudap\s+:\s")
    service_username_pattern = re.compile(r"\* Username\s+:\s+([^\r\n]+)")
    service_domain_pattern = re.compile(r"\* Domain\s+:\s+([^\r\n]+)")
    service_password_pattern = re.compile(r"\* Password\s+:\s+([^\r\n]+)")
    service_ntlm_hash_pattern = re.compile(r"\* NTLM\s+:\s+([a-fA-F0-9]{32})") 

    for line in mimikatz_output.splitlines():
        user_match = user_pattern.search(line)

        if user_match:
            results.append({
                'computer': computer_name,
                'user': user_match.group(1),
                'source': source
        })

        if domain_pattern.search(line):
            results[-1]['domain'] = domain_pattern.search(line).group(1)
        if sid_pattern.search(line):
            results[-1]['sid'] = sid_pattern.search(line).group(1)
        if sid_null_pattern.search(line) and 'sid' not in results[-1]:
            results[-1]['sid'] = None            

        if len(results) > 0:
            if ('domain' in results[-1] and 'sid' in results[-1]) and 'services' not in results[-1]:
                results[-1]['services'] = []

        if msv_pattern.search(line):
            results[-1]['services'].append({})
            results[-1]['services'][-1]['service_name'] = 'msv'
        if tspkg_pattern.search(line):
            results[-1]['services'].append({})
            results[-1]['services'][-1]['service_name'] = 'tspkg'
        if wdigest_pattern.search(line):
            results[-1]['services'].append({})
            results[-1]['services'][-1]['service_name'] = 'wdigest'
        if kerberos_pattern.search(line):
            results[-1]['services'].append({})
            results[-1]['services'][-1]['service_name'] = 'kerberos'
        if ssp_pattern.search(line):
            results[-1]['services'].append({})
            results[-1]['services'][-1]['service_name'] = 'ssp'
        if credman_pattern.search(line):
            results[-1]['services'].append({})
            results[-1]['services'][-1]['service_name'] = 'credman'
        if cloudap_pattern.search(line):
            results[-1]['services'].append({})
            results[-1]['services'][-1]['service_name'] = 'cloudap'

        if service_username_pattern.search(line):
            results[-1]['services'][-1]['username'] = service_username_pattern.search(line).group(1)
        if service_domain_pattern.search(line):
            results[-1]['services'][-1]['domain'] = service_domain_pattern.search(line).group(1)
        if service_ntlm_hash_pattern.search(line):
            results[-1]['services'][-1]['ntlm_hash'] = service_ntlm_hash_pattern.search(line).group(1)
        if service_password_pattern.search(line):
            service_password = service_password_pattern.search(line).group(1)
            if len(service_password) < 300:
                results[-1]['services'][-1]['password'] = service_password_pattern.search(line).group(1)
            else:
                results[-1]['services'][-1]['password'] = None

    return results


def logon_save(all_results):
    # replace "(null)" valuse with null
    for result in all_results:
        for key, value in result.items():
            if value == "(null)":
                result[key] = None
            for service in result['services']:
                for key, value in service.items():
                    if value == "(null)":
                        service[key] = None

    # concat 'user' and 'domain' fields into a single field: 'user'. also remove 'domain' field
    for result in all_results:
        if 'user' in result and 'domain' in result and result['user'] is not None and result['domain'] is not None:
            result['user'] = f"{result['domain']}\\{result['user']}"
        elif 'user' in result:
            result['user'] = result['user']
        elif 'domain' in result:
            result['user'] = result['domain']
        else:
            result['user'] = None
        result.pop('domain', None)

    # concat servce 'username' and 'domain' fields into a single field: 'username'. also remove 'domain' field
    for result in all_results:
        for service in result['services']:
            if 'username' in service and 'domain' in service and service['username'] is not None and service['domain'] is not None:
                service['username'] = f"{service['domain']}\\{service['username']}"
            elif 'username' in service:
                service['username'] = service['username']
            elif 'domain' in service:
                service['username'] = service['domain']
            else:
                service['username'] = None
            service.pop('domain', None)

    # remove any service that does not have at least one of the following: 'ntlm_hash', 'password'
    # value must be present and not null    
    for result in all_results:
        for service in result['services'][:]:
            if not any(service.get(key) for key in ('ntlm_hash', 'password')):
                result['services'].remove(service)

    # remove any result that does not have at least one service
    for result in all_results[:]:
        if not result['services']:
            all_results.remove(result)

    # extract collect creds from the json
    # new format: computer, user, sid, username, cred (ntlm or password)
    collect_creds = []
    for result in all_results:
        for service in result['services']:
            collect_creds.append({
                'computer': result['computer'],
                'user': result['user'],
                'sid': result['sid'],
                'username': service['username'],
                'ntlm/plaintext password': service.get('ntlm_hash') or service.get('password'),
                'source': result['source']
            })

        # remove entries with sid or username as None directly
    for i in range(len(collect_creds) - 1, -1, -1):
        if collect_creds[i]['sid'] is None or collect_creds[i]['username'] is None:
            collect_creds.pop(i)

    # remove duplicate and unnecessary entries
    for i in range(len(collect_creds) - 1, -1, -1):
        if collect_creds[i] in collect_creds[:i]:
            collect_creds.pop(i)

    patterns = ["Window Manager", "Font Driver Host"]
    for i in range(len(collect_creds) - 1, -1, -1):
        if any(pattern in collect_creds[i]['user'] for pattern in patterns):
            collect_creds.pop(i)

    # saving the results to a json file
    if collect_creds:
        with open('logon.json', 'w') as file:
            json.dump(collect_creds, file, indent=4)
    else:
        print("No Logon credentials found. 'logon.json' was not created.")


def sam_extract(file_path):
    results = []
    computer_name = os.path.basename(os.path.dirname(file_path))
    parent_folder_name = os.path.basename(os.path.dirname(file_path))
    source = f"{parent_folder_name}/{os.path.basename(file_path)}"

    with open(file_path, 'r') as file:
        mimikatz_output = file.read()

    user_pattern = re.compile(r"User\s+:\s+([^\r\n]+)")
    ntlm_hash_pattern = re.compile(r"Hash NTLM:\s+([a-fA-F0-9]{32})")

    for line in mimikatz_output.splitlines():
        if user_pattern.search(line):
            user_match = user_pattern.search(line)
            results.append({
                'computer': computer_name,
                'user': user_match.group(1)
        })

        if ntlm_hash_pattern.search(line):
            results[-1]['ntlm'] = ntlm_hash_pattern.search(line).group(1)
            results[-1]['source'] = source

    return results


def sam_save(all_results):
    # remove entires with no cred
    all_results = [i for i in all_results if 'ntlm' in i]

    # remove duplicate entries
    # an entry is duplcate if it has the same: computer + user + ntlm hash
    seen = set()
    i = 0
    while i < len(all_results):
        identifier = (all_results[i]['computer'], all_results[i]['user'], all_results[i]['ntlm'])
        if identifier in seen:
            del all_results[i]
        else:
            seen.add(identifier)
            i += 1

    # saving the results to a json file
    if all_results:
        with open('sam.json', 'w') as file:
            json.dump(all_results, file, indent=4)
    else:
        print("No SAM credentials found. 'sam.json' was not created.")


def dcc_extract(file_path):
    results = []
    computer_name = os.path.basename(os.path.dirname(file_path))
    parent_folder_name = os.path.basename(os.path.dirname(file_path))
    source = f"{parent_folder_name}/{os.path.basename(file_path)}"

    with open(file_path, 'r') as file:
        mimikatz_output = file.read()

    user_pattern = re.compile(r"User\s+:\s+([^\r\n]+)")
    dcc_pattern = re.compile(r"MsCacheV2\s:\s+([a-fA-F0-9]{32})")

    for line in mimikatz_output.splitlines():
        if user_pattern.search(line):
            user_match = user_pattern.search(line)
            results.append({
                'computer': computer_name,
                'user': user_match.group(1)
        })

        if dcc_pattern.search(line):
            results[-1]['dcc'] = dcc_pattern.search(line).group(1)
            crack_dcc = f'$DCC2$10240#{results[-1]["user"]}#{results[-1]["dcc"]}'
            results[-1]['dcc crack format'] = crack_dcc
            results[-1]['source'] = source

    return results


def dcc_save(all_results):
    # saving the results to a json file
    if all_results:
        with open('dcc.json', 'w') as file:
            json.dump(all_results, file, indent=4)
    else:
        print("No DCC credentials found. 'dcc.json' was not created.")


def ekey_extract(file_path):
    results = []
    computer_name = os.path.basename(os.path.dirname(file_path))
    parent_folder_name = os.path.basename(os.path.dirname(file_path))
    source = f"{parent_folder_name}/{os.path.basename(file_path)}"

    with open(file_path, 'r') as file:
        mimikatz_output = file.read()

    user_pattern = re.compile(r"User Name\s+:\s+([^\r\n]+)")
    username_pattern = re.compile(r"\* Username\s+:\s+([^\r\n]+)")
    domain_pattern = re.compile(r"(?<!\*\s)Domain\s+:\s+([^\r\n]+)")
    sid_pattern = re.compile(r"SID\s+:\s+([^\r\n]+)")
    sid_null_pattern = re.compile(r"SID\s+:\s")
    ekey_pattern = re.compile(r"des_cbc_md4\s+([a-fA-F0-9]{64})") 
    aes256_hmac_pattern = re.compile(r"aes256_hmac\s+([a-fA-F0-9]{64})")

    for line in mimikatz_output.splitlines():
        user_match = user_pattern.search(line)

        if user_match:
            results.append({
                'computer': computer_name,
                'source': source
        })

        if username_pattern.search(line):
            results[-1]['username'] = username_pattern.search(line).group(1)    
        if domain_pattern.search(line):
            results[-1]['domain'] = domain_pattern.search(line).group(1)
        if sid_pattern.search(line):
            results[-1]['sid'] = sid_pattern.search(line).group(1)
        if sid_null_pattern.search(line) and 'sid' not in results[-1]:
            results[-1]['sid'] = None        
        if ekey_pattern.search(line):
            results[-1]['ekey'] = ekey_pattern.search(line).group(1)
        if aes256_hmac_pattern.search(line):
            results[-1]['ekey'] = aes256_hmac_pattern.search(line).group(1)
            
    return results


def ekey_save(all_results):
    # remove entries that don't have an ekey
    all_results = [result for result in all_results if 'ekey' in result]

    # concat "username" and "domain" into "username"
    for result in all_results:
        if 'domain' in result:
            result['username'] = f"{result['domain']}\\{result['username']}"
        else:
            result['username'] = f"{result['username']}"
        del result['domain']

    # remove duplicate and unnecessary entries
    for i in range(len(all_results) - 1, -1, -1):
        if all_results[i] in all_results[:i]:
            all_results.pop(i)

    patterns = ["Window Manager", "Font Driver Host"]
    for i in range(len(all_results) - 1, -1, -1):
        if any(pattern in all_results[i]['username'] for pattern in patterns):
            all_results.pop(i)

    # change order of keys and values for each entry: computer, username, sid, ekey, source
    order = ["computer", "username", "sid", "ekey", "source"]
    for entry in all_results:
        reordered_entry = {key: entry[key] for key in order if key in entry}
        entry.clear()
        entry.update(reordered_entry)

    # saving the results to a json file
    if all_results:
        with open('ekey.json', 'w') as file:
            json.dump(all_results, file, indent=4)
    else:
        print("No Ekey credentials found. 'ekey.json' was not created.")


def generate_html_table(data, docname):
    style = """
    <style>
        * {
            margin: 0;
            padding: 0;
            font-family: Verdana, Geneva, Tahoma, sans-serif;
        }
        table {
            border-collapse: collapse;
            width: 95%;
            margin: 20px 0;
            font-size: 16px;
            text-align: left;
            margin-left: auto;
            margin-right: auto;
        }
        th, td {
            border: 1px solid #dddddd;
            padding: 8px;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        h2 {
            margin: 50px auto 0px auto;
            width: 95%;
        }
    </style>
    """
    html = f'<a href=./{docname.lower()}.html ><h2>{docname}</h2></a>\n<table>\n'
    html += '  <tr>\n'
    for key in data[0].keys():
        html += f'    <th>{key.upper()}</th>\n'
    html += '  </tr>\n'
    
    for entry in data:
        html += '  <tr>\n'
        for value in entry.values():
            html += f'    <td>{value}</td>\n'
        html += '  </tr>\n'
    
    html += '</table>\n'
    return html, style


def web_gen():
    current_dir = os.path.dirname(os.path.realpath(__file__))

    desired_order = ["sam.json", "logon.json", "dcc.json", "ekey.json"]
    all_html_tables = []
    style = ""
    valid_data_found = False

    for filename in desired_order:
        json_file_path = os.path.join(current_dir, filename)
        if os.path.exists(json_file_path):
            with open(json_file_path, 'r') as file:
                try:
                    data = json.load(file)
                    if not data:
                        continue
                except json.JSONDecodeError:
                    continue
                
            valid_data_found = True

            docname = filename.split('.')[0].capitalize()
            html_table, style = generate_html_table(data, docname)
            all_html_tables.append(html_table)

            html_file_name = f"{os.path.splitext(filename)[0]}.html"
            html_file_path = os.path.join(current_dir, html_file_name)
            
            with open(html_file_path, 'w') as file:
                file.write(f"<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
                           f"<meta charset='UTF-8'>\n<title>{docname}</title>\n"
                           f"{style}</head>\n<body>\n{html_table}</body>\n</html>")

    # only generate index.html if valid data is found
    if valid_data_found:
        index_html = "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n<title>Index</title>\n"
        index_html += style + "</head>\n<body>\n"
        index_html += "\n".join(all_html_tables)
        index_html += "</body>\n</html>"

        index_file_path = os.path.join(current_dir, "index.html")
        with open(index_file_path, 'w') as file:
            file.write(index_html)
    else:
        print("No valid data found in the JSON files. 'index.html' was not created.")



def main():
    parser = argparse.ArgumentParser(
        description='Parse Mimikatz output files and generate HTML files from JSON files'
    )
    parser.add_argument('--logon', '-l', action='store_true', help='Parse Logon')
    parser.add_argument('--web', '-w', action='store_true', help='Generate HTML file from JSON files')
    parser.add_argument('--sam', '-s', action='store_true', help='Parse SAM')
    parser.add_argument('--dcc', '-d', action='store_true', help='Parse DCC')
    parser.add_argument('--ekey', '-e', action='store_true', help='Parse Ekey')

    args = parser.parse_args()

    # if no arguments are provided, display help
    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.logon:
        files = gather_files_from_folders("logon")
        all_results = []
        for file_path in files:
            results = logon_extract(file_path)
            all_results.extend(results)
        logon_save(all_results)

    if args.sam:
        files = gather_files_from_folders("sam")
        all_results = []
        for file_path in files:
            results = sam_extract(file_path)
            all_results.extend(results)
        sam_save(all_results)

    if args.dcc:
        files = gather_files_from_folders("dcc")
        all_results = []
        for file_path in files:
            results = dcc_extract(file_path)
            all_results.extend(results)
        dcc_save(all_results)

    if args.ekey:
        files = gather_files_from_folders("ekey")
        all_results = []
        for file_path in files:
            results = ekey_extract(file_path)
            all_results.extend(results)
        ekey_save(all_results)

    if args.web:
        web_gen()
        
if __name__ == '__main__':
    main()