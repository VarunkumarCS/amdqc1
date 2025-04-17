import argparse,getpass,logging,requests,sys,warnings
from tabulate import tabulate
warnings.filterwarnings("ignore")
parser = argparse.ArgumentParser(description="Python script using Redfish API to get the Health Information of the Server")
parser.add_argument('-ips', help='Pass in iDRAC IP addresses (comma-separated)', required=True)
parser.add_argument('-u', help='Pass in iDRAC username', required=True)
parser.add_argument('-p', help='Pass in iDRAC password. If not passed in, script will prompt to enter password which will not be echoed to the screen', required=False)
parser.add_argument('--ssl', help='Verify SSL certificate for all Redfish calls, pass in "true". This argument is optional, if you do not pass in this argument, all Redfish calls will ignore SSL cert checks.', required=False)
parser.add_argument('-x', help='Pass in iDRAC X-auth token session ID to execute all Redfish calls instead of passing in username/password', required=False)
parser.add_argument('--script-examples', help='Get executing script examples', action="store_true", dest="script_examples", required=False)
parser.add_argument('--information', help='Get all health information of the server', action="store_true", required=False)
parser.add_argument('--all', help='Get all information of the server', action="store_true", required=False)
args = vars(parser.parse_args())
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)

def script_examples():
    print("""\n- python3 amdqc1.py -ips 10.2.57.101,10.2.57.102,10.2.57.103,10.2.57.104,10.2.57.105,10.2.57.106,10.2.57.107,10.2.57.108,10.2.57.109,10.2.57.110,10.2.57.111,10.2.57.112,10.2.57.113,10.2.57.114,10.2.57.115,10.2.57.116,10.2.57.117,10.2.57.118,10.2.57.119,10.2.57.120,10.2.57.121 -u root -p calvin --all, 
          this will get the information of the Servers.""")
    sys.exit(0)

def make_request(url, ip):
    headers = {'X-Auth-Token': args["x"]} if args["x"] else None
    auth = None if args["x"] else (idrac_username, idrac_password)

    response = requests.get(url, verify=verify_cert, headers=headers, auth=auth)
    return response

def check_supported_idrac_version(ip):
    response = make_request(f'https://{ip}/redfish/v1', ip)
    data = response.json()
    if response.status_code == 401:
        logging.warning(f"\n- WARNING, status code 401 detected for {ip}, check iDRAC username/password credentials")
        sys.exit(0)
    elif response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to validate iDRAC creds for {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

def information_of_server(ip):
    response = make_request(f'https://{ip}/redfish/v1/Managers/iDRAC.Embedded.1/EthernetInterfaces/NIC.1', ip)
    data = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Current-159-1.6.10__BIOS.Setup.1-1', ip)
    data1 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Current-107649-7.10__RAID.Backplane.Firmware.1', ip)
    data2 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Installed-110220-26.39.10.02__NIC.Integrated.1-1-1', ip)
    data3 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Installed-110220-26.39.10.02__NIC.Integrated.1-2-1', ip)
    data4 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Installed-27763-1.5.2__CPLD.Embedded.1', ip)
    data5 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Previous-25227-7.10.30.00__iDRAC.Embedded.1-1', ip)
    data6 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Installed-0-2.1.13.2025__BOSS.SL.10-1', ip)
    data7 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Installed-110222-26.39.10.02__NIC.Slot.6-1-1', ip)
    data8 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    response = make_request(f'https://{ip}/redfish/v1/UpdateService/FirmwareInventory/Installed-110222-26.39.10.02__NIC.Slot.6-1-1', ip)
    data9 = response.json()
    if response.status_code != 200:
        logging.warning(f"\n- WARNING, GET request failed to get the information of the server {ip}, status code {response.status_code} returned.")
        logging.warning(data)
        sys.exit(0)

    return [data['IPv4Addresses'][0]['Address'],data1['Version'],data2['Version'],data3['Version'],data4['Version'],data8['Version'],data9['Version'],data5['Version'],data6['Version'],data7['Version']]

if __name__ == "__main__":
    if args["script_examples"]:
        script_examples()

    if args["ips"] and (args["u"] or args["x"]):
        idrac_ips = args["ips"].split(',')
        idrac_username = args["u"]

        if args["p"]:
            idrac_password = args["p"]
        elif not args["p"] and not args["x"] and args["u"]:
            idrac_password = getpass.getpass(f"\n- Argument -p not detected, pass in iDRAC user {args['u']} password: ")

        verify_cert = args["ssl"].lower() == "true" if args["ssl"] else False

        table = [["IP Address","Bios","Backplane","NIC.Integrated.1-1-1","NIC.Integrated.1-2-1","NIC.Slot.6-1-1","NIC.Slot.6-2-1","CPLD","iDRAC","BOSS"]]

        for ip in idrac_ips:
            check_supported_idrac_version(ip)
            if args["information"]:
                table.append(information_of_server(ip))
            if args["all"]:
                table.append(information_of_server(ip))

        print()
        print("=================== FIRMWARE INFORMATION OF THE SERVERS ===================")
        print(tabulate(table, headers="firstrow", tablefmt="pretty"))
        print()

    else:
        logging.error("\n- FAIL, invalid argument values or not all required parameters passed in. See help text or argument --script-examples for more details.")
        sys.exit(0)