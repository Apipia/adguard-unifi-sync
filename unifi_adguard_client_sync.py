#!/usr/bin/env python3
"""
Unifi Adguard Client Sync - This will update Adguard Home with all active client information from Unifi OS.
Using a MAC Address as a primary identifier, this script will sync the IP Addresses and Names, so they
reflect what is in Unifi OS.

usage: unifi_adguard_client_sync.py [-h]
                                    unifi_url unifi_username adguard_url
                                    adguard_username

Expected Environment Variables:
    -   UNIFI_PW:       Password for Unifi user
    -   ADGUARD_PW:     Password for AdGuard user
"""
__author__ = "Anthony Pipia"
__maintainer__ = "Anthony Pipia"
__version__ = 0.1

import os
import requests
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("unifi_url", help="URL of Unifi Server")
    parser.add_argument("unifi_username", help="Username of Unifi user.")
    parser.add_argument("adguard_url", help="URL of AdGuard Server")
    parser.add_argument("adguard_username", help="Username of AdGuard user.")
    parser.add_help = True
    parser.description = "Syncs the active client data in Unifi OS with Client records in AdGuard. " \
                         "Please supply the passwords as environment variables (UNIFI_PW, ADGUARD_PW)."
    args = parser.parse_args()
    return args


def unifi_login(s: requests.Session, arguments):
    """
    Simple POST request to log in. This will store a cookie in the session cookie jar.
    :param arguments: argparse arguments
    :param s: requests.Session
    :return: None
    """
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    data = {"username": arguments.unifi_username, "password": os.environ['UNIFI_PW']}
    r = s.post("{}/api/auth/login".format(arguments.unifi_url), headers=headers, json=data, verify=False)
    r.raise_for_status()


def unifi_get_active_clients(s: requests.Session, arguments):
    """
    Simple GET request to retrieve all Active clients from Unifi.
    :param arguments: argparse arguments
    :param s: requests.Session
    :return: dict[str, dict] -> {mac_addr: client-obj}
    """
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    clients = s.get("{}/proxy/network/v2/api/site/default/clients/active".format(arguments.unifi_url),
                    headers=headers, verify=False)
    clients.raise_for_status()
    c = clients.json()
    active_clients = dict()
    for client in c:
        if client.get('radio') is None or client['radio'] != 'ng':
            active_clients[client['mac']] = client
    return active_clients


def adguard_login(s: requests.Session, arguments):
    """
    Simple POST request to log in to Adguard with username and password. Adds cookie
    to session cookie jar.
    :param arguments: argparse arguments
    :param s: requests.Session
    :return: None
    """
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    data = {"name": arguments.adguard_username, "password": os.environ["ADGUARD_PW"]}
    r = s.post("{}/control/login".format(arguments.adguard_url), headers=headers, json=data)
    r.raise_for_status()
    

def adguard_get_clients(s: requests.Session, arguments) -> dict[str, dict]:
    """
    GET Request to retrieve all clients from Adguard. They are then organized
    in a dictionary where the mac-address is a key. If they do not have a
    mac-address, they are ignored. TODO: Should they be?
    :param s:   requests.Session
    :param arguments: argparse arguments
    :return:    dict[str, dict] -> {mac_addr: client-obj}
    """
    r = s.get("{}/control/clients".format(arguments.adguard_url))
    r.raise_for_status()
    clients = dict()
    if r.json()['clients'] is not None:
        for client in r.json()['clients']:
            mac = None
            for item in client['ids']:
                if len(item) == 17:
                    mac = item
            if mac is not None:
                clients[mac] = client
    return clients


def adguard_add_client(s: requests.Session, client, adguard_url):
    """
    POST request to create a NEW client. A Unifi OS client object/dict
    is required.
    :param adguard_url: base-url for adguard
    :param s:       requests.Session
    :param client:  unifi-os client-dict
    :return:        None
    """
    if client.get("name") is None:
        print("Client {} needs to be named.".format(client["display_name"]))
    else:
        data = {"ids": [client['ip'], client['mac']],
                "tags": [],
                "use_global_settings": True,
                "use_global_blocked_services": True,
                "name": client['name'],
                "upstreams": []}
        r = s.post("{}/control/clients/add".format(adguard_url), json=data)
        r.raise_for_status()


def adguard_delete_all(s: requests.Session, clients: list[str], adguard_url):
    """
    Used to clean up clients in AdGuard. Since AdGuard clients are merely names for existing
    entities, deleting all doesn't remove any data. It just deletes the relationship between
    IP-ADDR and a Name.
    :param s:       requests.Session
    :param clients: list of client names
    :param adguard_url: base-url for adguard
    :return:        None
    """
    for c in clients:
        r = s.post("{}/control/clients/delete".format(adguard_url), json={"name": c})
        r.raise_for_status()
    

def adguard_update_client(s: requests.Session, client, old_name, adguard_url):
    """
    POST request to update a client. This request will update the name and
    IDS (mac_addr, ip_addr) of the client object in AdGuard.
    :param s:           requests.Session
    :param client:      unifi-os client-dict
    :param old_name:    the original name (from AdGuard client-dict)
    :param adguard_url: base-url for adguard
    :return:            None
    """
    data = {"name": old_name,
            "data": {
                "upstreams": [],
                "tags": [],
                "name": client['name'],
                "blocked_services": None,
                "ids": [client['ip'], client['mac']],
                "filtering_enabled": False,
                "parental_enabled": False,
                "safebrowsing_enabled": False,
                "safesearch_enabled": False,
                "use_global_blocked_services": True,
                "use_global_settings": True
                }
            }
    r = s.post("{}/control/clients/update".format(adguard_url), json=data)
    r.raise_for_status()


def main():
    args = parse_args()
    # Create Session
    session = requests.Session()

    # Login to unifi and retrieve clients
    unifi_login(session, args)
    unifi_clients = unifi_get_active_clients(session, args)

    # Login to AdGuard and retrieve clients
    adguard_login(session, args)
    adguard_clients = adguard_get_clients(session, args)

    # Set-math to figure out changes to make
    unifi_active_client_macs = set(list(unifi_clients.keys()))
    adguard_client_macs = set(list(adguard_clients.keys()))
    to_add = unifi_active_client_macs - adguard_client_macs
    to_modify = unifi_active_client_macs.intersection(adguard_client_macs)

    # Make changes if necessary
    if len(to_add) > 0:
        for c in to_add:
            adguard_add_client(session, unifi_clients[c], args.adguard_url)
    if len(to_modify) > 0:
        for c in to_modify:
            unifi_data = {unifi_clients[c]['ip'], unifi_clients[c]['mac']}
            if (unifi_data != set(adguard_clients[c]['ids']))\
                    or unifi_clients[c]['name'] != adguard_clients[c]['name']:
                adguard_update_client(session, unifi_clients[c], adguard_clients[c]['name'],
                                      args.adguard_url)


if __name__ == '__main__':
    main()

