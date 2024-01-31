import os
import logging
import requests
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest
from azure.mgmt.subscription import SubscriptionClient
from azure.identity import DefaultAzureCredential

# Setup Logging (prints to stdout currently)
logger = logging.getLogger('a-record-scan')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.propagate = False


class AzureClient(object):

    def __init__(self):
        """
        Initiates Azure clients using Default Azure Credentials. This method pulls the following values
        from the Environment Variables:
            AZURE_TENANT_ID
            AZURE_CLIENT_ID
            AZURE_CLIENT_SECRET
        Ensure these are configured. Use the supplied .env_template file for reference.
        """
        self.subscription_client = SubscriptionClient(
            credential=DefaultAzureCredential()
        )
        self.arg = ResourceGraphClient(
            credential=DefaultAzureCredential()
        )
        self.query = ("resources | where type contains 'publicIPAddresses' and "
                      "isnotempty(properties.ipAddress) | project properties.ipAddress, subscriptionId")
        self.ip_addr_check_url = "https://www.azurespeed.com/api/ipAddress?ipOrDomain="

    def get_all_public_ip_addresses(self):
        """ Using the app registration's subscriptions, create a query
        and retrieve all public IP Addresses
        https://learn.microsoft.com/en-us/azure/governance/resource-graph/first-query-python
        """
        # get all subscription id's in a list
        subs_list = [s.subscription_id for s in self.subscription_client.subscriptions.list()]

        # Azure Resource Graph API
        results = self.arg.resources(QueryRequest(
            subscriptions=subs_list,
            query=self.query
        ))
        return results.data

    def is_azure_ip(self, ip_addr):
        """ Check if a given IP Address belongs to Azure' Public IP Address space

        :param _type_ ip_addr: IPv4 address
        :return _type_: response json with zone information
        """
        # Check if a given IP address belongs to Azure's Public IP Address Space
        url = f"{self.ip_addr_check_url}{ip_addr}"
        r = requests.get(url)
        r.raise_for_status()
        return r.json()


class CloudflareClient(object):

    def __init__(self):
        """
        Client is used to query Cloudflare for DNS records. Use CLOUDFLARE_TOKEN environment variable
        to authenticate with the API.
        """
        self.base_url = "https://api.cloudflare.com/client/v4/zones/"
        try:
            auth = os.environ["CLOUDFLARE_TOKEN"]
            self.headers = {"content-type": "application/json",
                            "Authorization": f"Bearer {auth}"}
        except KeyError as ke:
            raise Exception("No CLOUDFLARE_TOKEN environment variable provided!") from ke

    def get_all_a_records(self, zone):
        """ Get all cloudflare a-records for a given zone

        :param _type_ zone:  zone to get all records from
        :return _type_: list of records
        """
        # Get the first one
        url = self.base_url + zone + "/dns_records"
        params = {"type": "A"}
        r = requests.get(url=url, params=params, headers=self.headers)
        results = r.json()['result']
        total_pages = r.json()['result_info']['total_pages']
        current_page = r.json()['result_info']['page']
        # iterate and collect records
        while current_page < total_pages:
            params.update({"page": current_page + 1})
            r = requests.get(url=url, params=params, headers=self.headers)
            results.extend(r.json()['result'])
            current_page += 1
        return results

    def get_all_zones(self):
        """ Get all zones

        :return _type_: All Zones
        """
        # Get the first one
        url = self.base_url
        r = requests.get(url=url, headers=self.headers)
        params = {"page": 1}
        results = r.json()['result']
        total_pages = r.json()['result_info']['total_pages']
        current_page = r.json()['result_info']['page']
        # iterate and collect records
        while current_page < total_pages:
            params.update({"page": current_page + 1})
            r = requests.get(url=url, params=params, headers=self.headers)
            results.extend(r.json()['result'])
            current_page += 1
        return results


def main():
    # Get a list of all azure owned IP Addresses
    logger.info("Gathering all public IP addresses from Azure")
    azure = AzureClient()
    azure_public_ips = [ip['properties_ipAddress'] for ip in azure.get_all_public_ip_addresses()]
    # Get all dns zones
    cf_client = CloudflareClient()
    all_zones = cf_client.get_all_zones()
    # for each zone
    current_zone = 1
    total_zones = len(all_zones)
    vulnerable_records = []
    for zone in all_zones:
        logger.info(f"Zone ({current_zone}/{total_zones}) {zone['name']}")
        current_zone += 1
        # Get all dns records
        all_dns_a_records = cf_client.get_all_a_records(zone['id'])
        # For each A-record
        for record in all_dns_a_records:
            region_data = azure.is_azure_ip(record['content'])
            if len(region_data) > 0:
                # This is a public Azure IP address
                if record['content'] not in azure_public_ips:
                    # VULNERABLE SUBDOMAIN
                    vulnerable_records.append(record)
                    logger.info(f"{record['name']}: {record['content']} ({region_data[0]['region']})")


if __name__ == '__main__':
    main()
