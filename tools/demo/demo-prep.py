import requests

import os

SUB_ID = os.getenv('AZ_SUB_ID')
RESOURCE_GROUP_NAME = "invisinets-demo"
VM_PW = os.getenv('VM_PW')
REGION1 = "westus"
REGION2 = "eastus"

FRONTEND_SERVER_ADDR = "0.0.0.0:8080"

vm1 = \
{
    "id": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/sample-demo-vm1".format(SUB_ID, RESOURCE_GROUP_NAME), 
    "description": """
        {
            "location": "{}",
            "properties": {
                "hardwareProfile": {
                "vmSize": "Standard_B1s"
                },
                "osProfile": {
                "adminPassword": "{}",
                "adminUsername": "sample-user",
                "computerName": "sample-compute"
                },
                "storageProfile": {
                "imageReference": {
                    "offer": "debian-10",
                    "publisher": "Debian",
                    "sku": "10",
                    "version": "latest"
                }
                }
            }
        }""".format(REGION1, VM_PW)
}

# TODO: remove resource ID from the URL
r = requests.post("http://{}/cloud/{}/region/{}/resources/{}/".format(FRONTEND_SERVER_ADDR, "azure", REGION1, 1), 
                  headers={"Content-Type": "application/json"}, json=vm1)
print(r.text)


vm2 = \
{
    "id": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/sample-demo-vm2".format(SUB_ID, RESOURCE_GROUP_NAME), 
    "description": """
        {
            "location": "{}",
            "properties": {
                "hardwareProfile": {
                "vmSize": "Standard_B1s"
                },
                "osProfile": {
                "adminPassword": "{}",
                "adminUsername": "sample-user",
                "computerName": "sample-compute"
                },
                "storageProfile": {
                "imageReference": {
                    "offer": "debian-10",
                    "publisher": "Debian",
                    "sku": "10",
                    "version": "latest"
                }
                }
            }
        }""".format(REGION2, VM_PW)
}

# TODO: remove resource ID from the URL
r = requests.post("http://{}/cloud/{}/region/{}/resources/{}/".format(FRONTEND_SERVER_ADDR, "azure", REGION2, 1), 
                  headers={"Content-Type": "application/json"}, json=vm2)
print(r.text)

