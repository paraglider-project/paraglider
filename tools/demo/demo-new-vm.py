import requests
import os

SUB_ID = os.getenv('AZ_SUB_ID')
RESOURCE_GROUP_NAME = "invisinets-demo"
VM_PW = os.getenv('VM_PW')
REGION = "westus"

FRONTEND_SERVER_ADDR = "0.0.0.0:8080"

# Create a new VM, VM3 in WestUS
vm3 = \
{
    "id": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/sample-demo-vm3".format(SUB_ID, RESOURCE_GROUP_NAME), 
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
        }""".format(REGION, VM_PW)
}

r = requests.post("http://{}/cloud/{}/region/{}/resources/{}/".format(FRONTEND_SERVER_ADDR, "azure", REGION, 1), 
                  headers={"Content-Type": "application/json"}, json=vm3)
print(r.text)