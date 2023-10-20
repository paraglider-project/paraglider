import requests

FRONTEND_SERVER_ADDR="localhost:8080"
SUB_ID="4ba880a9-fe39-4105-98e1-909297ff5bb8"
RESOURCE_GROUP_NAME="invisinets"
CLOUD="gcp"

r = requests.get("http://0.0.0.0:8080/ping")
print(r.text)

r = requests.get("http://0.0.0.0:8080/namespace/")
print(r.text)

azure_vm_string = \
    """
    {
        "location": "westus",
        "properties": {
            "hardwareProfile": {
            "vmSize": "Standard_B1s"
            },
            "osProfile": {
                "adminPassword": "",
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
    }"""

gcp_vm_string = \
"""
{
    "instance_resource": { 
        "disks":[{ 
            "auto_delete": true,
            "boot": true,
            "initialize_params": {
                "disk_size_gb": 10,
                "source_image": "projects/debian-cloud/global/images/family/debian-10"
            },
            "type": "PERSISTENT"
        }],
        "machine_type": "zones/us-west1-a/machineTypes/f1-micro",
        "name": "vm-invisinets-test-1"
    },
    "project": "invisinets",
    "zone": "us-west1-a"

}
"""

az_id = "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/test-vm".format(SUB_ID, RESOURCE_GROUP_NAME)

vm3 = \
{
    "id": "", 
    "description": gcp_vm_string
}

# r = requests.post("http://{}/cloud/{}/resources/".format(FRONTEND_SERVER_ADDR, CLOUD), 
#                   headers={"Content-Type": "application/json"}, json=vm3)
# print(r.text)


r = requests.post("http://0.0.0.0:8080/namespace/newnamespace/")
print(r.text)


id = "projects/invisinets/zones/us-west1-a/instances/vm-invisinets-test-1"
r = requests.get("http://0.0.0.0:8080/cloud/{}/permit-list/{}".format(CLOUD, id))
print(r.text)

r = requests.post("http://0.0.0.0:8080/namespace/default/")
print(r.text)

r = requests.get("http://0.0.0.0:8080/cloud/{}/permit-list/{}".format(CLOUD, id))
print(r.text)
