
import requests
import os

SUB_ID = os.getenv('AZ_SUB_ID')
RESOURCE_GROUP_NAME = "invisinets-demo"
VM_PW = os.getenv('VM_PW')
REGION1 = "westus"
REGION2 = "eastus"

FRONTEND_SERVER_ADDR = "0.0.0.0:8080"

# Ping (L7) frontend server 
r = requests.get("http://" + FRONTEND_SERVER_ADDR + "/ping")
print(r.text)

# From before, we have VM1 and VM2 in different regions and cannot talk to one another (by default)

# Now, add them to each other's permit lists
vm1_ip = "10.0.0.4"
vm2_ip = "10.1.0.4"
vm1_permit_list = \
{
    "associated_resource": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/sample-demo-vm1".format(SUB_ID, RESOURCE_GROUP_NAME), 
    "rules": [
        {
            "id" : "allow-vm2-inbound",
            "tag": [vm2_ip],
            "direction": 0,
            "src_port": -1,
            "dst_port": -1,
            "protocol": 1
        },
        {
            "id" : "allow-vm2-outbound",
            "tag": [vm2_ip],
            "direction": 1,
            "src_port": -1,
            "dst_port": -1,
            "protocol": 1
        }
    ]
}

vm2_permit_list = \
{
    "associated_resource": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/sample-demo-vm2".format(SUB_ID, RESOURCE_GROUP_NAME), 
    "rules": [
        {
            "id" : "allow-vm1-inbound",
            "tag": [vm1_ip],
            "direction": 0,
            "src_port": -1,
            "dst_port": -1,
            "protocol": 1
        },
        {
            "id" : "allow-vm1-outbound",
            "tag": [vm1_ip],
            "direction": 1,
            "src_port": -1,
            "dst_port": -1,
            "protocol": 1
        }
    ]
}

r = requests.post("http://0.0.0.0:8080/cloud/{}/resources/{}/permit-list/rules".format("azure", 1), headers={"Content-Type": "application/json"}, json=vm1_permit_list)
print(r.text)

r = requests.post("http://0.0.0.0:8080/cloud/{}/resources/{}/permit-list/rules".format("azure", 1), headers={"Content-Type": "application/json"}, json=vm2_permit_list)
print(r.text)


# Now you can ping