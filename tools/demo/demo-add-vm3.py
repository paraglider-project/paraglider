import requests
import os

SUB_ID = os.getenv('AZ_SUB_ID')
RESOURCE_GROUP_NAME = "invisinets-demo"

FRONTEND_SERVER_ADDR = "0.0.0.0:8080"

VM1_IP = "10.0.0.4"
VM3_IP = "10.0.0.5"

# Add permit list rules to allow VM1 and VM3 to talk
vm1_permit_list = \
{
    "associated_resource": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/sample-demo-vm1".format(SUB_ID, RESOURCE_GROUP_NAME), 
    "rules": [
        {
            "id" : "allow-vm3-inbound",
            "tag": [VM3_IP],
            "direction": 0,
            "src_port": -1,
            "dst_port": -1,
            "protocol": 1
        },
        {
            "id" : "allow-vm3-outbound",
            "tag": [VM3_IP],
            "direction": 1,
            "src_port": -1,
            "dst_port": -1,
            "protocol": 1
        }
    ]
}

vm3_permit_list = \
{
    "associated_resource": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/sample-demo-vm3".format(SUB_ID, RESOURCE_GROUP_NAME), 
    "rules": [
        {
            "id" : "allow-vm1-inbound",
            "tag": [VM1_IP],
            "direction": 0,
            "src_port": -1,
            "dst_port": -1,
            "protocol": 1
        },
        {
            "id" : "allow-vm1-outbound",
            "tag": [VM1_IP],
            "direction": 1,
            "src_port": -1,
            "dst_port": -1,
            "protocol": 1
        }
    ]
}

r = requests.post("http://{}/cloud/{}/resources/{}/permit-list/rules".format(FRONTEND_SERVER_ADDR, "azure", 1), headers={"Content-Type": "application/json"}, json=vm1_permit_list)
print(r.text)

r = requests.post("http://{}/cloud/{}/resources/{}/permit-list/rules".format(FRONTEND_SERVER_ADDR, "azure", 1), headers={"Content-Type": "application/json"}, json=vm3_permit_list)
print(r.text)