import requests
import os
import utils

CONTROLLER_ADDR = "localhost:8080"
GCP_PROJECT = "invisinets"
GCP_ZONE = "us-west1-a"
RESOURCE_GROUP_NAME = "invisinets-demo"
SUBID = os.getenv("AZ_SUB_ID")
VM_PW = os.getenv("VM_PW")

AZURE_VM_NAME = "demo-vm-A"
GCP_VM1_NAME = "demo-vm-B"
GCP_VM2_NAME = "demo-vm-C"


# Show that resources are up in the portal (starting from where we left off)

# Show that ping does not work between the VMs

# Add permit list rules back to the GCP VM
# Get the allocated VM IPs
AZURE_VM_IP = input("Enter the IP of the Azure VM: ")
gcp_permit_list = utils.create_ping_permit_list(resource=utils.create_gcp_vm_id(GCP_PROJECT, GCP_ZONE, GCP_VM1_NAME), remote_ip=AZURE_VM_IP)

r = requests.post("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "gcp"),
                  headers={"Content-Type": "application/json"}, json=gcp_permit_list)
print(r.text)

# Show that ping works again

# Bring a new VM up in GCP
vm_request_json = utils.create_vm_gcp("demo-vm-3", GCP_PROJECT, GCP_ZONE)
r = requests.post("http://{}/cloud/{}/resources/".format(CONTROLLER_ADDR, "gcp"), 
                  headers={"Content-Type": "application/json"}, json=vm_request_json)
print(r.text)

# Show that ping does not work between the new VM and the Azure VM or the original GCP VM

# Add permit list rules to permit communication between the new VM and the Azure VM
# Get the allocated VM IPs
GCP_VM2_IP = input("Enter the IP of the new GCP VM: ")

azure_permit_list = utils.create_permit_list(resource=utils.create_azure_vm_id(SUBID, RESOURCE_GROUP_NAME, AZURE_VM_NAME), remote_ip=GCP_VM2_IP)

r = requests.post("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "azure"),
                  headers={"Content-Type": "application/json"}, json=azure_permit_list)
print(r.text)

gcp_permit_list = utils.create_permit_list(resource=utils.create_gcp_vm_id(GCP_PROJECT, GCP_ZONE, GCP_VM2_NAME), remote_ip=AZURE_VM_IP)

r = requests.post("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "gcp"),
                  headers={"Content-Type": "application/json"}, json=gcp_permit_list)
print(r.text)


