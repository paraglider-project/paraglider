import requests
import os
import utils
import json

CONTROLLER_ADDR = "localhost:8080"
GCP_PROJECT = "invisinets"
GCP_ZONE = "us-west1-a"
RESOURCE_GROUP_NAME = "invisinets-demo"
SUBID = os.getenv("AZ_SUB_ID")
VM_PW = os.getenv("VM_PW")

AZURE_VM_NAME = "demo-vm-a"
GCP_VM1_NAME = "demo-vm-b"
GCP_VM2_NAME = "demo-vm-c"


# Show that resources are up in the portal (starting from where we left off)

# Show that ping does not work between the VMs

# Add permit list rules back to the GCP VM
# Get the allocated VM IPs
if input("Update GCP VM B permit list? (y/n):") == "y":
    AZURE_VM_IP = input("Enter the IP of the Azure VM: ")
    gcp_permit_list = utils.create_ping_permit_list(resource=utils.create_gcp_vm_id(GCP_PROJECT, GCP_ZONE, GCP_VM1_NAME), remote_ip=AZURE_VM_IP)
    print("Request JSON: ", json.dumps(gcp_permit_list, indent=2))
    r = requests.post("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "gcp"),
                    headers={"Content-Type": "application/json"}, json=gcp_permit_list)
    print(r.text)
    input("Press Enter to continue...")

# Show that ping works again

# Bring a new VM up in GCP
if input("Create VM C in GCP? (y/n):") == "y":
    vm_request_json = utils.create_vm_gcp("demo-vm-3", GCP_PROJECT, GCP_ZONE)
    print("Request JSON: ", json.dumps(vm_request_json, indent=2))
    r = requests.post("http://{}/cloud/{}/resources/".format(CONTROLLER_ADDR, "gcp"), 
                    headers={"Content-Type": "application/json"}, json=vm_request_json)
    print(r.text)
    input("Press Enter to continue...")

# Show that ping does not work between the new VM and the Azure VM or the original GCP VM

# Add permit list rules to permit communication between the new VM and the Azure VM
# Get the allocated VM IPs
if input("Update Azure VM A permit list? (y/n):") == "y":
    GCP_VM2_IP = input("Enter the IP of the new GCP VM: ")
    azure_permit_list = utils.create_ping_permit_list(resource=utils.create_azure_vm_id(SUBID, RESOURCE_GROUP_NAME, AZURE_VM_NAME), remote_ip=GCP_VM2_IP)
    print("Request JSON: ", json.dumps(azure_permit_list, indent=2))
    r = requests.post("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "azure"),
                    headers={"Content-Type": "application/json"}, json=azure_permit_list)
    print(r.text)
    input("Press Enter to continue...")

if input("Update GCP VM C permit list? (y/n):") == "y":
    gcp_permit_list = utils.create_ping_permit_list(resource=utils.create_gcp_vm_id(GCP_PROJECT, GCP_ZONE, GCP_VM2_NAME), remote_ip=AZURE_VM_IP, local_ssh_access_cidr="35.235.240.0/20")
    print("Request JSON: ", json.dumps(gcp_permit_list, indent=2))
    r = requests.post("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "gcp"),
                    headers={"Content-Type": "application/json"}, json=gcp_permit_list)
    print(r.text)
    input("Press Enter to continue...")


