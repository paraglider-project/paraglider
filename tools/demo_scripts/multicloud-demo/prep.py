
import requests
import os
import json
import utils

CONTROLLER_ADDR = "localhost:8080"
GCP_PROJECT = "invisinets"
GCP_ZONE = "us-west1-a"
AZURE_REGION = "westus"
RESOURCE_GROUP_NAME = "invisinets-demo"
SUBID = os.getenv("AZ_SUB_ID")
VM_PW = os.getenv("VM_PW")

GCP_VM_NAME = "demo-vm-b"
AZ_VM_NAME = "demo-vm-a"

# Create a VM in GCP
if input("Create GCP VM? (y/n):") == "y":
    vm_request_json = utils.create_vm_gcp(GCP_VM_NAME, GCP_PROJECT, GCP_ZONE)
    print("Request JSON: ", json.dumps(vm_request_json, indent=2))
    r = requests.post("http://{}/cloud/{}/resources/".format(CONTROLLER_ADDR, "gcp"), 
                    headers={"Content-Type": "application/json"}, json=vm_request_json)
    print(r.text)
    input("Press Enter to continue...")

# Create a VM in Azure
if input("Create Azure VM? (y/n):") == "y":
    vm_request_json = utils.create_vm_azure(SUBID, RESOURCE_GROUP_NAME, AZ_VM_NAME, AZURE_REGION, VM_PW)
    print("Request JSON: ", json.dumps(vm_request_json, indent=2))
    r = requests.post("http://{}/cloud/{}/resources/".format(CONTROLLER_ADDR, "azure"),
                    headers={"Content-Type": "application/json"}, json=vm_request_json)
    print(r.text)
    input("Press Enter to continue...")

# Look at the portal to see what resources have been created
input("Look at the portal to see what resources have been created (press Enter to continue)...")

# Log into the GCP VM and try to ping the Azure VM

# Get the allocated VM IPs
GCP_VM_IP = input("Enter the IP of the GCP VM: ")
GCP_VM_SUBNET_CIDR = "35.235.240.0/20"
AZURE_VM_IP = input("Enter the IP of the Azure VM: ")

# Connect the VMs
if input("Add to Azure VM's permit list? (y/n):") == "y":
    azure_permit_list = utils.create_ping_permit_list(utils.create_azure_vm_id(SUBID, RESOURCE_GROUP_NAME, AZ_VM_NAME), remote_ip=GCP_VM_IP)
    print("Request JSON: ", json.dumps(azure_permit_list, indent=2))
    print("Creating multicloud connection (this may take some time)...")
    r = requests.post("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "azure"),
                    headers={"Content-Type": "application/json"}, json=azure_permit_list)
    print(r.text)
    input("Press Enter to continue...")

if input("Add to GCP VM's permit list? (y/n):") == "y":
    gcp_permit_list = utils.create_ping_permit_list(resource=utils.create_gcp_vm_id(GCP_PROJECT, GCP_ZONE, GCP_VM_NAME), remote_ip=AZURE_VM_IP, local_ssh_access_cidr=GCP_VM_SUBNET_CIDR)
    print("Request JSON: ", json.dumps(gcp_permit_list, indent=2))
    print("Checking multicloud connection (this may take some time)...")
    r = requests.post("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "gcp"),
                    headers={"Content-Type": "application/json"}, json=gcp_permit_list)
    print(r.text)
    input("Press Enter to continue...")

# Watch the VPN Gateways get provisioned 

# Wait

# Show that ping works between the VMs now

# Remove one of the rules to prevent ping from working
if input("Remove from GCP VM's permit list? (y/n):") == "y":
    gcp_permit_list_remove = utils.create_ping_permit_list(resource=utils.create_gcp_vm_id(GCP_PROJECT, GCP_ZONE, GCP_VM_NAME), remote_ip=AZURE_VM_IP)
    print("Request JSON: ", json.dumps(gcp_permit_list_remove, indent=2))
    r = requests.delete("http://{}/cloud/{}/permit-list/rules/".format(CONTROLLER_ADDR, "gcp"),
                        headers={"Content-Type": "application/json"}, json=gcp_permit_list_remove)
    print(r.text)
    input("Press Enter to continue...")

# Show that ping no longer works

