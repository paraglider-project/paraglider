# Invisinets Multicloud Demo

**Goals:**
* Create two VMs (one in Azure, and one in GCP) and connect the two (ping-reachable). 
* Create a third VM in GCP and allow it to ping the Azure VM, but not the other GCP VM

![Demo Diagram](demo-diagram.png)

## Utils
The scripts used in this demo send HTTP requests to the Invisinets controller. These requests often have JSON content. The `utils.py` file provides simple functions for getting python dictionaries representing the necessary JSON objects. 

## Setup
* Run `go run main.go frontend <path_to_config>` to start the frontend server
* Run `go run main.go az <port #> <frontend_rpc_addr>` to start the Azure plugin
* Run `go run main.go gcp <port #> <frontend_rpc_addr> ` to start the GCP plugin

## Phase 1 (Pre-recorded)
Run `python3 prep.py` to perform the steps outlined below.

Note that the `AZ_SUB_ID` and `VM_PW` environment variables must be set.

### Steps
Invisinets requests are shown in <span style="color:cornflowerblue">blue</span>.
1. <span style="color:cornflowerblue">Create VM A in Azure</span>
2. <span style="color:cornflowerblue">Create VM B in GCP </span>
3. Check the GCP and Azure portals to see the created resources
4. Log into VM B and try to ping VM A <span style="color:firebrick">(*this should fail*) </span>
5. <span style="color:cornflowerblue">Set the permit lists on both VMs to allow pings from the other's IP</span>
6. Try to ping VM A from VM B <span style="color:forestgreen">(*this should succeed*) </span>
7. Check the portals to see the VPN gateways get provisioned
8. <span style="color:cornflowerblue">Remove the permit list rules allowing pings from VM B's permit list</span>
9. Try to ping VM A from VM B <span style="color:firebrick">(*this should fail*) </span>

## Phase 2 (Live)
Run `python3 live.py` to perform the steps outlined below.

Note that the `AZ_SUB_ID` and `VM_PW` environment variables must be set.

### Steps
1. Show the resources up in each cloud portal
2. Try to ping VM A from VM B <span style="color:firebrick">(*this should fail*) </span>
3. <span style="color:cornflowerblue">Add the permit list rules allowing the pings back to VM B</span>
4. Try to ping VM A from VM B <span style="color:forestgreen">(*this should succeed*) </span>
5. <span style="color:cornflowerblue">Create VM C in GCP </span>
6. Log into VM C and try to ping VM A and VM B <span style="color:firebrick">(*this should fail*) </span>
7. <span style="color:cornflowerblue">Add permit list rules to both VM A and VM C to allow pings between them </span>
8. Try to ping VM B from VM C <span style="color:firebrick">(*this should fail*) </span>
9. Try to ping VM A from VM C <span style="color:forestgreen">(*this should succeed*) </span>