# Invisinets Multicloud Demo

**Goals:**
* Create two VMs in Azure in different regions and connect them together
* Create a third VM in GCP and connect to one of the Azure VMs

## Setup
* Run `go run main.go frontend <path_to_config>` to start the frontend server
* Run `go run main.go az <port #> <frontend_rpc_addr>` to start the Azure plugin
* Run `go run main.go gcp <port #> <frontend_rpc_addr> ` to start the GCP plugin

## Phase 1 (Live)
Run `python3 phase1.py` to perform the steps outlined below.

Note that the `AZ_SUB_ID` and `VM_PW` environment variables must be set.

### Steps
Invisinets requests are shown in <span style="color:cornflowerblue">blue</span>.
1. <span style="color:cornflowerblue">Create VM A in Azure</span>
2. <span style="color:cornflowerblue">Create VM B in Azure </span>
3. Log into VM A and try to ping VM B <span style="color:firebrick">(*this should fail*) </span>
4. <span style="color:cornflowerblue">Set the permit lists on both VMs to allow pings from the other's IP</span>
5. Try to ping VM B from VM A <span style="color:forestgreen">(*this should succeed*) </span>

## Phase 2 (Pre-recorded)
Run `python3 phase2.py` to perform the steps outlined below.

Note that the `AZ_SUB_ID` and `VM_PW` environment variables must be set.

### Steps
Invisinets requests are shown in <span style="color:cornflowerblue">blue</span>.
1. <span style="color:cornflowerblue">Create VM C in GCP</span>
2. Log into VM C and try to ping VM A <span style="color:firebrick">(*this should fail*) </span>
3. <span style="color:cornflowerblue">Set the permit lists on both VMs to allow pings from the other's IP</span>
4. Try to ping VM A from VM C <span style="color:forestgreen">(*this should succeed*) </span>
5. <span style="color:cornflowerblue">Remove the permit list rules allowing pings from VM C's permit list</span>
6. Try to ping VM A from VM C <span style="color:firebrick">(*this should fail*) </span>

## Phase 3 (Live)
Run `python3 phase3.py` to perform the steps outlined below.

Note that the `AZ_SUB_ID` and `VM_PW` environment variables must be set.

### Steps
1. Show the resources up in each cloud portal
2. Try to ping VM A from VM C <span style="color:firebrick">(*this should fail*) </span>
3. <span style="color:cornflowerblue">Add the permit list rules allowing the pings back to VM C</span>
4. Try to ping VM A from VM C <span style="color:forestgreen">(*this should succeed*) </span>
5. Try to ping VM B from VM C <span style="color:firebrick">(*this should fail*) </span>


### Phase 4 (Live)
Look at all the resources created in the portal (and construct a diagram with them)

