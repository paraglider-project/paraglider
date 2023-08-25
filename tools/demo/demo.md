# Invisinets Demo 8/25

## Setup
### Every time:
* Run `go run main.go frontend <path_to_config>` to start the frontend server
* Run `go run main.go az <port #>` to start the azure plugin
* Run `go run main.go gcp <port #>` to start the gcp plugin

### Only when resources are not yet provisioned:
* Run `python3 demo-prep.py` to setup the initial VMs

* Setup bastion (in the portal) for VM1 to be able to ping from it 

## Step 1: Start up VM3
This VM will be used later, but VM provisioning takes time
* Run `python3 demo-new-vm.py`

## Step 2: Check connectivity between VM1 and VM2
These two VMs both (1) do not have any allowed traffic and (2) are not even in the same virtual network

Pinging VM2 from VM1 should show no response

## Step 3: Set permit lists for VM1 and VM2
* Run `python3 demo.py` to set the permit lists

This will create the vnet peering needed and set NSG rules

Now pings from VM1 should reach VM2

## Step 4: Set permit lists for VM1 and VM3
* Run `python3 demo-add-vm3.py` to set the permit lists

Now VM1 should be able to ping VM3 as well


