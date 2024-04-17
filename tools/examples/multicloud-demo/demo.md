# Multicloud Demo

**Goals:**
* Create two VMs in Azure in different regions and connect them together
* Create a third VM in GCP and connect to one of the Azure VMs

<img src="vm-diagram.png" alt="Diagram" style="width:600px;"/>

## Setup
* Run `invd startup <path_to_config>` to start all the microservices

## Phase 0: Multi-cloud Prep (Pre-recorded)
### Steps
<!-- Invisinets requests are shown in <span style="color:cornflowerblue">blue</span>. -->
1. <span style="color:cornflowerblue">Create VM A in Azure</span>
    * `inv resource create azure vm-a azure-vm-westus.json`
2. <span style="color:cornflowerblue">Create VM C in GCP</span>
    * `inv resource create gcp vm-c gcp-vm.json`
3. <span style="color:cornflowerblue">Log into VM C and try to ping VM A</span> <span style="color:firebrick">(*this should fail*) </span>
    * `inv rule add gcp vm-c --ssh 35.235.240.0/20`
4. <span style="color:cornflowerblue">Set the permit list on VM C to allow pings from VM A.</span> This will set up the multicloud infrastructure (takes some time)
    * `inv rule add gcp vm-c --ping default.azure.vm-a`

## Phase 1: Multi-region connectivity (Live)
### Steps
<!-- Invisinets requests are shown in <span style="color:cornflowerblue">blue</span>. -->
1. <span style="color:cornflowerblue">Create VM B in Azure </span>
    * `inv resource create azure vm-b azure-vm-eastus.json`
2. <span style="color:cornflowerblue">Set the permit list on VM A to allow pings to VM B </span>
    * `inv rule add azure vm-a --ping default.azure.vm-b`
3. Log into VM A and try to ping VM B <span style="color:firebrick">(*this should fail*) </span>
4. <span style="color:cornflowerblue">Set the permit list on VM B to allow pings from VM A</span>
    * `inv rule add azure vm-b --ping default.azure.vm-a`
5. Try to ping VM B from VM A <span style="color:forestgreen">(*this should succeed*) </span>

## Phase 2: Multi-cloud connectivity (Live)
### Steps
1. Try to ping VM A from VM C <span style="color:firebrick">(*this should fail*) </span>
2. <span style="color:cornflowerblue">Set the permit list on VM A to allow pings from VM C</span>
    * `inv rule add azure vm-a --ping default.gcp.vm-c`
3. Try to ping VM A from VM C <span style="color:forestgreen">(*this should succeed*) </span>
4. <span style="color:cornflowerblue">Remove the permit list rules allowing pings from VM C's permit list</span>
    * `inv rule delete gcp vm-c --ping default.azure.vm-a`
5. Try to ping VM A from VM C <span style="color:firebrick">(*this should fail*) </span>
