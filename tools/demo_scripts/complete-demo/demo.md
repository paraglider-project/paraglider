# Invisinets Multicloud Demo

**Goals:**
* Create two VMs in Azure in different regions and connect them together
* Create a third VM in GCP and connect to one of the Azure VMs

## Setup
* Run `invd frontend <path_to_config>` to start the frontend server
* Run `invd az <port #> <frontend_rpc_addr>` to start the Azure plugin
* Run `invd gcp <port #> <frontend_rpc_addr> ` to start the GCP plugin

## Phase 1 (Live)
### Steps
Invisinets requests are shown in <span style="color:cornflowerblue">blue</span>.
1. <span style="color:cornflowerblue">Create VM A in Azure</span>
    * `inv resource create azure <resource_id> <file_to_description>`
2. <span style="color:cornflowerblue">Create VM B in Azure </span>
    * `inv resource create azure <resource_id> <file_to_description>`
3. <span style="color:cornflowerblue">Set the permit list on VM A to allow SSH and pings to VM B </span>
    * `inv rule add azure <vm_a_uri> --ssh <ip_range>`
4. Log into VM A and try to ping VM B <span style="color:firebrick">(*this should fail*) </span>
5. <span style="color:cornflowerblue">Set the permit list on VM B to allow pings from VM A</span>
    * `inv rule add azure <vm_b_uri> --ssh <ip_range>`
6. Try to ping VM B from VM A <span style="color:forestgreen">(*this should succeed*) </span>

## Phase 2 (Pre-recorded)
### Steps
Invisinets requests are shown in <span style="color:cornflowerblue">blue</span>.
1. <span style="color:cornflowerblue">Create VM C in GCP</span>
    * `inv resource create gcp "" <file_to_description>`
2. Log into VM C and try to ping VM A <span style="color:firebrick">(*this should fail*) </span>
3. <span style="color:cornflowerblue">Set the permit lists on both VMs to allow pings from the other's IP</span>
    * `inv rule add azure <vm_a_uri> --ping <vm_c_name>`
    * `inv rule add gcp <vm_b_uri> --ping <vm_a_name>`
4. Try to ping VM A from VM C <span style="color:forestgreen">(*this should succeed*) </span>
5. <span style="color:cornflowerblue">Remove the permit list rules allowing pings from VM C's permit list</span>
    * `inv rule delete gcp <vm_c_uri> --ping <vm_a_name>`
6. Try to ping VM A from VM C <span style="color:firebrick">(*this should fail*) </span>

## Phase 3 (Live)
### Steps
1. Show the resources up in each cloud portal
2. Try to ping VM A from VM C <span style="color:firebrick">(*this should fail*) </span>
3. <span style="color:cornflowerblue">Add the permit list rules allowing the pings back to VM C</span>
    * `inv rule add gcp <vm_c_uri> --ping <vm_a_name>`
4. Try to ping VM A from VM C <span style="color:forestgreen">(*this should succeed*) </span>
5. Try to ping VM B from VM C <span style="color:firebrick">(*this should fail*) </span>


### Phase 4 (Live)
Look at all the resources created in the portal (and construct a diagram with them)

