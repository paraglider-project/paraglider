
import json

class PermitListRule:
    def __init__(self, id, tags, src_port, dst_port, protocol, direction):
        self.id = id
        self.tags = tags
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.direction = direction

    def get_dict(self):
        return self.__dict__

def create_permit_list(resource, rules):
    return {
        "associated_resource": resource,
        "rules": [r.get_dict() for r in rules]
    }

def create_ping_permit_list(resource, remote_ip, local_ssh_access_cidr=None):
    rules = [PermitListRule("allow-ping-inbound", [remote_ip], -1, -1, 1, 0), PermitListRule("allow-ping-outbound", [remote_ip], -1, -1, 1, 1)]
    if local_ssh_access_cidr != None:
        rules.append(PermitListRule("allow-local-inbound", [local_ssh_access_cidr], -1, -1, 6, 0))
        rules.append(PermitListRule("allow-local-outbound", [local_ssh_access_cidr], -1, -1, 6, 1))
    return create_permit_list(resource, rules)

def create_azure_vm_id(subscription, resource_group, vm_name):
    return "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}".format(subscription, resource_group, vm_name)

def create_vm_azure(subscription, resource_group, vm_name, region, password):
    description = {
        "location": region,
        "properties": {
            "hardwareProfile": {
                "vmSize": "Standard_B1s"
            },
            "osProfile": {
                "adminPassword": password,
                "adminUsername": "sample-user",
                "computerName": "sample-compute"
            },
            "storageProfile": {
                "imageReference": {
                    "offer": "debian-10",
                    "publisher": "Debian",
                    "sku": "10",
                    "version": "latest"
                }
            }
        }
    }
    description_json = json.dumps(description)
    return \
    {
        "id": create_azure_vm_id(subscription, resource_group, vm_name),
        "description": description_json
    }

def create_gcp_vm_id(project, zone, vm_name):
    return "projects/{}/zones/{}/instances/{}".format(project, zone, vm_name)

def create_vm_gcp(vm_name, project, zone):
    description = { 
        "instance_resource": { 
                "disks": [{
                    "auto_delete": True,
                    "boot": True,
                    "initialize_params": {
                        "disk_size_gb": 10,
                        "source_image": "projects/debian-cloud/global/images/family/debian-10"
                    },
                    "type": "PERSISTENT"
                }],
                "machine_type": "zones/{}/machineTypes/f1-micro".format(zone),
                "name": vm_name
            },
            "project": project,
            "zone": zone
    }
    description_json = json.dumps(description)

    return  \
    {
        "id": "",
        "description": description_json
    }

"""
        {{
            "instance_resource": {{ 
                "disks": [{{ 
                    "auto_delete": true,
                    "boot": true,
                    "initialize_params": {{
                        "disk_size_gb": 10,
                        "source_image": "projects/debian-cloud/global/images/family/debian-10"
                    }},
                    "type": "PERSISTENT"
                }}],
                "machine_type": "zones/{}/machineTypes/f1-micro",
                "name": {}
            }},
            "project": {},
            "zone": {}

        }}
"""