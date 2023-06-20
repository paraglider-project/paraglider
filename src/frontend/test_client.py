import requests

r = requests.get("http://0.0.0.0:8080/ping")
print(r.text)

r = requests.get("http://0.0.0.0:8080/permit-lists/:123")
print(r.text)

test_permit_list = \
{
    "name": "example-permit-list", 
    "type": "permit-list",
    "location": "westus",
    "id": "tenant-id/permit-list-id",
    "properties": {
        "associated_resource": "tenant-id/resource-id",
        "rules" : [
            {
                "tag" : "tagname",
                "direction": 0,
                "src_port": 1,
                "dst_port": 2,
                "protocol": 3
            }
        ]
    }
}

r = requests.post("http://0.0.0.0:8080/permit-lists/:123", headers={"Content-Type": "application/json"}, json=test_permit_list)
print(r.text)

