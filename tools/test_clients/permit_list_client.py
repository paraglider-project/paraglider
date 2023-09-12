import requests

r = requests.get("http://0.0.0.0:8080/ping")
print(r.text)

test_permit_list = \
{
    "associated_resource": "example-permit-list", 
    "rules": [
        {
            "id" : "id",
            "tag": ["tagname"],
            "direction": 0,
            "src_port": 1,
            "dst_port": 2,
            "protocol": 3
        }
    ]
}

r = requests.post("http://0.0.0.0:8080/cloud/{}/resources/{}/permit-list/rules".format("example", 123), headers={"Content-Type": "application/json"}, json=test_permit_list)
print(r.text)

test_resource = \
{
    "id": "resource-id",
    "description": "some json",
}

r = requests.post("http://0.0.0.0:8080/cloud/{}/region/{}/resources/{}/".format("example", "us-west", 123), headers={"Content-Type": "application/json"}, json=test_resource)
print(r.text)

r = requests.get("http://0.0.0.0:8080/cloud/{}/resources/{}/permit-list".format("wrong", 123))
print(r.text)
