import requests

r = requests.get("http://0.0.0.0:8080/ping")
print(r.text)


tag_name_entry = \
{
    "uri": "resource/uri",
    "ip":  "1.2.3.4"
}
r = requests.post("http://0.0.0.0:8080/tags/{}/name".format("resourcename1"), headers={"Content-Type": "application/json"}, json=tag_name_entry)
print(r.text)

tag_mapping = \
    [
        "resourcename1"
    ]
r = requests.post("http://0.0.0.0:8080/tags/{}".format("parenttag"), headers={"Content-Type": "application/json"}, json=tag_mapping)
print(r.text)

r = requests.get("http://0.0.0.0:8080/tags/{}/resolve".format("parenttag"))
print(r.text)

test_permit_list = \
{
    "associated_resource": "example-permit-list-resource", 
    "rules": [
        {
            "id" : "id",
            "tags": ["parenttag"],
            "direction": 0,
            "src_port": 1,
            "dst_port": 2,
            "protocol": 3
        }
    ]
}

r = requests.post("http://0.0.0.0:8080/cloud/{}/resources/{}/permit-list/rules".format("example", "example-permit-list-resource"), headers={"Content-Type": "application/json"}, json=test_permit_list)
print(r.text)

tag_name_entry = \
{
    "uri": "resource/uri2",
    "ip":  "2.3.4.5"
}
r = requests.post("http://0.0.0.0:8080/tags/{}/name".format("resourcename2"), headers={"Content-Type": "application/json"}, json=tag_name_entry)
print(r.text)

tag_mapping = \
    [
        "resourcename2"
    ]
r = requests.post("http://0.0.0.0:8080/tags/{}".format("parenttag"), headers={"Content-Type": "application/json"}, json=tag_mapping)
print(r.text)

r = requests.get("http://0.0.0.0:8080/tags/{}/resolve".format("parenttag"))
print(r.text)

r = requests.get("http://0.0.0.0:8080/cloud/{}/resources/{}/permit-list".format("example", "example-permit-list-resource"), headers={"Content-Type": "application/json"}, json=test_permit_list)
print(r.text)

