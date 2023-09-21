import requests

r = requests.get("http://0.0.0.0:8080/ping")
print(r.text)


tag_name_entry = \
{
    "uri": "resource/uri",
    "ip":  "1.2.3.4"
}
r = requests.post("http://0.0.0.0:8080/tags/{}/name".format("exampletag"), headers={"Content-Type": "application/json"}, json=tag_name_entry)
print(r.text)

tag_mapping = \
    [
        "exampletag"
    ]
r = requests.post("http://0.0.0.0:8080/tags/{}".format("parenttag"), headers={"Content-Type": "application/json"}, json=tag_mapping)
print(r.text)

r = requests.get("http://0.0.0.0:8080/tags/{}/resolve".format("parenttag"))
print(r.text)
