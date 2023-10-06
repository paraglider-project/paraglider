import requests

r = requests.get("http://0.0.0.0:8080/ping")
print(r.text)

r = requests.get("http://0.0.0.0:8080/tags/{}".format("exampletag"))
print(r.text)

tag_mapping = \
    [
        "child1"
    ]
r = requests.post("http://0.0.0.0:8080/tags/{}".format("exampletag"), headers={"Content-Type": "application/json"}, json=tag_mapping)
print(r.text)

tag_mapping = \
    [
        "child2",
        "child3"
    ]
r = requests.post("http://0.0.0.0:8080/tags/{}".format("exampletag"), headers={"Content-Type": "application/json"}, json=tag_mapping)
print(r.text)

tag_mapping = \
    [
        "child1",
        "child3"
    ]
r = requests.delete("http://0.0.0.0:8080/tags/{}/members".format("exampletag"), headers={"Content-Type": "application/json"}, json=tag_mapping)
print(r.text)

r = requests.get("http://0.0.0.0:8080/tags/{}".format("exampletag"))
print(r.text)

r = requests.delete("http://0.0.0.0:8080/tags/{}".format("exampletag"))
print(r.text)
