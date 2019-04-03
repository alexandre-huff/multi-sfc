import json

with open("data/out.json") as f:
    data = json.load(f)

# print(json.dumps(data, indent=2))

intervals = data["intervals"]

for item in intervals:
    print(item["sum"]["bits_per_second"] / 1000 / 1000)
