import argparse

parser = argparse.ArgumentParser(
    description="Use this tool to put logical expressions into clusters"
)
parser.add_argument(
    "--output", dest="output", metavar="<filename>", type=str, required=True
)
parser.add_argument(
    "--input", dest="input", metavar="<filename>", type=str, required=True
)
parser.add_argument(
    "--to_cp_code_data", dest="plus_data", action="store_true"
)
parser.set_defaults(plus_data=False)
options = parser.parse_args()

with open(options.input, "r") as file:
    content = file.readlines()


def disj_contains(expression):
    sensors = []
    elements = expression.split("v")
    elements = [element.strip(" ") for element in elements]
    for element in elements:
        sensor = ""
        i = 0
        while element[i] not in (" ", "<", ">", "=", "!", "@"):
            sensor = sensor + element[i]
            i += 1
        sensors.append(sensor)
    return set(sensors)


def contains(expression):
    sensors = []
    disjunctions = expression.split("&")
    disjunctions = [disj.strip("() ") for disj in disjunctions]
    for disj in disjunctions:
        sensors += disj_contains(disj)
    return set(sensors)
    
def break_into_small_clusters(cluster):
    disjunctions = []
    small_clusters = []
    for entry in cluster:
        disjunctions_in_entry = entry["expression"].split("&")
        disjunctions_in_entry = [
            {
                "expression": disj.strip("() \n"),
                "sensors": entry["sensors"],
                "conj_id": entry["conj_id"],
            }
            for disj in disjunctions_in_entry
        ]
        disjunctions += disjunctions_in_entry
    for disj in disjunctions:
        disj["contains"] = disj_contains(disj["expression"])
    for i in range(len(disjunctions)):
        for j in range(i+1,len(disjunctions)):
            if disjunctions[i]["expression"] == disjunctions[j]["expression"]:
                if disjunctions[i]["contains"].intersection(disjunctions[i]["sensors"]):
                    disjunctions[j]["conj_id"] = disjunctions[i]["conj_id"]
                elif disjunctions[j]["contains"].intersection(disjunctions[j]["sensors"]):
                    disjunctions[i]["conj_id"] = disjunctions[j]["conj_id"]
    while disjunctions:
        small_clusters.append([disjunctions[0]])
        small_cluster_contains = set(disjunctions[0]["contains"])
        del disjunctions[0]
        k = 0
        while k < len(disjunctions):
            if small_cluster_contains.intersection(disjunctions[k]["contains"]):
                small_clusters[-1].append(disjunctions[k])
                small_cluster_contains = small_cluster_contains.union(
                    disjunctions[k]["contains"]
                )
                del disjunctions[k]
                k = 0
            else:
                k += 1
    return small_clusters


def unify_smalls_if_needed(clusters):
    smalls = []
    small_contains = []
    small_matches = []
    for entry in clusters:
        small_contains.append(set([]))
        small_matches.append(set([]))
        for expr in entry:
            small_contains[-1] = small_contains[-1].union(expr["contains"])
            small_matches[-1] = small_matches[-1].union(expr["sensors"])
    while clusters:
        smalls.append(clusters[0])
        actual_contains = small_contains[0]
        actual_matches = small_matches[0]
        del clusters[0]
        del small_contains[0]
        del small_matches[0]
        k = 0
        while k < len(clusters):
            collision = False
            print(actual_matches,";",actual_contains,":",small_contains,";",small_matches)
            for a in actual_matches:
                for b in actual_contains:
                    if (a in small_contains[k] and b in small_matches[k]):
                        actual_contains = actual_contains.union(small_contains[k])
                        actual_matches = actual_matches.union(small_matches[k])
                        smalls[-1] += clusters[k]
                        del clusters[k]
                        del small_contains[k]
                        del small_matches[k]
                        collision = True
                        break
                if collision:
                    break
            if not collision:
                k += 1
    return smalls

for line in content:
    line.replace("(","")
    line.replace(")","")
    line.replace("between","@")
expressions = []
conj_id = 0
for line in content:
    if line != "\n":
        if ":" in line:
            stripped_sensors = line.strip(" ")
            sensors = stripped_sensors.split(",")
            sensors = set([sensor.strip(": \n") for sensor in sensors])
            expressions.append({"sensors": sensors})
            expressions[-1]["conj_id"] = conj_id
            conj_id += 1
        else:
            stripped_expression = line.strip(" ")
            expressions[-1]["expression"] = stripped_expression
            expressions[-1]["contains"] = contains(stripped_expression)

big_clusters = []
while expressions:
    big_clusters.append([expressions[0]])
    big_cluster_contains = set(expressions[0]["contains"])
    del expressions[0]
    i = 0
    while i < len(expressions):
        if big_cluster_contains.intersection(expressions[i]["contains"]):
            big_clusters[-1].append(expressions[i])
            big_cluster_contains = big_cluster_contains.union(
                expressions[i]["contains"]
            )
            del expressions[i]
            i = 0
        else:
            i += 1

small_clusters = [[]] * len(big_clusters)
for i in range(len(big_clusters)):
    small_clusters[i] = break_into_small_clusters(big_clusters[i])
                

for j in range(len(small_clusters)):
    small_clusters[j] = unify_smalls_if_needed(small_clusters[j])

written = []

with open(options.output, "w") as out_file:
    for k in range(len(small_clusters)):
        out_file.write("independent cluster " + str(k + 1) + "\n")
        for j in range(len(small_clusters[k])):
            out_file.write("small cluster " + str(j + 1) + "\n")
            for entry in small_clusters[k][j]:
                if entry["expression"] not in written:
                    if options.plus_data:
                        out_file.write(entry["expression"].replace("@","between") + "; conj_id:" + str(entry["conj_id"]) + "; sensors:" + str(entry["sensors"]) + "\n")
                    else:
                        out_file.write(entry["expression"].replace("@","between") + "\n")
                    written.append(entry["expression"])
    out_file.write("\n" * 3)
    print("Successfully wrote clustered expressions to", options.output)
