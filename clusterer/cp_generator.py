
import argparse

parser = argparse.ArgumentParser(
    description="Use this tool to turn the clustered logical expressions into Control Plane setup code"
)
parser.add_argument(
    "--outputs", dest="output", metavar="<filename>", type=str, required=True
)
parser.add_argument(
    "--input", dest="input", metavar="<filename>", type=str, required=True
)
options = parser.parse_args()

def sensor_to_int(sensor):
    num = None
    for i in range(len(sensor)):
        try:
            num = int(sensor[i:])
        except ValueError:
            pass
    if not num:
        return ord(sensor[-1])

def line_to_table_entry(line):
    print("line:",line)
    components = line.split(";")
    expressions = components[0].split("v")
    conj_id = components[1]
    conj_id = int(conj_id.split(":")[1])
    sensors = list(eval(components[2].split(":")[1]))
    print("sensors:",sensors)
    entry_string = ""
    j = 0
    for expr in expressions:
        expr = expr.strip()
        j += 1
        i = 0
        while i < len(sensors) and (not (sensors[i] in expr)):
            i += 1
        if i == len(sensors):
            for sensor in sensors:
                entry_string = entry_string + """p4.SwitchIngress.conj_table_%s.add_with_set_conj_value_%s(
                %s,
                conj_v=%s,
                disj_op = %s
                disj_v = %s
                upper_bound = %s)

""" % (str(j), str(j), str(sensor_to_int(sensor)), str(conj_id), str(0), str(0), str(0))
            continue
        sensor_as_int = sensor_to_int(sensors[i])
        if ">" in expr:
            disj_op = 1
        elif "<" in expr:
            disj_op = 2
        elif "!=" in expr:
            disj_op = 4
        elif "=" in expr:
            disj_op = 3
        elif "between" in expr:
            disj_op = 5
        k = 1
        valid = True
        disj_value = 0
        if disj_op == 5:
            expr_comps = expr.split(",")
            upper_bound = int(expr_comps[1])
            expr = expr_comps[0]
        while k < len(expr) and valid:
            try:
                disj_value = int(expr[-k:])
                valid = True
                k += 1
            except ValueError:
                valid = False
        
        if disj_op == 5:
            entry_string = entry_string + """p4.SwitchIngress.conj_table_%s.add_with_set_conj_value_%s(
                %s,
                conj_v=%s,
                disj_op = %s
                disj_v = %s
                upper_bound = %s)

""" % (str(j), str(j), str(sensor_as_int), str(conj_id), str(disj_op), str(disj_value), str(upper_bound))
        else:    
            entry_string = entry_string + """p4.SwitchIngress.conj_table_%s.add_with_set_conj_value_%s(
                %s,
                conj_v=%s,
                disj_op = %s
                disj_v = %s)

""" % (str(j), str(j), str(sensor_as_int), str(conj_id), str(disj_op), str(disj_value))
    return entry_string
    

with open(options.input, "r") as file:
    content = file.readlines()

small_clusters = []
for line in content:
    if "small cluster" in line:
        small_clusters.append([])
    elif ("conj_id" in line and "sensors:" in line):
        small_clusters[-1].append(line)



for i in range(len(small_clusters)):
    with open(options.output + ("_%s" % (i+1)) + ".py", "w") as out_file:
        out_file.write("""
p4 = bfrt.test2.pipe

""")
        for line in small_clusters[i]:
            out_file.write(line_to_table_entry(line))
    print("Successfully wrote small cluster control panel code to", options.output + ("_%s" % (i+1)) + ".py", "w")
