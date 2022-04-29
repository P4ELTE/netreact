import argparse

parser = argparse.ArgumentParser(
    description="Use this tool to automatically generate the maching logic for FastReact"
)
parser.add_argument(
    "--sensor-count", dest="sensorcount", metavar="<count>", type=int, default=1000
)
parser.add_argument(
    "--output", dest="output", metavar="<filename>", type=str, required=True
)
parser.add_argument(
    "--max-conjunctive", dest="maxconj", metavar="<count>", type=int, default=1
)
parser.add_argument(
    "--history-size", dest="historysize", metavar="<count>", type=int, default=4
)
parser.add_argument(
    "--dummy-tables", dest="dummy_count", metavar="<count>", type=int, default=0
)
parser.add_argument(
    "--p4-template", dest="p4template", metavar="<filename>", type=str, required=True
)

options = parser.parse_args()
assert options.sensorcount > 0, "Sensorcount must be > 0"
assert options.historysize > 0, "Historysize must be > 0"
assert options.maxconj > 0, "Conjunction count must be > 0"
assert options.dummy_count > -1, "Dummy table count must be natural number"

with open(options.p4template) as rf:
    s = rf.read()

output_base = options.output.replace(".p4", "")
p4output = "%s.p4" % output_base

s = s.replace("<SENSOR_COUNT>", str(options.sensorcount))
s = s.replace("<HISTORY_SIZE>", str(options.historysize))

register_declarations = ""
register_actions = ""
register_calls = ""
for k in range(options.historysize):
    register_declarations = (
            register_declarations
            + "\tRegister<bit<32>,bit<32>>(SENSOR_COUNT) map_register_%s;\n" % str(k + 1)
    )
    register_actions = (
            register_actions
            + "\tRegisterAction<bit<32>,_,bit<32>>(map_register_%s) get_map_%s = {"
            % (str(k + 1), str(k + 1))
    )
    if k == 0:
        register_actions = (
                register_actions
                + """
    void apply(inout bit<32> register_data,  out bit<32> result){
            result = register_data;
            register_data = hdr.sensor.sensorValue;
        }
    };
"""
        )
    else:
        register_actions = (
                register_actions
                + """
    void apply(inout bit<32> register_data,  out bit<32> result){
            result = register_data;
            register_data = ig_md.historical_value;
        }
    };

"""
        )
    register_calls = (
            register_calls
            + "\t\t\tig_md.historical_value = get_map_%s.execute(hdr.sensor.sensorId);\n"
            % str(k + 1)
    )

map_register_declarations = ""
for k in range(options.maxconj):
    map_register_declarations = (
            map_register_declarations
            + "\tRegister<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_%s;\n"
            % str(k + 1)
    )

map_register_actions = ""
for j in range(options.maxconj):
    map_register_actions = (
            map_register_actions
            + """

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_%s) set_disj_map_%s_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_%s;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_%s) set_disj_map_%s_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_%s;
            result = register_data;
        }
    };
"""
            % (str(j + 1), str(j + 1), str(j + 1), str(j + 1), str(j + 1), str(j + 1))
    )
conj_meta = ""
for k in range(options.maxconj):
    conj_meta = (
            conj_meta
            + "\n\tbit<32> conj_value_%s;\n\tbit<32> disj_value_%s;\n\tbit<32> disj_map_%s;\n\tbit<32> upper_bound_%s;\n"
            % (str(k + 1), str(k + 1), str(k + 1), str(k + 1))
    )
s = s.replace("<CONJ_META>", conj_meta)

dummy_meta = ""
for k in range(options.dummy_count):
    dummy_meta += "\tbit<32> dummy_%s;\n" % str(k + 1)
s = s.replace("<DUMMY_META>", dummy_meta)

disj_meta = ""

for k in range(options.maxconj):
    disj_meta += "\tbit<32> disj_op_%s;\n" % str(k + 1)
    disj_meta += "\tbool disj_%s;\n" % str(k + 1)
    disj_meta += "\tbit<32> toCheck_%s;\n" % str(k + 1)
    disj_meta += "\tbit<32> sensorValue_copy_%s;\n" % str(k + 1)

s = s.replace("<DISJ_META>", disj_meta)

dummy_tables = ""
dummy_table_calls = ""
conjuntion_tables = ""
conjuntion_table_calls = ""
subtraction_table_calls = ""
ingress_metadata_fields = ""
disjuntion_bool_inits = ""
subtraction_tables = ""
evaluation = ""
sum_disj_keys = ""
sum_disj_entry = ""
evaluation_tables = ""
call_evals = ""
new_map_tables = ""
new_map_counter = 1
check_disj_map_tables = ""
store_disj_map_tables = ""
sum_conj_entry = ""
sum_conj_keys = ""
new_map_table_calls = ""
store_disj_map_table_calls = ""
check_disj_map_table_calls = ""
hash_action = ""

for k in range(options.dummy_count):
    if k == 0:
        dummy_tables += """
	action set_dummy_value_%s(bit<32> dummy_v){
		ig_md.dummy_%s = dummy_v;
	}

	table dummy_table_%s{
    actions = {
            set_dummy_value_%s;
        }
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        size = 50000;
        const entries = {
            {0} : set_dummy_value_%s(3);
            {1} : set_dummy_value_%s(1);
            {2} : set_dummy_value_%s(100);
            {3} : set_dummy_value_%s(2000);
            {4} : set_dummy_value_%s(10000);
            {5} : set_dummy_value_%s(200000);
		}
	}        
""" % (
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
        )
    else:
        dummy_tables += """
	action set_dummy_value_%s(bit<32> dummy_v){
		ig_md.dummy_%s = dummy_v;
	}

	table dummy_table_%s{
    actions = {
            set_dummy_value_%s;
        }
        key = {
            ig_md.dummy_%s: exact;
        }
        size = 6;
        const entries = {
            {0} : set_dummy_value_%s(3);
            {1} : set_dummy_value_%s(1);
            {2} : set_dummy_value_%s(100);
            {3} : set_dummy_value_%s(2000);
            {4} : set_dummy_value_%s(10000);
            {5} : set_dummy_value_%s(200000);
		}
	}        
""" % (
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
            str(k + 1),
        )

    dummy_table_calls += "\t\t\tdummy_table_%s.apply();\n" % (str(k + 1))

for k in range(options.maxconj):
    hash_action += (
            "\t\tig_md.sensorValue_copy_%s = identity_hash.get(hdr.sensor.sensorValue);\n"
            % str(k + 1)
    )
    if k < 4:
        sum_conj_keys = sum_conj_keys + "\t\t\tig_md.disj_%s: exact;\n" % (str(k + 1))
    if k == 0:
        sum_conj_entry = sum_conj_entry + "true"
    elif k < 4:
        sum_conj_entry = sum_conj_entry + ",true"
    store_disj_map_table_calls += """               store_disj_map_%s.apply();
""" % (
        str(k + 1)
    )

    store_disj_map_tables = store_disj_map_tables + '''
    action store_disj_%s_true() {
		ig_md.disj_map_%s = set_disj_map_%s_register_true.execute(ig_md.conj_value_%s);
	}

    action store_disj_%s_false() {
		ig_md.disj_map_%s = set_disj_map_%s_register_false.execute(ig_md.conj_value_%s);
	}

	table store_disj_map_%s{
		actions = {
			store_disj_%s_true;
			store_disj_%s_false;
		}
		key = {
			ig_md.disj_%s : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_%s_true();
			{false} : store_disj_%s_false();
		}
	}
''' % (str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1))
    conjuntion_table_calls = conjuntion_table_calls + "\t\t\tconj_table_%s.apply();\n" % str(k + 1)
    conjuntion_tables = conjuntion_tables + '''
	action set_conj_value_%s(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_%s = conj_v;
        ig_md.disj_op_%s = disj_op;
        ig_md.disj_value_%s = disj_v;
		ig_md.upper_bound_%s = upper_bound;
	}

	table conj_table_%s{
    actions = {
            set_conj_value_%s;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_%s(0,0,0,0);
        const entries = {
            {0} : set_conj_value_%s(3,100,2,0);
            {1} : set_conj_value_%s(1,400,2,0);
		}
	}
''' % (k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1)
    check_disj_map_table_calls = check_disj_map_table_calls + "\t\t\tcheck_disj_map_%s.apply();\n" % str(k + 1)
    check_disj_map_tables = check_disj_map_tables + '''
	action set_disj_map_%s_true(){
		ig_md.disj_%s = true;
    }

	action set_disj_map_%s_false(){
        ig_md.disj_%s = false;
    }
	
	table check_disj_map_%s{
		actions = {
			set_disj_map_%s_true;
			set_disj_map_%s_false;
		}
		key = {
			ig_md.disj_map_%s: exact;

		}
		size = 1;
		const default_action = set_disj_map_%s_true;
		const entries = {
			{0} : set_disj_map_%s_false();
		}
	}
''' % (str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1))
    new_map_tables = new_map_tables + '''
	action create_with_true_%s(bit<32> bitstring){
		ig_md.disj_map_%s = bitstring | ig_md.disj_map_%s;
	}
	
	action create_with_false_%s(bit<32> bitstring){
		ig_md.disj_map_%s = bitstring & ig_md.disj_map_%s;
	}
''' % (str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1))
    new_map_table_calls = new_map_table_calls + '''
                if(ig_md.disj_op_%s != 0){
                    create_new_map_%s.apply();
                }
''' % (str(k + 1), str(k + 1))
    new_map_tables = new_map_tables + '''
	table create_new_map_%s{
		actions = {
			create_with_false_%s;
			create_with_true_%s;
		}
		key = {
			ig_md.disj_%s : exact;
			ig_md.conj_value_%s : exact;
            hdr.sensor.sensorId : exact;
		}
		size = 64;
		const entries = {
			{true,0,1} : create_with_true_%s(0b00000000000000000000000000000001);
			{true,1,1} : create_with_true_%s(0b00000000000000000000000000000010);
			{true,2,1} : create_with_true_%s(0b00000000000000000000000000000100);
			{true,3,1} : create_with_true_%s(0b00000000000000000000000000001000);
			{true,4,1} : create_with_true_%s(0b00000000000000000000000000010000);
			{true,5,1} : create_with_true_%s(0b00000000000000000000000000100000);
			{true,6,1} : create_with_true_%s(0b00000000000000000000000001000000);
			{true,7,1} : create_with_true_%s(0b00000000000000000000000010000000);
			{true,8,1} : create_with_true_%s(0b00000000000000000000000100000000);
			{true,9,1} : create_with_true_%s(0b00000000000000000000001000000000);
			{true,10,1} : create_with_true_%s(0b00000000000000000000010000000000);
			{true,11,1} : create_with_true_%s(0b00000000000000000000100000000000);
			{true,12,1} : create_with_true_%s(0b00000000000000000001000000000000);
			{true,13,1} : create_with_true_%s(0b00000000000000000010000000000000);
			{true,14,1} : create_with_true_%s(0b00000000000000000100000000000000);
			{true,15,1} : create_with_true_%s(0b00000000000000001000000000000000);
			{true,16,1} : create_with_true_%s(0b00000000000000010000000000000000);
			{true,17,1} : create_with_true_%s(0b00000000000000100000000000000000);
			{true,18,1} : create_with_true_%s(0b00000000000001000000000000000000);
			{true,19,1} : create_with_true_%s(0b00000000000010000000000000000000);
			{true,20,1} : create_with_true_%s(0b00000000000100000000000000000000);
			{true,21,1} : create_with_true_%s(0b00000000001000000000000000000000);
			{true,22,1} : create_with_true_%s(0b00000000010000000000000000000000);
			{true,23,1} : create_with_true_%s(0b00000000100000000000000000000000);
			{true,24,1} : create_with_true_%s(0b00000001000000000000000000000000);
			{true,25,1} : create_with_true_%s(0b00000010000000000000000000000000);
			{true,26,1} : create_with_true_%s(0b00000100000000000000000000000000);
			{true,27,1} : create_with_true_%s(0b00001000000000000000000000000000);
			{true,28,1} : create_with_true_%s(0b00010000000000000000000000000000);
			{true,29,1} : create_with_true_%s(0b00100000000000000000000000000000);
			{true,30,1} : create_with_true_%s(0b01000000000000000000000000000000);
			{true,31,1} : create_with_true_%s(0b10000000000000000000000000000000);
			{false,0,1} : create_with_false_%s(0b11111111111111111111111111111110);
			{false,1,1} : create_with_false_%s(0b11111111111111111111111111111101);
			{false,2,1} : create_with_false_%s(0b11111111111111111111111111111011);
			{false,3,1} : create_with_false_%s(0b11111111111111111111111111110111);
			{false,4,1} : create_with_false_%s(0b11111111111111111111111111101111);
			{false,5,1} : create_with_false_%s(0b11111111111111111111111111011111);
			{false,6,1} : create_with_false_%s(0b11111111111111111111111110111111);
			{false,7,1} : create_with_false_%s(0b11111111111111111111111101111111);
			{false,8,1} : create_with_false_%s(0b11111111111111111111111011111111);
			{false,9,1} : create_with_false_%s(0b11111111111111111111110111111111);
			{false,10,1} : create_with_false_%s(0b11111111111111111111101111111111);
			{false,11,1} : create_with_false_%s(0b11111111111111111111011111111111);
			{false,12,1} : create_with_false_%s(0b11111111111111111110111111111111);
			{false,13,1} : create_with_false_%s(0b11111111111111111101111111111111);
			{false,14,1} : create_with_false_%s(0b11111111111111111011111111111111);
			{false,15,1} : create_with_false_%s(0b11111111111111110111111111111111);
			{false,16,1} : create_with_false_%s(0b11111111111111101111111111111111);
			{false,17,1} : create_with_false_%s(0b11111111111111011111111111111111);
			{false,18,1} : create_with_false_%s(0b11111111111110111111111111111111);
			{false,19,1} : create_with_false_%s(0b11111111111101111111111111111111);
			{false,20,1} : create_with_false_%s(0b11111111111011111111111111111111);
			{false,21,1} : create_with_false_%s(0b11111111110111111111111111111111);
			{false,22,1} : create_with_false_%s(0b11111111101111111111111111111111);
			{false,23,1} : create_with_false_%s(0b11111111011111111111111111111111);
			{false,24,1} : create_with_false_%s(0b11111110111111111111111111111111);
			{false,25,1} : create_with_false_%s(0b11111101111111111111111111111111);
			{false,26,1} : create_with_false_%s(0b11111011111111111111111111111111);
			{false,27,1} : create_with_false_%s(0b11110111111111111111111111111111);
			{false,28,1} : create_with_false_%s(0b11101111111111111111111111111111);
			{false,29,1} : create_with_false_%s(0b11011111111111111111111111111111);
			{false,30,1} : create_with_false_%s(0b10111111111111111111111111111111);
			{false,31,1} : create_with_false_%s(0b01111111111111111111111111111111);
		}
	}
''' % (str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
       str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1))
table_counter = 1
for k in range(options.maxconj):
    subtraction_table_calls = subtraction_table_calls + "\t\t\tsubtract_table_%s.apply();\n\t\t\tsubtract_table_upper_%s.apply();\n" % (
        table_counter, table_counter)
    subtraction_tables = subtraction_tables + '''
        action subtraction_%s(){
            ig_md.toCheck_%s = ig_md.disj_value_%s - ig_md.sensorValue_copy_%s;
        }
    
        table subtract_table_%s{
            actions = {
                subtraction_%s;
            }
            key = {
                ig_md.disj_op_%s: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_%s();
                {2} : subtraction_%s();
                {3} : subtraction_%s();
                {4} : subtraction_%s();
            }
        }

		action subtraction_upper_%s(){
            ig_md.upper_bound_%s = ig_md.upper_bound_%s - ig_md.sensorValue_copy_%s;
        }
		
		table subtract_table_upper_%s{
            actions = {
                subtraction_upper_%s;
            }
            key = {
                ig_md.disj_op_%s: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_%s();
            }
        }
    ''' % (
        k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1,
        k + 1, k + 1, k + 1)

    call_evals = call_evals + '''
            if(ig_md.disj_op_%s == 1 || ig_md.disj_op_%s == 5)
            {
                eval_greater_disj_%s.apply();
                
            }
            else if(ig_md.disj_op_%s == 2)
            {
                eval_smaller_disj_%s.apply();
            }
            else if(ig_md.disj_op_%s == 3 || ig_md.disj_op_%s == 0)
            {
                eval_equal_disj_%s.apply();
            }
            else if(ig_md.disj_op_%s == 4)
            {
                eval_not_equal_disj_%s.apply();
            }
            if(ig_md.disj_op_%s == 5 && ig_md.disj_%s)
            {
            eval_range_disj_%s.apply();
            }
                
    ''' % (k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1, k + 1)
    evaluation_tables = evaluation_tables + '''
        action set_disj_%s_true(){
            ig_md.disj_%s = true;
        }
        
        action set_disj_%s_false(){
            ig_md.disj_%s = false;
        }

        action and_disj_%s(bool upper){
            ig_md.disj_%s = upper;
        }
        
        table eval_greater_disj_%s{
            actions = {
                set_disj_%s_true;
                set_disj_%s_false;
            }
            key = {
                ig_md.toCheck_%s : ternary;
            }
            size = 2;
            const default_action = set_disj_%s_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_%s_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_%s_false();
            }
        }
    
        table eval_smaller_disj_%s{
            actions = {
                set_disj_%s_true;
                set_disj_%s_false;
            }
            key = {
                ig_md.toCheck_%s : ternary;
            }
            size = 2;
            const default_action = set_disj_%s_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_%s_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_%s_true();
            }
        }
    
        table eval_equal_disj_%s{
            actions = {
                set_disj_%s_true;
                set_disj_%s_false;
            }
            key = {
                ig_md.toCheck_%s : exact;
            }
            size = 1;
            const default_action = set_disj_%s_false;
            const entries = {
                0 : set_disj_%s_true();
            }
        }
    
        table eval_not_equal_disj_%s{
            actions = {
                set_disj_%s_true;
                set_disj_%s_false;
            }
            key = {
                ig_md.toCheck_%s : exact;
            }
            size = 1;
            const default_action = set_disj_%s_true;
            const entries = {
                0 : set_disj_%s_false();
            }
        }

        table eval_range_disj_%s{
            actions = {
                and_disj_%s;
            }
            key = {
				ig_md.upper_bound_%s : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_%s(true);
            }
        }
    ''' % (str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
           str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
           str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1),
           str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1), str(k + 1))
    sum_disj_keys = sum_disj_keys + "\t\t\tig_md.disj_%s: exact;\n" % str(k + 1)
    if (k + 1 == options.maxconj):
        sum_disj_entry = sum_disj_entry + "true"
    else:
        sum_disj_entry = sum_disj_entry + "true, "
    table_counter = table_counter + 1

sum_conj_table_2 = ""
sum_conj_2_call = ""

sum_conj_table_3 = ""
sum_conj_3_call = ""

if options.maxconj > 4:
    sum_conj_2_call = "\t\t\tsum_conj_2.apply();\n"
    sum_conj_2_keys = ""
    sum_conj_2_entry = ""
    for i in range(5, min(options.maxconj + 1, 7)):
        sum_conj_2_keys += "\t\t\tig_md.disj_%s: exact;\n" % (i)
        sum_conj_2_entry += ", true"
    sum_conj_table_2 = """
	table sum_conj_2{
		actions = {
			sum_conj_set_true;
			sum_conj_set_false;
		}
		key = {
			ig_md.summed_conj: exact;
%s

		}
		size = 1;
		const default_action = sum_conj_set_false;
		const entries = {
			{true%s} : sum_conj_set_true();
		}
	}
""" % (sum_conj_2_keys, sum_conj_2_entry)

if options.maxconj > 7:
    sum_conj_3_call = "\t\t\tsum_conj_3.apply();\n"
    sum_conj_3_keys = ""
    sum_conj_3_entry = ""
    for i in range(7, options.maxconj + 1):
        sum_conj_3_keys += "\t\t\tig_md.disj_%s: exact;\n" % (i)
        sum_conj_3_entry += ", true"
    sum_conj_table_3 = """
	table sum_conj_3{
		actions = {
			sum_conj_set_true;
			sum_conj_set_false;
		}
		key = {
			ig_md.summed_conj: exact;
%s

		}
		size = 1;
		const default_action = sum_conj_set_false;
		const entries = {
			{true%s} : sum_conj_set_true();
		}
	}
""" % (sum_conj_3_keys, sum_conj_3_entry)
# subtract_table.apply();

s = s.replace("<HASH_ACTION>", hash_action)
s = s.replace("<HISTORY_REGISTERS>", register_declarations)
s = s.replace("<NEW_MAP_TABLE_CALLS>", new_map_table_calls)
s = s.replace("<MAP_REGISTERS>", map_register_declarations)
s = s.replace("<HISTORY_REGISTER_ACTIONS>", register_actions)
s = s.replace("<REGISTER_CALLS>", register_calls)
s = s.replace("<CONJ_TABLES>", conjuntion_tables)
s = s.replace("<NEW_MAP_TABLES>", new_map_tables)
s = s.replace("<CONJ_TABLE_CALLS>", conjuntion_table_calls)
s = s.replace("<DISJ_BOOL_INIT>", disjuntion_bool_inits)
s = s.replace("<SUBTRACTION_TABLES>", subtraction_tables)
s = s.replace("<SUBTRACT_TABLE_CALLS>", subtraction_table_calls)
s = s.replace("<SUM_DISJ_KEYS>", sum_disj_keys)
s = s.replace("<SUM_DISJ_ENTRY>", sum_disj_entry)
s = s.replace("<EVALUATION_TABLES>", evaluation_tables)
s = s.replace("<CALL_EVALS>", call_evals)
s = s.replace("<MAP_REGISTER_ACTIONS>", map_register_actions)
s = s.replace("<CHECK_DISJ_MAP_TABLES>", check_disj_map_tables)
s = s.replace("<STORE_DISJ_MAP_TABLES>", store_disj_map_tables)
s = s.replace("<SUM_CONJ_ENTRY>", sum_conj_entry)
s = s.replace("<SUM_CONJ_KEYS>", sum_conj_keys)
s = s.replace("<SUM_CONJ_2_TABLE>", sum_conj_table_2)
s = s.replace("<SUM_CONJ_2_CALL>", sum_conj_2_call)
s = s.replace("<SUM_CONJ_3_TABLE>", sum_conj_table_3)
s = s.replace("<SUM_CONJ_3_CALL>", sum_conj_3_call)
s = s.replace("<DUMMY_TABLES>", dummy_tables)
s = s.replace("<DUMMY_TABLE_CALLS>", dummy_table_calls)
s = s.replace("<STORE_DISJ_MAP_TABLE_CALLS>", store_disj_map_table_calls)
s = s.replace("<CHECK_DISJ_MAP_TABLE_CALLS>", check_disj_map_table_calls)
with open(p4output, 'w') as wf:
    wf.write(s)
