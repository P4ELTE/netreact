
p4 = bfrt.test2.pipe

p4.SwitchIngress.conj_table_1.add_with_set_conj_value_1(
                100,
                conj_v=2,
                disj_op = 3
                disj_v = 10)

p4.SwitchIngress.conj_table_2.add_with_set_conj_value_2(
                100,
                conj_v=2,
                disj_op = 0
                disj_v = 0
                upper_bound = 0)

p4.SwitchIngress.conj_table_2.add_with_set_conj_value_2(
                101,
                conj_v=2,
                disj_op = 0
                disj_v = 0
                upper_bound = 0)

p4.SwitchIngress.conj_table_1.add_with_set_conj_value_1(
                101,
                conj_v=2,
                disj_op = 4
                disj_v = 10)

p4.SwitchIngress.conj_table_2.add_with_set_conj_value_2(
                100,
                conj_v=2,
                disj_op = 0
                disj_v = 0
                upper_bound = 0)

p4.SwitchIngress.conj_table_2.add_with_set_conj_value_2(
                101,
                conj_v=2,
                disj_op = 0
                disj_v = 0
                upper_bound = 0)

