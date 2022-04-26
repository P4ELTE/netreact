
p4 = bfrt.test2.pipe

p4.SwitchIngress.conj_table_1.add_with_set_conj_value_1(
                97,
                conj_v=0,
                disj_op = 1
                disj_v = 12)

p4.SwitchIngress.conj_table_2.add_with_set_conj_value_2(
                99,
                conj_v=0,
                disj_op = 2
                disj_v = 20)

p4.SwitchIngress.conj_table_1.add_with_set_conj_value_1(
                99,
                conj_v=0,
                disj_op = 4
                disj_v = 10)

p4.SwitchIngress.conj_table_2.add_with_set_conj_value_2(
                97,
                conj_v=0,
                disj_op = 3
                disj_v = 1)

