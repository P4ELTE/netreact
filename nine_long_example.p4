#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define SENSOR_COUNT 1000
#define HISTORY_SIZE 5


// HEADERS AND TYPES ************************************************************

header ethernet_t {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<1> _reserved;
    bit<1> dont_fragment;
    bit<1> more_fragments;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> csum;
}

header sensor_t {
	bit<32> sensorId;
	bit<32> sensorValue;
}

// #meta
struct ingress_metadata_t {
	bit<32> historical_value;
	bit<32> new_map;

	bit<32> conj_value_1;
	bit<32> disj_value_1;
	bit<32> disj_map_1;
	bit<32> upper_bound_1;

	bit<32> conj_value_2;
	bit<32> disj_value_2;
	bit<32> disj_map_2;
	bit<32> upper_bound_2;

	bit<32> conj_value_3;
	bit<32> disj_value_3;
	bit<32> disj_map_3;
	bit<32> upper_bound_3;

	bit<32> conj_value_4;
	bit<32> disj_value_4;
	bit<32> disj_map_4;
	bit<32> upper_bound_4;

	bit<32> conj_value_5;
	bit<32> disj_value_5;
	bit<32> disj_map_5;
	bit<32> upper_bound_5;

	bit<32> conj_value_6;
	bit<32> disj_value_6;
	bit<32> disj_map_6;
	bit<32> upper_bound_6;

	bit<32> conj_value_7;
	bit<32> disj_value_7;
	bit<32> disj_map_7;
	bit<32> upper_bound_7;

	bit<32> conj_value_8;
	bit<32> disj_value_8;
	bit<32> disj_map_8;
	bit<32> upper_bound_8;

	bit<32> conj_value_9;
	bit<32> disj_value_9;
	bit<32> disj_map_9;
	bit<32> upper_bound_9;

	bit<32> disj_op_1;
	bool disj_1;
	bit<32> toCheck_1;
	bit<32> sensorValue_copy_1;
	bit<32> disj_op_2;
	bool disj_2;
	bit<32> toCheck_2;
	bit<32> sensorValue_copy_2;
	bit<32> disj_op_3;
	bool disj_3;
	bit<32> toCheck_3;
	bit<32> sensorValue_copy_3;
	bit<32> disj_op_4;
	bool disj_4;
	bit<32> toCheck_4;
	bit<32> sensorValue_copy_4;
	bit<32> disj_op_5;
	bool disj_5;
	bit<32> toCheck_5;
	bit<32> sensorValue_copy_5;
	bit<32> disj_op_6;
	bool disj_6;
	bit<32> toCheck_6;
	bit<32> sensorValue_copy_6;
	bit<32> disj_op_7;
	bool disj_7;
	bit<32> toCheck_7;
	bit<32> sensorValue_copy_7;
	bit<32> disj_op_8;
	bool disj_8;
	bit<32> toCheck_8;
	bit<32> sensorValue_copy_8;
	bit<32> disj_op_9;
	bool disj_9;
	bit<32> toCheck_9;
	bit<32> sensorValue_copy_9;



	
	bool summed_conj;
}

struct egress_metadata_t {
}


struct header_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
	sensor_t sensor;
}

// INGRESS ************************************************************

parser TofinoIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            0 : parse_port_metadata;
        }
    }

    state parse_port_metadata {
#if __TARGET_TOFINO__ == 2
        pkt.advance(192);
#else
        pkt.advance(64);
#endif
        transition accept;
    }
}


parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }

}


parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {


    TofinoIngressParser() tofino_parser;
	
    state start {
	    tofino_parser.apply(pkt, hdr, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            //6: parse_tcp;
            17: parse_udp;
            default: accept; 
        } 
    }

    state parse_udp{
        pkt.extract(hdr.udp);
        pkt.extract(hdr.sensor);
		transition accept;
    }

}

control SwitchIngress(
        inout header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

	Register<bit<32>,bit<32>>(SENSOR_COUNT) map_register_1;
	Register<bit<32>,bit<32>>(SENSOR_COUNT) map_register_2;
	Register<bit<32>,bit<32>>(SENSOR_COUNT) map_register_3;
	Register<bit<32>,bit<32>>(SENSOR_COUNT) map_register_4;


	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_1;
	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_2;
	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_3;
	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_4;
	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_5;
	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_6;
	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_7;
	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_8;
	Register<bit<32>,bit<32>>(SENSOR_COUNT*2) disj_map_register_9;


Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash;

	action copy1(){
		ig_md.sensorValue_copy_1 = identity_hash.get(hdr.sensor.sensorValue);
		ig_md.sensorValue_copy_2 = identity_hash.get(hdr.sensor.sensorValue);
		ig_md.sensorValue_copy_3 = identity_hash.get(hdr.sensor.sensorValue);
		ig_md.sensorValue_copy_4 = identity_hash.get(hdr.sensor.sensorValue);
		ig_md.sensorValue_copy_5 = identity_hash.get(hdr.sensor.sensorValue);
		ig_md.sensorValue_copy_6 = identity_hash.get(hdr.sensor.sensorValue);
		ig_md.sensorValue_copy_7 = identity_hash.get(hdr.sensor.sensorValue);
		ig_md.sensorValue_copy_8 = identity_hash.get(hdr.sensor.sensorValue);
		ig_md.sensorValue_copy_9 = identity_hash.get(hdr.sensor.sensorValue);

	}
	
	table assign_data {
        actions = { copy1; }
        const default_action = copy1();
    }


	RegisterAction<bit<32>,_,bit<32>>(map_register_1) get_map_1 = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            result = register_data;
            register_data = hdr.sensor.sensorValue;
        }
    };
	RegisterAction<bit<32>,_,bit<32>>(map_register_2) get_map_2 = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            result = register_data;
            register_data = ig_md.historical_value;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(map_register_3) get_map_3 = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            result = register_data;
            register_data = ig_md.historical_value;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(map_register_4) get_map_4 = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            result = register_data;
            register_data = ig_md.historical_value;
        }
    };





	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_1) set_disj_map_1_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_1;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_1) set_disj_map_1_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_1;
            result = register_data;
        }
    };


	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_2) set_disj_map_2_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_2;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_2) set_disj_map_2_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_2;
            result = register_data;
        }
    };


	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_3) set_disj_map_3_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_3;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_3) set_disj_map_3_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_3;
            result = register_data;
        }
    };


	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_4) set_disj_map_4_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_4;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_4) set_disj_map_4_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_4;
            result = register_data;
        }
    };


	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_5) set_disj_map_5_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_5;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_5) set_disj_map_5_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_5;
            result = register_data;
        }
    };


	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_6) set_disj_map_6_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_6;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_6) set_disj_map_6_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_6;
            result = register_data;
        }
    };


	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_7) set_disj_map_7_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_7;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_7) set_disj_map_7_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_7;
            result = register_data;
        }
    };


	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_8) set_disj_map_8_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_8;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_8) set_disj_map_8_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_8;
            result = register_data;
        }
    };


	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_9) set_disj_map_9_register_false = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data & ig_md.disj_map_9;
            result = register_data;
        }
    };

	RegisterAction<bit<32>,_,bit<32>>(disj_map_register_9) set_disj_map_9_register_true = {
    void apply(inout bit<32> register_data,  out bit<32> result){
            register_data = register_data | ig_md.disj_map_9;
            result = register_data;
        }
    };



	
	Lpf<bit<32>, bit<32>>(size=SENSOR_COUNT) lpf_1;
	
	bit<32> lpf_input;
	bit<32> lpf_output_1;





	action set_conj_value_1(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_1 = conj_v;
        ig_md.disj_op_1 = disj_op;
        ig_md.disj_value_1 = disj_v;
		ig_md.upper_bound_1 = upper_bound;
	}

	table conj_table_1{
    actions = {
            set_conj_value_1;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_1(0,0,0,0);
        const entries = {
            {0} : set_conj_value_1(3,100,2,0);
            {1} : set_conj_value_1(1,400,2,0);
		}
	}

	action set_conj_value_2(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_2 = conj_v;
        ig_md.disj_op_2 = disj_op;
        ig_md.disj_value_2 = disj_v;
		ig_md.upper_bound_2 = upper_bound;
	}

	table conj_table_2{
    actions = {
            set_conj_value_2;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_2(0,0,0,0);
        const entries = {
            {0} : set_conj_value_2(3,100,2,0);
            {1} : set_conj_value_2(1,400,2,0);
		}
	}

	action set_conj_value_3(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_3 = conj_v;
        ig_md.disj_op_3 = disj_op;
        ig_md.disj_value_3 = disj_v;
		ig_md.upper_bound_3 = upper_bound;
	}

	table conj_table_3{
    actions = {
            set_conj_value_3;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_3(0,0,0,0);
        const entries = {
            {0} : set_conj_value_3(3,100,2,0);
            {1} : set_conj_value_3(1,400,2,0);
		}
	}

	action set_conj_value_4(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_4 = conj_v;
        ig_md.disj_op_4 = disj_op;
        ig_md.disj_value_4 = disj_v;
		ig_md.upper_bound_4 = upper_bound;
	}

	table conj_table_4{
    actions = {
            set_conj_value_4;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_4(0,0,0,0);
        const entries = {
            {0} : set_conj_value_4(3,100,2,0);
            {1} : set_conj_value_4(1,400,2,0);
		}
	}

	action set_conj_value_5(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_5 = conj_v;
        ig_md.disj_op_5 = disj_op;
        ig_md.disj_value_5 = disj_v;
		ig_md.upper_bound_5 = upper_bound;
	}

	table conj_table_5{
    actions = {
            set_conj_value_5;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_5(0,0,0,0);
        const entries = {
            {0} : set_conj_value_5(3,100,2,0);
            {1} : set_conj_value_5(1,400,2,0);
		}
	}

	action set_conj_value_6(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_6 = conj_v;
        ig_md.disj_op_6 = disj_op;
        ig_md.disj_value_6 = disj_v;
		ig_md.upper_bound_6 = upper_bound;
	}

	table conj_table_6{
    actions = {
            set_conj_value_6;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_6(0,0,0,0);
        const entries = {
            {0} : set_conj_value_6(3,100,2,0);
            {1} : set_conj_value_6(1,400,2,0);
		}
	}

	action set_conj_value_7(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_7 = conj_v;
        ig_md.disj_op_7 = disj_op;
        ig_md.disj_value_7 = disj_v;
		ig_md.upper_bound_7 = upper_bound;
	}

	table conj_table_7{
    actions = {
            set_conj_value_7;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_7(0,0,0,0);
        const entries = {
            {0} : set_conj_value_7(3,100,2,0);
            {1} : set_conj_value_7(1,400,2,0);
		}
	}

	action set_conj_value_8(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_8 = conj_v;
        ig_md.disj_op_8 = disj_op;
        ig_md.disj_value_8 = disj_v;
		ig_md.upper_bound_8 = upper_bound;
	}

	table conj_table_8{
    actions = {
            set_conj_value_8;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_8(0,0,0,0);
        const entries = {
            {0} : set_conj_value_8(3,100,2,0);
            {1} : set_conj_value_8(1,400,2,0);
		}
	}

	action set_conj_value_9(bit<32> conj_v, bit<32> disj_v, bit<32> disj_op, bit<32> upper_bound){
		ig_md.conj_value_9 = conj_v;
        ig_md.disj_op_9 = disj_op;
        ig_md.disj_value_9 = disj_v;
		ig_md.upper_bound_9 = upper_bound;
	}

	table conj_table_9{
    actions = {
            set_conj_value_9;
        }
        key = {
            hdr.sensor.sensorId: exact;
        }
        size = SENSOR_COUNT;
        const default_action = set_conj_value_9(0,0,0,0);
        const entries = {
            {0} : set_conj_value_9(3,100,2,0);
            {1} : set_conj_value_9(1,400,2,0);
		}
	}




        action subtraction_1(){
            ig_md.toCheck_1 = ig_md.disj_value_1 - ig_md.sensorValue_copy_1;
        }
    
        table subtract_table_1{
            actions = {
                subtraction_1;
            }
            key = {
                ig_md.disj_op_1: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_1();
                {2} : subtraction_1();
                {3} : subtraction_1();
                {4} : subtraction_1();
            }
        }

		action subtraction_upper_1(){
            ig_md.upper_bound_1 = ig_md.upper_bound_1 - ig_md.sensorValue_copy_1;
        }
		
		table subtract_table_upper_1{
            actions = {
                subtraction_upper_1;
            }
            key = {
                ig_md.disj_op_1: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_1();
            }
        }
    
        action subtraction_2(){
            ig_md.toCheck_2 = ig_md.disj_value_2 - ig_md.sensorValue_copy_2;
        }
    
        table subtract_table_2{
            actions = {
                subtraction_2;
            }
            key = {
                ig_md.disj_op_2: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_2();
                {2} : subtraction_2();
                {3} : subtraction_2();
                {4} : subtraction_2();
            }
        }

		action subtraction_upper_2(){
            ig_md.upper_bound_2 = ig_md.upper_bound_2 - ig_md.sensorValue_copy_2;
        }
		
		table subtract_table_upper_2{
            actions = {
                subtraction_upper_2;
            }
            key = {
                ig_md.disj_op_2: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_2();
            }
        }
    
        action subtraction_3(){
            ig_md.toCheck_3 = ig_md.disj_value_3 - ig_md.sensorValue_copy_3;
        }
    
        table subtract_table_3{
            actions = {
                subtraction_3;
            }
            key = {
                ig_md.disj_op_3: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_3();
                {2} : subtraction_3();
                {3} : subtraction_3();
                {4} : subtraction_3();
            }
        }

		action subtraction_upper_3(){
            ig_md.upper_bound_3 = ig_md.upper_bound_3 - ig_md.sensorValue_copy_3;
        }
		
		table subtract_table_upper_3{
            actions = {
                subtraction_upper_3;
            }
            key = {
                ig_md.disj_op_3: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_3();
            }
        }
    
        action subtraction_4(){
            ig_md.toCheck_4 = ig_md.disj_value_4 - ig_md.sensorValue_copy_4;
        }
    
        table subtract_table_4{
            actions = {
                subtraction_4;
            }
            key = {
                ig_md.disj_op_4: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_4();
                {2} : subtraction_4();
                {3} : subtraction_4();
                {4} : subtraction_4();
            }
        }

		action subtraction_upper_4(){
            ig_md.upper_bound_4 = ig_md.upper_bound_4 - ig_md.sensorValue_copy_4;
        }
		
		table subtract_table_upper_4{
            actions = {
                subtraction_upper_4;
            }
            key = {
                ig_md.disj_op_4: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_4();
            }
        }
    
        action subtraction_5(){
            ig_md.toCheck_5 = ig_md.disj_value_5 - ig_md.sensorValue_copy_5;
        }
    
        table subtract_table_5{
            actions = {
                subtraction_5;
            }
            key = {
                ig_md.disj_op_5: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_5();
                {2} : subtraction_5();
                {3} : subtraction_5();
                {4} : subtraction_5();
            }
        }

		action subtraction_upper_5(){
            ig_md.upper_bound_5 = ig_md.upper_bound_5 - ig_md.sensorValue_copy_5;
        }
		
		table subtract_table_upper_5{
            actions = {
                subtraction_upper_5;
            }
            key = {
                ig_md.disj_op_5: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_5();
            }
        }
    
        action subtraction_6(){
            ig_md.toCheck_6 = ig_md.disj_value_6 - ig_md.sensorValue_copy_6;
        }
    
        table subtract_table_6{
            actions = {
                subtraction_6;
            }
            key = {
                ig_md.disj_op_6: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_6();
                {2} : subtraction_6();
                {3} : subtraction_6();
                {4} : subtraction_6();
            }
        }

		action subtraction_upper_6(){
            ig_md.upper_bound_6 = ig_md.upper_bound_6 - ig_md.sensorValue_copy_6;
        }
		
		table subtract_table_upper_6{
            actions = {
                subtraction_upper_6;
            }
            key = {
                ig_md.disj_op_6: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_6();
            }
        }
    
        action subtraction_7(){
            ig_md.toCheck_7 = ig_md.disj_value_7 - ig_md.sensorValue_copy_7;
        }
    
        table subtract_table_7{
            actions = {
                subtraction_7;
            }
            key = {
                ig_md.disj_op_7: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_7();
                {2} : subtraction_7();
                {3} : subtraction_7();
                {4} : subtraction_7();
            }
        }

		action subtraction_upper_7(){
            ig_md.upper_bound_7 = ig_md.upper_bound_7 - ig_md.sensorValue_copy_7;
        }
		
		table subtract_table_upper_7{
            actions = {
                subtraction_upper_7;
            }
            key = {
                ig_md.disj_op_7: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_7();
            }
        }
    
        action subtraction_8(){
            ig_md.toCheck_8 = ig_md.disj_value_8 - ig_md.sensorValue_copy_8;
        }
    
        table subtract_table_8{
            actions = {
                subtraction_8;
            }
            key = {
                ig_md.disj_op_8: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_8();
                {2} : subtraction_8();
                {3} : subtraction_8();
                {4} : subtraction_8();
            }
        }

		action subtraction_upper_8(){
            ig_md.upper_bound_8 = ig_md.upper_bound_8 - ig_md.sensorValue_copy_8;
        }
		
		table subtract_table_upper_8{
            actions = {
                subtraction_upper_8;
            }
            key = {
                ig_md.disj_op_8: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_8();
            }
        }
    
        action subtraction_9(){
            ig_md.toCheck_9 = ig_md.disj_value_9 - ig_md.sensorValue_copy_9;
        }
    
        table subtract_table_9{
            actions = {
                subtraction_9;
            }
            key = {
                ig_md.disj_op_9: exact;
            }
            size = 4;
            const entries = {
                {1} : subtraction_9();
                {2} : subtraction_9();
                {3} : subtraction_9();
                {4} : subtraction_9();
            }
        }

		action subtraction_upper_9(){
            ig_md.upper_bound_9 = ig_md.upper_bound_9 - ig_md.sensorValue_copy_9;
        }
		
		table subtract_table_upper_9{
            actions = {
                subtraction_upper_9;
            }
            key = {
                ig_md.disj_op_9: exact;
            }
            size = 1;
            const entries = {
                {5} : subtraction_upper_9();
            }
        }
    


        action set_disj_1_true(){
            ig_md.disj_1 = true;
        }
        
        action set_disj_1_false(){
            ig_md.disj_1 = false;
        }

        action and_disj_1(bool upper){
            ig_md.disj_1 = upper;
        }
        
        table eval_greater_disj_1{
            actions = {
                set_disj_1_true;
                set_disj_1_false;
            }
            key = {
                ig_md.toCheck_1 : ternary;
            }
            size = 2;
            const default_action = set_disj_1_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_1_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_1_false();
            }
        }
    
        table eval_smaller_disj_1{
            actions = {
                set_disj_1_true;
                set_disj_1_false;
            }
            key = {
                ig_md.toCheck_1 : ternary;
            }
            size = 2;
            const default_action = set_disj_1_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_1_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_1_true();
            }
        }
    
        table eval_equal_disj_1{
            actions = {
                set_disj_1_true;
                set_disj_1_false;
            }
            key = {
                ig_md.toCheck_1 : exact;
            }
            size = 1;
            const default_action = set_disj_1_false;
            const entries = {
                0 : set_disj_1_true();
            }
        }
    
        table eval_not_equal_disj_1{
            actions = {
                set_disj_1_true;
                set_disj_1_false;
            }
            key = {
                ig_md.toCheck_1 : exact;
            }
            size = 1;
            const default_action = set_disj_1_true;
            const entries = {
                0 : set_disj_1_false();
            }
        }

        table eval_range_disj_1{
            actions = {
                and_disj_1;
            }
            key = {
				ig_md.upper_bound_1 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_1(true);
            }
        }
    
        action set_disj_2_true(){
            ig_md.disj_2 = true;
        }
        
        action set_disj_2_false(){
            ig_md.disj_2 = false;
        }

        action and_disj_2(bool upper){
            ig_md.disj_2 = upper;
        }
        
        table eval_greater_disj_2{
            actions = {
                set_disj_2_true;
                set_disj_2_false;
            }
            key = {
                ig_md.toCheck_2 : ternary;
            }
            size = 2;
            const default_action = set_disj_2_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_2_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_2_false();
            }
        }
    
        table eval_smaller_disj_2{
            actions = {
                set_disj_2_true;
                set_disj_2_false;
            }
            key = {
                ig_md.toCheck_2 : ternary;
            }
            size = 2;
            const default_action = set_disj_2_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_2_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_2_true();
            }
        }
    
        table eval_equal_disj_2{
            actions = {
                set_disj_2_true;
                set_disj_2_false;
            }
            key = {
                ig_md.toCheck_2 : exact;
            }
            size = 1;
            const default_action = set_disj_2_false;
            const entries = {
                0 : set_disj_2_true();
            }
        }
    
        table eval_not_equal_disj_2{
            actions = {
                set_disj_2_true;
                set_disj_2_false;
            }
            key = {
                ig_md.toCheck_2 : exact;
            }
            size = 1;
            const default_action = set_disj_2_true;
            const entries = {
                0 : set_disj_2_false();
            }
        }

        table eval_range_disj_2{
            actions = {
                and_disj_2;
            }
            key = {
				ig_md.upper_bound_2 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_2(true);
            }
        }
    
        action set_disj_3_true(){
            ig_md.disj_3 = true;
        }
        
        action set_disj_3_false(){
            ig_md.disj_3 = false;
        }

        action and_disj_3(bool upper){
            ig_md.disj_3 = upper;
        }
        
        table eval_greater_disj_3{
            actions = {
                set_disj_3_true;
                set_disj_3_false;
            }
            key = {
                ig_md.toCheck_3 : ternary;
            }
            size = 2;
            const default_action = set_disj_3_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_3_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_3_false();
            }
        }
    
        table eval_smaller_disj_3{
            actions = {
                set_disj_3_true;
                set_disj_3_false;
            }
            key = {
                ig_md.toCheck_3 : ternary;
            }
            size = 2;
            const default_action = set_disj_3_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_3_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_3_true();
            }
        }
    
        table eval_equal_disj_3{
            actions = {
                set_disj_3_true;
                set_disj_3_false;
            }
            key = {
                ig_md.toCheck_3 : exact;
            }
            size = 1;
            const default_action = set_disj_3_false;
            const entries = {
                0 : set_disj_3_true();
            }
        }
    
        table eval_not_equal_disj_3{
            actions = {
                set_disj_3_true;
                set_disj_3_false;
            }
            key = {
                ig_md.toCheck_3 : exact;
            }
            size = 1;
            const default_action = set_disj_3_true;
            const entries = {
                0 : set_disj_3_false();
            }
        }

        table eval_range_disj_3{
            actions = {
                and_disj_3;
            }
            key = {
				ig_md.upper_bound_3 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_3(true);
            }
        }
    
        action set_disj_4_true(){
            ig_md.disj_4 = true;
        }
        
        action set_disj_4_false(){
            ig_md.disj_4 = false;
        }

        action and_disj_4(bool upper){
            ig_md.disj_4 = upper;
        }
        
        table eval_greater_disj_4{
            actions = {
                set_disj_4_true;
                set_disj_4_false;
            }
            key = {
                ig_md.toCheck_4 : ternary;
            }
            size = 2;
            const default_action = set_disj_4_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_4_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_4_false();
            }
        }
    
        table eval_smaller_disj_4{
            actions = {
                set_disj_4_true;
                set_disj_4_false;
            }
            key = {
                ig_md.toCheck_4 : ternary;
            }
            size = 2;
            const default_action = set_disj_4_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_4_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_4_true();
            }
        }
    
        table eval_equal_disj_4{
            actions = {
                set_disj_4_true;
                set_disj_4_false;
            }
            key = {
                ig_md.toCheck_4 : exact;
            }
            size = 1;
            const default_action = set_disj_4_false;
            const entries = {
                0 : set_disj_4_true();
            }
        }
    
        table eval_not_equal_disj_4{
            actions = {
                set_disj_4_true;
                set_disj_4_false;
            }
            key = {
                ig_md.toCheck_4 : exact;
            }
            size = 1;
            const default_action = set_disj_4_true;
            const entries = {
                0 : set_disj_4_false();
            }
        }

        table eval_range_disj_4{
            actions = {
                and_disj_4;
            }
            key = {
				ig_md.upper_bound_4 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_4(true);
            }
        }
    
        action set_disj_5_true(){
            ig_md.disj_5 = true;
        }
        
        action set_disj_5_false(){
            ig_md.disj_5 = false;
        }

        action and_disj_5(bool upper){
            ig_md.disj_5 = upper;
        }
        
        table eval_greater_disj_5{
            actions = {
                set_disj_5_true;
                set_disj_5_false;
            }
            key = {
                ig_md.toCheck_5 : ternary;
            }
            size = 2;
            const default_action = set_disj_5_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_5_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_5_false();
            }
        }
    
        table eval_smaller_disj_5{
            actions = {
                set_disj_5_true;
                set_disj_5_false;
            }
            key = {
                ig_md.toCheck_5 : ternary;
            }
            size = 2;
            const default_action = set_disj_5_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_5_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_5_true();
            }
        }
    
        table eval_equal_disj_5{
            actions = {
                set_disj_5_true;
                set_disj_5_false;
            }
            key = {
                ig_md.toCheck_5 : exact;
            }
            size = 1;
            const default_action = set_disj_5_false;
            const entries = {
                0 : set_disj_5_true();
            }
        }
    
        table eval_not_equal_disj_5{
            actions = {
                set_disj_5_true;
                set_disj_5_false;
            }
            key = {
                ig_md.toCheck_5 : exact;
            }
            size = 1;
            const default_action = set_disj_5_true;
            const entries = {
                0 : set_disj_5_false();
            }
        }

        table eval_range_disj_5{
            actions = {
                and_disj_5;
            }
            key = {
				ig_md.upper_bound_5 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_5(true);
            }
        }
    
        action set_disj_6_true(){
            ig_md.disj_6 = true;
        }
        
        action set_disj_6_false(){
            ig_md.disj_6 = false;
        }

        action and_disj_6(bool upper){
            ig_md.disj_6 = upper;
        }
        
        table eval_greater_disj_6{
            actions = {
                set_disj_6_true;
                set_disj_6_false;
            }
            key = {
                ig_md.toCheck_6 : ternary;
            }
            size = 2;
            const default_action = set_disj_6_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_6_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_6_false();
            }
        }
    
        table eval_smaller_disj_6{
            actions = {
                set_disj_6_true;
                set_disj_6_false;
            }
            key = {
                ig_md.toCheck_6 : ternary;
            }
            size = 2;
            const default_action = set_disj_6_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_6_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_6_true();
            }
        }
    
        table eval_equal_disj_6{
            actions = {
                set_disj_6_true;
                set_disj_6_false;
            }
            key = {
                ig_md.toCheck_6 : exact;
            }
            size = 1;
            const default_action = set_disj_6_false;
            const entries = {
                0 : set_disj_6_true();
            }
        }
    
        table eval_not_equal_disj_6{
            actions = {
                set_disj_6_true;
                set_disj_6_false;
            }
            key = {
                ig_md.toCheck_6 : exact;
            }
            size = 1;
            const default_action = set_disj_6_true;
            const entries = {
                0 : set_disj_6_false();
            }
        }

        table eval_range_disj_6{
            actions = {
                and_disj_6;
            }
            key = {
				ig_md.upper_bound_6 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_6(true);
            }
        }
    
        action set_disj_7_true(){
            ig_md.disj_7 = true;
        }
        
        action set_disj_7_false(){
            ig_md.disj_7 = false;
        }

        action and_disj_7(bool upper){
            ig_md.disj_7 = upper;
        }
        
        table eval_greater_disj_7{
            actions = {
                set_disj_7_true;
                set_disj_7_false;
            }
            key = {
                ig_md.toCheck_7 : ternary;
            }
            size = 2;
            const default_action = set_disj_7_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_7_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_7_false();
            }
        }
    
        table eval_smaller_disj_7{
            actions = {
                set_disj_7_true;
                set_disj_7_false;
            }
            key = {
                ig_md.toCheck_7 : ternary;
            }
            size = 2;
            const default_action = set_disj_7_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_7_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_7_true();
            }
        }
    
        table eval_equal_disj_7{
            actions = {
                set_disj_7_true;
                set_disj_7_false;
            }
            key = {
                ig_md.toCheck_7 : exact;
            }
            size = 1;
            const default_action = set_disj_7_false;
            const entries = {
                0 : set_disj_7_true();
            }
        }
    
        table eval_not_equal_disj_7{
            actions = {
                set_disj_7_true;
                set_disj_7_false;
            }
            key = {
                ig_md.toCheck_7 : exact;
            }
            size = 1;
            const default_action = set_disj_7_true;
            const entries = {
                0 : set_disj_7_false();
            }
        }

        table eval_range_disj_7{
            actions = {
                and_disj_7;
            }
            key = {
				ig_md.upper_bound_7 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_7(true);
            }
        }
    
        action set_disj_8_true(){
            ig_md.disj_8 = true;
        }
        
        action set_disj_8_false(){
            ig_md.disj_8 = false;
        }

        action and_disj_8(bool upper){
            ig_md.disj_8 = upper;
        }
        
        table eval_greater_disj_8{
            actions = {
                set_disj_8_true;
                set_disj_8_false;
            }
            key = {
                ig_md.toCheck_8 : ternary;
            }
            size = 2;
            const default_action = set_disj_8_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_8_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_8_false();
            }
        }
    
        table eval_smaller_disj_8{
            actions = {
                set_disj_8_true;
                set_disj_8_false;
            }
            key = {
                ig_md.toCheck_8 : ternary;
            }
            size = 2;
            const default_action = set_disj_8_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_8_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_8_true();
            }
        }
    
        table eval_equal_disj_8{
            actions = {
                set_disj_8_true;
                set_disj_8_false;
            }
            key = {
                ig_md.toCheck_8 : exact;
            }
            size = 1;
            const default_action = set_disj_8_false;
            const entries = {
                0 : set_disj_8_true();
            }
        }
    
        table eval_not_equal_disj_8{
            actions = {
                set_disj_8_true;
                set_disj_8_false;
            }
            key = {
                ig_md.toCheck_8 : exact;
            }
            size = 1;
            const default_action = set_disj_8_true;
            const entries = {
                0 : set_disj_8_false();
            }
        }

        table eval_range_disj_8{
            actions = {
                and_disj_8;
            }
            key = {
				ig_md.upper_bound_8 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_8(true);
            }
        }
    
        action set_disj_9_true(){
            ig_md.disj_9 = true;
        }
        
        action set_disj_9_false(){
            ig_md.disj_9 = false;
        }

        action and_disj_9(bool upper){
            ig_md.disj_9 = upper;
        }
        
        table eval_greater_disj_9{
            actions = {
                set_disj_9_true;
                set_disj_9_false;
            }
            key = {
                ig_md.toCheck_9 : ternary;
            }
            size = 2;
            const default_action = set_disj_9_true;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_9_false();
                0b0000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_9_false();
            }
        }
    
        table eval_smaller_disj_9{
            actions = {
                set_disj_9_true;
                set_disj_9_false;
            }
            key = {
                ig_md.toCheck_9 : ternary;
            }
            size = 2;
            const default_action = set_disj_9_false;
            const entries = {
				0b0000000000000000000000000000000 &&& 0b11111111111111111111111111111111 : set_disj_9_false();
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : set_disj_9_true();
            }
        }
    
        table eval_equal_disj_9{
            actions = {
                set_disj_9_true;
                set_disj_9_false;
            }
            key = {
                ig_md.toCheck_9 : exact;
            }
            size = 1;
            const default_action = set_disj_9_false;
            const entries = {
                0 : set_disj_9_true();
            }
        }
    
        table eval_not_equal_disj_9{
            actions = {
                set_disj_9_true;
                set_disj_9_false;
            }
            key = {
                ig_md.toCheck_9 : exact;
            }
            size = 1;
            const default_action = set_disj_9_true;
            const entries = {
                0 : set_disj_9_false();
            }
        }

        table eval_range_disj_9{
            actions = {
                and_disj_9;
            }
            key = {
				ig_md.upper_bound_9 : ternary;
            }
            size = 1;
            const entries = {
                0b1000000000000000000000000000000 &&& 0b10000000000000000000000000000000 : and_disj_9(true);
            }
        }
    
	

	action create_with_true_1(bit<32> bitstring){
		ig_md.disj_map_1 = bitstring | ig_md.disj_map_1;
	}
	
	action create_with_false_1(bit<32> bitstring){
		ig_md.disj_map_1 = bitstring & ig_md.disj_map_1;
	}

	table create_new_map_1{
		actions = {
			create_with_false_1;
			create_with_true_1;
		}
		key = {
			ig_md.disj_1 : exact;
			ig_md.conj_value_1 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_1(0b00000000000000000000000000000001);
			{true,1} : create_with_true_1(0b00000000000000000000000000000010);
			{true,2} : create_with_true_1(0b00000000000000000000000000000100);
			{true,3} : create_with_true_1(0b00000000000000000000000000001000);
			{true,4} : create_with_true_1(0b00000000000000000000000000010000);
			{true,5} : create_with_true_1(0b00000000000000000000000000100000);
			{true,6} : create_with_true_1(0b00000000000000000000000001000000);
			{true,7} : create_with_true_1(0b00000000000000000000000010000000);
			{true,8} : create_with_true_1(0b00000000000000000000000100000000);
			{true,9} : create_with_true_1(0b00000000000000000000001000000000);
			{true,10} : create_with_true_1(0b00000000000000000000010000000000);
			{true,11} : create_with_true_1(0b00000000000000000000100000000000);
			{true,12} : create_with_true_1(0b00000000000000000001000000000000);
			{true,13} : create_with_true_1(0b00000000000000000010000000000000);
			{true,14} : create_with_true_1(0b00000000000000000100000000000000);
			{true,15} : create_with_true_1(0b00000000000000001000000000000000);
			{true,16} : create_with_true_1(0b00000000000000010000000000000000);
			{true,17} : create_with_true_1(0b00000000000000100000000000000000);
			{true,18} : create_with_true_1(0b00000000000001000000000000000000);
			{true,19} : create_with_true_1(0b00000000000010000000000000000000);
			{true,20} : create_with_true_1(0b00000000000100000000000000000000);
			{true,21} : create_with_true_1(0b00000000001000000000000000000000);
			{true,22} : create_with_true_1(0b00000000010000000000000000000000);
			{true,23} : create_with_true_1(0b00000000100000000000000000000000);
			{true,24} : create_with_true_1(0b00000001000000000000000000000000);
			{true,25} : create_with_true_1(0b00000010000000000000000000000000);
			{true,26} : create_with_true_1(0b00000100000000000000000000000000);
			{true,27} : create_with_true_1(0b00001000000000000000000000000000);
			{true,28} : create_with_true_1(0b00010000000000000000000000000000);
			{true,29} : create_with_true_1(0b00100000000000000000000000000000);
			{true,30} : create_with_true_1(0b01000000000000000000000000000000);
			{true,31} : create_with_true_1(0b10000000000000000000000000000000);
			{false,0} : create_with_false_1(0b11111111111111111111111111111110);
			{false,1} : create_with_false_1(0b11111111111111111111111111111101);
			{false,2} : create_with_false_1(0b11111111111111111111111111111011);
			{false,3} : create_with_false_1(0b11111111111111111111111111110111);
			{false,4} : create_with_false_1(0b11111111111111111111111111101111);
			{false,5} : create_with_false_1(0b11111111111111111111111111011111);
			{false,6} : create_with_false_1(0b11111111111111111111111110111111);
			{false,7} : create_with_false_1(0b11111111111111111111111101111111);
			{false,8} : create_with_false_1(0b11111111111111111111111011111111);
			{false,9} : create_with_false_1(0b11111111111111111111110111111111);
			{false,10} : create_with_false_1(0b11111111111111111111101111111111);
			{false,11} : create_with_false_1(0b11111111111111111111011111111111);
			{false,12} : create_with_false_1(0b11111111111111111110111111111111);
			{false,13} : create_with_false_1(0b11111111111111111101111111111111);
			{false,14} : create_with_false_1(0b11111111111111111011111111111111);
			{false,15} : create_with_false_1(0b11111111111111110111111111111111);
			{false,16} : create_with_false_1(0b11111111111111101111111111111111);
			{false,17} : create_with_false_1(0b11111111111111011111111111111111);
			{false,18} : create_with_false_1(0b11111111111110111111111111111111);
			{false,19} : create_with_false_1(0b11111111111101111111111111111111);
			{false,20} : create_with_false_1(0b11111111111011111111111111111111);
			{false,21} : create_with_false_1(0b11111111110111111111111111111111);
			{false,22} : create_with_false_1(0b11111111101111111111111111111111);
			{false,23} : create_with_false_1(0b11111111011111111111111111111111);
			{false,24} : create_with_false_1(0b11111110111111111111111111111111);
			{false,25} : create_with_false_1(0b11111101111111111111111111111111);
			{false,26} : create_with_false_1(0b11111011111111111111111111111111);
			{false,27} : create_with_false_1(0b11110111111111111111111111111111);
			{false,28} : create_with_false_1(0b11101111111111111111111111111111);
			{false,29} : create_with_false_1(0b11011111111111111111111111111111);
			{false,30} : create_with_false_1(0b10111111111111111111111111111111);
			{false,31} : create_with_false_1(0b01111111111111111111111111111111);
		}
	}

	action create_with_true_2(bit<32> bitstring){
		ig_md.disj_map_2 = bitstring | ig_md.disj_map_2;
	}
	
	action create_with_false_2(bit<32> bitstring){
		ig_md.disj_map_2 = bitstring & ig_md.disj_map_2;
	}

	table create_new_map_2{
		actions = {
			create_with_false_2;
			create_with_true_2;
		}
		key = {
			ig_md.disj_2 : exact;
			ig_md.conj_value_2 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_2(0b00000000000000000000000000000001);
			{true,1} : create_with_true_2(0b00000000000000000000000000000010);
			{true,2} : create_with_true_2(0b00000000000000000000000000000100);
			{true,3} : create_with_true_2(0b00000000000000000000000000001000);
			{true,4} : create_with_true_2(0b00000000000000000000000000010000);
			{true,5} : create_with_true_2(0b00000000000000000000000000100000);
			{true,6} : create_with_true_2(0b00000000000000000000000001000000);
			{true,7} : create_with_true_2(0b00000000000000000000000010000000);
			{true,8} : create_with_true_2(0b00000000000000000000000100000000);
			{true,9} : create_with_true_2(0b00000000000000000000001000000000);
			{true,10} : create_with_true_2(0b00000000000000000000010000000000);
			{true,11} : create_with_true_2(0b00000000000000000000100000000000);
			{true,12} : create_with_true_2(0b00000000000000000001000000000000);
			{true,13} : create_with_true_2(0b00000000000000000010000000000000);
			{true,14} : create_with_true_2(0b00000000000000000100000000000000);
			{true,15} : create_with_true_2(0b00000000000000001000000000000000);
			{true,16} : create_with_true_2(0b00000000000000010000000000000000);
			{true,17} : create_with_true_2(0b00000000000000100000000000000000);
			{true,18} : create_with_true_2(0b00000000000001000000000000000000);
			{true,19} : create_with_true_2(0b00000000000010000000000000000000);
			{true,20} : create_with_true_2(0b00000000000100000000000000000000);
			{true,21} : create_with_true_2(0b00000000001000000000000000000000);
			{true,22} : create_with_true_2(0b00000000010000000000000000000000);
			{true,23} : create_with_true_2(0b00000000100000000000000000000000);
			{true,24} : create_with_true_2(0b00000001000000000000000000000000);
			{true,25} : create_with_true_2(0b00000010000000000000000000000000);
			{true,26} : create_with_true_2(0b00000100000000000000000000000000);
			{true,27} : create_with_true_2(0b00001000000000000000000000000000);
			{true,28} : create_with_true_2(0b00010000000000000000000000000000);
			{true,29} : create_with_true_2(0b00100000000000000000000000000000);
			{true,30} : create_with_true_2(0b01000000000000000000000000000000);
			{true,31} : create_with_true_2(0b10000000000000000000000000000000);
			{false,0} : create_with_false_2(0b11111111111111111111111111111110);
			{false,1} : create_with_false_2(0b11111111111111111111111111111101);
			{false,2} : create_with_false_2(0b11111111111111111111111111111011);
			{false,3} : create_with_false_2(0b11111111111111111111111111110111);
			{false,4} : create_with_false_2(0b11111111111111111111111111101111);
			{false,5} : create_with_false_2(0b11111111111111111111111111011111);
			{false,6} : create_with_false_2(0b11111111111111111111111110111111);
			{false,7} : create_with_false_2(0b11111111111111111111111101111111);
			{false,8} : create_with_false_2(0b11111111111111111111111011111111);
			{false,9} : create_with_false_2(0b11111111111111111111110111111111);
			{false,10} : create_with_false_2(0b11111111111111111111101111111111);
			{false,11} : create_with_false_2(0b11111111111111111111011111111111);
			{false,12} : create_with_false_2(0b11111111111111111110111111111111);
			{false,13} : create_with_false_2(0b11111111111111111101111111111111);
			{false,14} : create_with_false_2(0b11111111111111111011111111111111);
			{false,15} : create_with_false_2(0b11111111111111110111111111111111);
			{false,16} : create_with_false_2(0b11111111111111101111111111111111);
			{false,17} : create_with_false_2(0b11111111111111011111111111111111);
			{false,18} : create_with_false_2(0b11111111111110111111111111111111);
			{false,19} : create_with_false_2(0b11111111111101111111111111111111);
			{false,20} : create_with_false_2(0b11111111111011111111111111111111);
			{false,21} : create_with_false_2(0b11111111110111111111111111111111);
			{false,22} : create_with_false_2(0b11111111101111111111111111111111);
			{false,23} : create_with_false_2(0b11111111011111111111111111111111);
			{false,24} : create_with_false_2(0b11111110111111111111111111111111);
			{false,25} : create_with_false_2(0b11111101111111111111111111111111);
			{false,26} : create_with_false_2(0b11111011111111111111111111111111);
			{false,27} : create_with_false_2(0b11110111111111111111111111111111);
			{false,28} : create_with_false_2(0b11101111111111111111111111111111);
			{false,29} : create_with_false_2(0b11011111111111111111111111111111);
			{false,30} : create_with_false_2(0b10111111111111111111111111111111);
			{false,31} : create_with_false_2(0b01111111111111111111111111111111);
		}
	}

	action create_with_true_3(bit<32> bitstring){
		ig_md.disj_map_3 = bitstring | ig_md.disj_map_3;
	}
	
	action create_with_false_3(bit<32> bitstring){
		ig_md.disj_map_3 = bitstring & ig_md.disj_map_3;
	}

	table create_new_map_3{
		actions = {
			create_with_false_3;
			create_with_true_3;
		}
		key = {
			ig_md.disj_3 : exact;
			ig_md.conj_value_3 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_3(0b00000000000000000000000000000001);
			{true,1} : create_with_true_3(0b00000000000000000000000000000010);
			{true,2} : create_with_true_3(0b00000000000000000000000000000100);
			{true,3} : create_with_true_3(0b00000000000000000000000000001000);
			{true,4} : create_with_true_3(0b00000000000000000000000000010000);
			{true,5} : create_with_true_3(0b00000000000000000000000000100000);
			{true,6} : create_with_true_3(0b00000000000000000000000001000000);
			{true,7} : create_with_true_3(0b00000000000000000000000010000000);
			{true,8} : create_with_true_3(0b00000000000000000000000100000000);
			{true,9} : create_with_true_3(0b00000000000000000000001000000000);
			{true,10} : create_with_true_3(0b00000000000000000000010000000000);
			{true,11} : create_with_true_3(0b00000000000000000000100000000000);
			{true,12} : create_with_true_3(0b00000000000000000001000000000000);
			{true,13} : create_with_true_3(0b00000000000000000010000000000000);
			{true,14} : create_with_true_3(0b00000000000000000100000000000000);
			{true,15} : create_with_true_3(0b00000000000000001000000000000000);
			{true,16} : create_with_true_3(0b00000000000000010000000000000000);
			{true,17} : create_with_true_3(0b00000000000000100000000000000000);
			{true,18} : create_with_true_3(0b00000000000001000000000000000000);
			{true,19} : create_with_true_3(0b00000000000010000000000000000000);
			{true,20} : create_with_true_3(0b00000000000100000000000000000000);
			{true,21} : create_with_true_3(0b00000000001000000000000000000000);
			{true,22} : create_with_true_3(0b00000000010000000000000000000000);
			{true,23} : create_with_true_3(0b00000000100000000000000000000000);
			{true,24} : create_with_true_3(0b00000001000000000000000000000000);
			{true,25} : create_with_true_3(0b00000010000000000000000000000000);
			{true,26} : create_with_true_3(0b00000100000000000000000000000000);
			{true,27} : create_with_true_3(0b00001000000000000000000000000000);
			{true,28} : create_with_true_3(0b00010000000000000000000000000000);
			{true,29} : create_with_true_3(0b00100000000000000000000000000000);
			{true,30} : create_with_true_3(0b01000000000000000000000000000000);
			{true,31} : create_with_true_3(0b10000000000000000000000000000000);
			{false,0} : create_with_false_3(0b11111111111111111111111111111110);
			{false,1} : create_with_false_3(0b11111111111111111111111111111101);
			{false,2} : create_with_false_3(0b11111111111111111111111111111011);
			{false,3} : create_with_false_3(0b11111111111111111111111111110111);
			{false,4} : create_with_false_3(0b11111111111111111111111111101111);
			{false,5} : create_with_false_3(0b11111111111111111111111111011111);
			{false,6} : create_with_false_3(0b11111111111111111111111110111111);
			{false,7} : create_with_false_3(0b11111111111111111111111101111111);
			{false,8} : create_with_false_3(0b11111111111111111111111011111111);
			{false,9} : create_with_false_3(0b11111111111111111111110111111111);
			{false,10} : create_with_false_3(0b11111111111111111111101111111111);
			{false,11} : create_with_false_3(0b11111111111111111111011111111111);
			{false,12} : create_with_false_3(0b11111111111111111110111111111111);
			{false,13} : create_with_false_3(0b11111111111111111101111111111111);
			{false,14} : create_with_false_3(0b11111111111111111011111111111111);
			{false,15} : create_with_false_3(0b11111111111111110111111111111111);
			{false,16} : create_with_false_3(0b11111111111111101111111111111111);
			{false,17} : create_with_false_3(0b11111111111111011111111111111111);
			{false,18} : create_with_false_3(0b11111111111110111111111111111111);
			{false,19} : create_with_false_3(0b11111111111101111111111111111111);
			{false,20} : create_with_false_3(0b11111111111011111111111111111111);
			{false,21} : create_with_false_3(0b11111111110111111111111111111111);
			{false,22} : create_with_false_3(0b11111111101111111111111111111111);
			{false,23} : create_with_false_3(0b11111111011111111111111111111111);
			{false,24} : create_with_false_3(0b11111110111111111111111111111111);
			{false,25} : create_with_false_3(0b11111101111111111111111111111111);
			{false,26} : create_with_false_3(0b11111011111111111111111111111111);
			{false,27} : create_with_false_3(0b11110111111111111111111111111111);
			{false,28} : create_with_false_3(0b11101111111111111111111111111111);
			{false,29} : create_with_false_3(0b11011111111111111111111111111111);
			{false,30} : create_with_false_3(0b10111111111111111111111111111111);
			{false,31} : create_with_false_3(0b01111111111111111111111111111111);
		}
	}

	action create_with_true_4(bit<32> bitstring){
		ig_md.disj_map_4 = bitstring | ig_md.disj_map_4;
	}
	
	action create_with_false_4(bit<32> bitstring){
		ig_md.disj_map_4 = bitstring & ig_md.disj_map_4;
	}

	table create_new_map_4{
		actions = {
			create_with_false_4;
			create_with_true_4;
		}
		key = {
			ig_md.disj_4 : exact;
			ig_md.conj_value_4 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_4(0b00000000000000000000000000000001);
			{true,1} : create_with_true_4(0b00000000000000000000000000000010);
			{true,2} : create_with_true_4(0b00000000000000000000000000000100);
			{true,3} : create_with_true_4(0b00000000000000000000000000001000);
			{true,4} : create_with_true_4(0b00000000000000000000000000010000);
			{true,5} : create_with_true_4(0b00000000000000000000000000100000);
			{true,6} : create_with_true_4(0b00000000000000000000000001000000);
			{true,7} : create_with_true_4(0b00000000000000000000000010000000);
			{true,8} : create_with_true_4(0b00000000000000000000000100000000);
			{true,9} : create_with_true_4(0b00000000000000000000001000000000);
			{true,10} : create_with_true_4(0b00000000000000000000010000000000);
			{true,11} : create_with_true_4(0b00000000000000000000100000000000);
			{true,12} : create_with_true_4(0b00000000000000000001000000000000);
			{true,13} : create_with_true_4(0b00000000000000000010000000000000);
			{true,14} : create_with_true_4(0b00000000000000000100000000000000);
			{true,15} : create_with_true_4(0b00000000000000001000000000000000);
			{true,16} : create_with_true_4(0b00000000000000010000000000000000);
			{true,17} : create_with_true_4(0b00000000000000100000000000000000);
			{true,18} : create_with_true_4(0b00000000000001000000000000000000);
			{true,19} : create_with_true_4(0b00000000000010000000000000000000);
			{true,20} : create_with_true_4(0b00000000000100000000000000000000);
			{true,21} : create_with_true_4(0b00000000001000000000000000000000);
			{true,22} : create_with_true_4(0b00000000010000000000000000000000);
			{true,23} : create_with_true_4(0b00000000100000000000000000000000);
			{true,24} : create_with_true_4(0b00000001000000000000000000000000);
			{true,25} : create_with_true_4(0b00000010000000000000000000000000);
			{true,26} : create_with_true_4(0b00000100000000000000000000000000);
			{true,27} : create_with_true_4(0b00001000000000000000000000000000);
			{true,28} : create_with_true_4(0b00010000000000000000000000000000);
			{true,29} : create_with_true_4(0b00100000000000000000000000000000);
			{true,30} : create_with_true_4(0b01000000000000000000000000000000);
			{true,31} : create_with_true_4(0b10000000000000000000000000000000);
			{false,0} : create_with_false_4(0b11111111111111111111111111111110);
			{false,1} : create_with_false_4(0b11111111111111111111111111111101);
			{false,2} : create_with_false_4(0b11111111111111111111111111111011);
			{false,3} : create_with_false_4(0b11111111111111111111111111110111);
			{false,4} : create_with_false_4(0b11111111111111111111111111101111);
			{false,5} : create_with_false_4(0b11111111111111111111111111011111);
			{false,6} : create_with_false_4(0b11111111111111111111111110111111);
			{false,7} : create_with_false_4(0b11111111111111111111111101111111);
			{false,8} : create_with_false_4(0b11111111111111111111111011111111);
			{false,9} : create_with_false_4(0b11111111111111111111110111111111);
			{false,10} : create_with_false_4(0b11111111111111111111101111111111);
			{false,11} : create_with_false_4(0b11111111111111111111011111111111);
			{false,12} : create_with_false_4(0b11111111111111111110111111111111);
			{false,13} : create_with_false_4(0b11111111111111111101111111111111);
			{false,14} : create_with_false_4(0b11111111111111111011111111111111);
			{false,15} : create_with_false_4(0b11111111111111110111111111111111);
			{false,16} : create_with_false_4(0b11111111111111101111111111111111);
			{false,17} : create_with_false_4(0b11111111111111011111111111111111);
			{false,18} : create_with_false_4(0b11111111111110111111111111111111);
			{false,19} : create_with_false_4(0b11111111111101111111111111111111);
			{false,20} : create_with_false_4(0b11111111111011111111111111111111);
			{false,21} : create_with_false_4(0b11111111110111111111111111111111);
			{false,22} : create_with_false_4(0b11111111101111111111111111111111);
			{false,23} : create_with_false_4(0b11111111011111111111111111111111);
			{false,24} : create_with_false_4(0b11111110111111111111111111111111);
			{false,25} : create_with_false_4(0b11111101111111111111111111111111);
			{false,26} : create_with_false_4(0b11111011111111111111111111111111);
			{false,27} : create_with_false_4(0b11110111111111111111111111111111);
			{false,28} : create_with_false_4(0b11101111111111111111111111111111);
			{false,29} : create_with_false_4(0b11011111111111111111111111111111);
			{false,30} : create_with_false_4(0b10111111111111111111111111111111);
			{false,31} : create_with_false_4(0b01111111111111111111111111111111);
		}
	}

	action create_with_true_5(bit<32> bitstring){
		ig_md.disj_map_5 = bitstring | ig_md.disj_map_5;
	}
	
	action create_with_false_5(bit<32> bitstring){
		ig_md.disj_map_5 = bitstring & ig_md.disj_map_5;
	}

	table create_new_map_5{
		actions = {
			create_with_false_5;
			create_with_true_5;
		}
		key = {
			ig_md.disj_5 : exact;
			ig_md.conj_value_5 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_5(0b00000000000000000000000000000001);
			{true,1} : create_with_true_5(0b00000000000000000000000000000010);
			{true,2} : create_with_true_5(0b00000000000000000000000000000100);
			{true,3} : create_with_true_5(0b00000000000000000000000000001000);
			{true,4} : create_with_true_5(0b00000000000000000000000000010000);
			{true,5} : create_with_true_5(0b00000000000000000000000000100000);
			{true,6} : create_with_true_5(0b00000000000000000000000001000000);
			{true,7} : create_with_true_5(0b00000000000000000000000010000000);
			{true,8} : create_with_true_5(0b00000000000000000000000100000000);
			{true,9} : create_with_true_5(0b00000000000000000000001000000000);
			{true,10} : create_with_true_5(0b00000000000000000000010000000000);
			{true,11} : create_with_true_5(0b00000000000000000000100000000000);
			{true,12} : create_with_true_5(0b00000000000000000001000000000000);
			{true,13} : create_with_true_5(0b00000000000000000010000000000000);
			{true,14} : create_with_true_5(0b00000000000000000100000000000000);
			{true,15} : create_with_true_5(0b00000000000000001000000000000000);
			{true,16} : create_with_true_5(0b00000000000000010000000000000000);
			{true,17} : create_with_true_5(0b00000000000000100000000000000000);
			{true,18} : create_with_true_5(0b00000000000001000000000000000000);
			{true,19} : create_with_true_5(0b00000000000010000000000000000000);
			{true,20} : create_with_true_5(0b00000000000100000000000000000000);
			{true,21} : create_with_true_5(0b00000000001000000000000000000000);
			{true,22} : create_with_true_5(0b00000000010000000000000000000000);
			{true,23} : create_with_true_5(0b00000000100000000000000000000000);
			{true,24} : create_with_true_5(0b00000001000000000000000000000000);
			{true,25} : create_with_true_5(0b00000010000000000000000000000000);
			{true,26} : create_with_true_5(0b00000100000000000000000000000000);
			{true,27} : create_with_true_5(0b00001000000000000000000000000000);
			{true,28} : create_with_true_5(0b00010000000000000000000000000000);
			{true,29} : create_with_true_5(0b00100000000000000000000000000000);
			{true,30} : create_with_true_5(0b01000000000000000000000000000000);
			{true,31} : create_with_true_5(0b10000000000000000000000000000000);
			{false,0} : create_with_false_5(0b11111111111111111111111111111110);
			{false,1} : create_with_false_5(0b11111111111111111111111111111101);
			{false,2} : create_with_false_5(0b11111111111111111111111111111011);
			{false,3} : create_with_false_5(0b11111111111111111111111111110111);
			{false,4} : create_with_false_5(0b11111111111111111111111111101111);
			{false,5} : create_with_false_5(0b11111111111111111111111111011111);
			{false,6} : create_with_false_5(0b11111111111111111111111110111111);
			{false,7} : create_with_false_5(0b11111111111111111111111101111111);
			{false,8} : create_with_false_5(0b11111111111111111111111011111111);
			{false,9} : create_with_false_5(0b11111111111111111111110111111111);
			{false,10} : create_with_false_5(0b11111111111111111111101111111111);
			{false,11} : create_with_false_5(0b11111111111111111111011111111111);
			{false,12} : create_with_false_5(0b11111111111111111110111111111111);
			{false,13} : create_with_false_5(0b11111111111111111101111111111111);
			{false,14} : create_with_false_5(0b11111111111111111011111111111111);
			{false,15} : create_with_false_5(0b11111111111111110111111111111111);
			{false,16} : create_with_false_5(0b11111111111111101111111111111111);
			{false,17} : create_with_false_5(0b11111111111111011111111111111111);
			{false,18} : create_with_false_5(0b11111111111110111111111111111111);
			{false,19} : create_with_false_5(0b11111111111101111111111111111111);
			{false,20} : create_with_false_5(0b11111111111011111111111111111111);
			{false,21} : create_with_false_5(0b11111111110111111111111111111111);
			{false,22} : create_with_false_5(0b11111111101111111111111111111111);
			{false,23} : create_with_false_5(0b11111111011111111111111111111111);
			{false,24} : create_with_false_5(0b11111110111111111111111111111111);
			{false,25} : create_with_false_5(0b11111101111111111111111111111111);
			{false,26} : create_with_false_5(0b11111011111111111111111111111111);
			{false,27} : create_with_false_5(0b11110111111111111111111111111111);
			{false,28} : create_with_false_5(0b11101111111111111111111111111111);
			{false,29} : create_with_false_5(0b11011111111111111111111111111111);
			{false,30} : create_with_false_5(0b10111111111111111111111111111111);
			{false,31} : create_with_false_5(0b01111111111111111111111111111111);
		}
	}

	action create_with_true_6(bit<32> bitstring){
		ig_md.disj_map_6 = bitstring | ig_md.disj_map_6;
	}
	
	action create_with_false_6(bit<32> bitstring){
		ig_md.disj_map_6 = bitstring & ig_md.disj_map_6;
	}

	table create_new_map_6{
		actions = {
			create_with_false_6;
			create_with_true_6;
		}
		key = {
			ig_md.disj_6 : exact;
			ig_md.conj_value_6 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_6(0b00000000000000000000000000000001);
			{true,1} : create_with_true_6(0b00000000000000000000000000000010);
			{true,2} : create_with_true_6(0b00000000000000000000000000000100);
			{true,3} : create_with_true_6(0b00000000000000000000000000001000);
			{true,4} : create_with_true_6(0b00000000000000000000000000010000);
			{true,5} : create_with_true_6(0b00000000000000000000000000100000);
			{true,6} : create_with_true_6(0b00000000000000000000000001000000);
			{true,7} : create_with_true_6(0b00000000000000000000000010000000);
			{true,8} : create_with_true_6(0b00000000000000000000000100000000);
			{true,9} : create_with_true_6(0b00000000000000000000001000000000);
			{true,10} : create_with_true_6(0b00000000000000000000010000000000);
			{true,11} : create_with_true_6(0b00000000000000000000100000000000);
			{true,12} : create_with_true_6(0b00000000000000000001000000000000);
			{true,13} : create_with_true_6(0b00000000000000000010000000000000);
			{true,14} : create_with_true_6(0b00000000000000000100000000000000);
			{true,15} : create_with_true_6(0b00000000000000001000000000000000);
			{true,16} : create_with_true_6(0b00000000000000010000000000000000);
			{true,17} : create_with_true_6(0b00000000000000100000000000000000);
			{true,18} : create_with_true_6(0b00000000000001000000000000000000);
			{true,19} : create_with_true_6(0b00000000000010000000000000000000);
			{true,20} : create_with_true_6(0b00000000000100000000000000000000);
			{true,21} : create_with_true_6(0b00000000001000000000000000000000);
			{true,22} : create_with_true_6(0b00000000010000000000000000000000);
			{true,23} : create_with_true_6(0b00000000100000000000000000000000);
			{true,24} : create_with_true_6(0b00000001000000000000000000000000);
			{true,25} : create_with_true_6(0b00000010000000000000000000000000);
			{true,26} : create_with_true_6(0b00000100000000000000000000000000);
			{true,27} : create_with_true_6(0b00001000000000000000000000000000);
			{true,28} : create_with_true_6(0b00010000000000000000000000000000);
			{true,29} : create_with_true_6(0b00100000000000000000000000000000);
			{true,30} : create_with_true_6(0b01000000000000000000000000000000);
			{true,31} : create_with_true_6(0b10000000000000000000000000000000);
			{false,0} : create_with_false_6(0b11111111111111111111111111111110);
			{false,1} : create_with_false_6(0b11111111111111111111111111111101);
			{false,2} : create_with_false_6(0b11111111111111111111111111111011);
			{false,3} : create_with_false_6(0b11111111111111111111111111110111);
			{false,4} : create_with_false_6(0b11111111111111111111111111101111);
			{false,5} : create_with_false_6(0b11111111111111111111111111011111);
			{false,6} : create_with_false_6(0b11111111111111111111111110111111);
			{false,7} : create_with_false_6(0b11111111111111111111111101111111);
			{false,8} : create_with_false_6(0b11111111111111111111111011111111);
			{false,9} : create_with_false_6(0b11111111111111111111110111111111);
			{false,10} : create_with_false_6(0b11111111111111111111101111111111);
			{false,11} : create_with_false_6(0b11111111111111111111011111111111);
			{false,12} : create_with_false_6(0b11111111111111111110111111111111);
			{false,13} : create_with_false_6(0b11111111111111111101111111111111);
			{false,14} : create_with_false_6(0b11111111111111111011111111111111);
			{false,15} : create_with_false_6(0b11111111111111110111111111111111);
			{false,16} : create_with_false_6(0b11111111111111101111111111111111);
			{false,17} : create_with_false_6(0b11111111111111011111111111111111);
			{false,18} : create_with_false_6(0b11111111111110111111111111111111);
			{false,19} : create_with_false_6(0b11111111111101111111111111111111);
			{false,20} : create_with_false_6(0b11111111111011111111111111111111);
			{false,21} : create_with_false_6(0b11111111110111111111111111111111);
			{false,22} : create_with_false_6(0b11111111101111111111111111111111);
			{false,23} : create_with_false_6(0b11111111011111111111111111111111);
			{false,24} : create_with_false_6(0b11111110111111111111111111111111);
			{false,25} : create_with_false_6(0b11111101111111111111111111111111);
			{false,26} : create_with_false_6(0b11111011111111111111111111111111);
			{false,27} : create_with_false_6(0b11110111111111111111111111111111);
			{false,28} : create_with_false_6(0b11101111111111111111111111111111);
			{false,29} : create_with_false_6(0b11011111111111111111111111111111);
			{false,30} : create_with_false_6(0b10111111111111111111111111111111);
			{false,31} : create_with_false_6(0b01111111111111111111111111111111);
		}
	}

	action create_with_true_7(bit<32> bitstring){
		ig_md.disj_map_7 = bitstring | ig_md.disj_map_7;
	}
	
	action create_with_false_7(bit<32> bitstring){
		ig_md.disj_map_7 = bitstring & ig_md.disj_map_7;
	}

	table create_new_map_7{
		actions = {
			create_with_false_7;
			create_with_true_7;
		}
		key = {
			ig_md.disj_7 : exact;
			ig_md.conj_value_7 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_7(0b00000000000000000000000000000001);
			{true,1} : create_with_true_7(0b00000000000000000000000000000010);
			{true,2} : create_with_true_7(0b00000000000000000000000000000100);
			{true,3} : create_with_true_7(0b00000000000000000000000000001000);
			{true,4} : create_with_true_7(0b00000000000000000000000000010000);
			{true,5} : create_with_true_7(0b00000000000000000000000000100000);
			{true,6} : create_with_true_7(0b00000000000000000000000001000000);
			{true,7} : create_with_true_7(0b00000000000000000000000010000000);
			{true,8} : create_with_true_7(0b00000000000000000000000100000000);
			{true,9} : create_with_true_7(0b00000000000000000000001000000000);
			{true,10} : create_with_true_7(0b00000000000000000000010000000000);
			{true,11} : create_with_true_7(0b00000000000000000000100000000000);
			{true,12} : create_with_true_7(0b00000000000000000001000000000000);
			{true,13} : create_with_true_7(0b00000000000000000010000000000000);
			{true,14} : create_with_true_7(0b00000000000000000100000000000000);
			{true,15} : create_with_true_7(0b00000000000000001000000000000000);
			{true,16} : create_with_true_7(0b00000000000000010000000000000000);
			{true,17} : create_with_true_7(0b00000000000000100000000000000000);
			{true,18} : create_with_true_7(0b00000000000001000000000000000000);
			{true,19} : create_with_true_7(0b00000000000010000000000000000000);
			{true,20} : create_with_true_7(0b00000000000100000000000000000000);
			{true,21} : create_with_true_7(0b00000000001000000000000000000000);
			{true,22} : create_with_true_7(0b00000000010000000000000000000000);
			{true,23} : create_with_true_7(0b00000000100000000000000000000000);
			{true,24} : create_with_true_7(0b00000001000000000000000000000000);
			{true,25} : create_with_true_7(0b00000010000000000000000000000000);
			{true,26} : create_with_true_7(0b00000100000000000000000000000000);
			{true,27} : create_with_true_7(0b00001000000000000000000000000000);
			{true,28} : create_with_true_7(0b00010000000000000000000000000000);
			{true,29} : create_with_true_7(0b00100000000000000000000000000000);
			{true,30} : create_with_true_7(0b01000000000000000000000000000000);
			{true,31} : create_with_true_7(0b10000000000000000000000000000000);
			{false,0} : create_with_false_7(0b11111111111111111111111111111110);
			{false,1} : create_with_false_7(0b11111111111111111111111111111101);
			{false,2} : create_with_false_7(0b11111111111111111111111111111011);
			{false,3} : create_with_false_7(0b11111111111111111111111111110111);
			{false,4} : create_with_false_7(0b11111111111111111111111111101111);
			{false,5} : create_with_false_7(0b11111111111111111111111111011111);
			{false,6} : create_with_false_7(0b11111111111111111111111110111111);
			{false,7} : create_with_false_7(0b11111111111111111111111101111111);
			{false,8} : create_with_false_7(0b11111111111111111111111011111111);
			{false,9} : create_with_false_7(0b11111111111111111111110111111111);
			{false,10} : create_with_false_7(0b11111111111111111111101111111111);
			{false,11} : create_with_false_7(0b11111111111111111111011111111111);
			{false,12} : create_with_false_7(0b11111111111111111110111111111111);
			{false,13} : create_with_false_7(0b11111111111111111101111111111111);
			{false,14} : create_with_false_7(0b11111111111111111011111111111111);
			{false,15} : create_with_false_7(0b11111111111111110111111111111111);
			{false,16} : create_with_false_7(0b11111111111111101111111111111111);
			{false,17} : create_with_false_7(0b11111111111111011111111111111111);
			{false,18} : create_with_false_7(0b11111111111110111111111111111111);
			{false,19} : create_with_false_7(0b11111111111101111111111111111111);
			{false,20} : create_with_false_7(0b11111111111011111111111111111111);
			{false,21} : create_with_false_7(0b11111111110111111111111111111111);
			{false,22} : create_with_false_7(0b11111111101111111111111111111111);
			{false,23} : create_with_false_7(0b11111111011111111111111111111111);
			{false,24} : create_with_false_7(0b11111110111111111111111111111111);
			{false,25} : create_with_false_7(0b11111101111111111111111111111111);
			{false,26} : create_with_false_7(0b11111011111111111111111111111111);
			{false,27} : create_with_false_7(0b11110111111111111111111111111111);
			{false,28} : create_with_false_7(0b11101111111111111111111111111111);
			{false,29} : create_with_false_7(0b11011111111111111111111111111111);
			{false,30} : create_with_false_7(0b10111111111111111111111111111111);
			{false,31} : create_with_false_7(0b01111111111111111111111111111111);
		}
	}

	action create_with_true_8(bit<32> bitstring){
		ig_md.disj_map_8 = bitstring | ig_md.disj_map_8;
	}
	
	action create_with_false_8(bit<32> bitstring){
		ig_md.disj_map_8 = bitstring & ig_md.disj_map_8;
	}

	table create_new_map_8{
		actions = {
			create_with_false_8;
			create_with_true_8;
		}
		key = {
			ig_md.disj_8 : exact;
			ig_md.conj_value_8 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_8(0b00000000000000000000000000000001);
			{true,1} : create_with_true_8(0b00000000000000000000000000000010);
			{true,2} : create_with_true_8(0b00000000000000000000000000000100);
			{true,3} : create_with_true_8(0b00000000000000000000000000001000);
			{true,4} : create_with_true_8(0b00000000000000000000000000010000);
			{true,5} : create_with_true_8(0b00000000000000000000000000100000);
			{true,6} : create_with_true_8(0b00000000000000000000000001000000);
			{true,7} : create_with_true_8(0b00000000000000000000000010000000);
			{true,8} : create_with_true_8(0b00000000000000000000000100000000);
			{true,9} : create_with_true_8(0b00000000000000000000001000000000);
			{true,10} : create_with_true_8(0b00000000000000000000010000000000);
			{true,11} : create_with_true_8(0b00000000000000000000100000000000);
			{true,12} : create_with_true_8(0b00000000000000000001000000000000);
			{true,13} : create_with_true_8(0b00000000000000000010000000000000);
			{true,14} : create_with_true_8(0b00000000000000000100000000000000);
			{true,15} : create_with_true_8(0b00000000000000001000000000000000);
			{true,16} : create_with_true_8(0b00000000000000010000000000000000);
			{true,17} : create_with_true_8(0b00000000000000100000000000000000);
			{true,18} : create_with_true_8(0b00000000000001000000000000000000);
			{true,19} : create_with_true_8(0b00000000000010000000000000000000);
			{true,20} : create_with_true_8(0b00000000000100000000000000000000);
			{true,21} : create_with_true_8(0b00000000001000000000000000000000);
			{true,22} : create_with_true_8(0b00000000010000000000000000000000);
			{true,23} : create_with_true_8(0b00000000100000000000000000000000);
			{true,24} : create_with_true_8(0b00000001000000000000000000000000);
			{true,25} : create_with_true_8(0b00000010000000000000000000000000);
			{true,26} : create_with_true_8(0b00000100000000000000000000000000);
			{true,27} : create_with_true_8(0b00001000000000000000000000000000);
			{true,28} : create_with_true_8(0b00010000000000000000000000000000);
			{true,29} : create_with_true_8(0b00100000000000000000000000000000);
			{true,30} : create_with_true_8(0b01000000000000000000000000000000);
			{true,31} : create_with_true_8(0b10000000000000000000000000000000);
			{false,0} : create_with_false_8(0b11111111111111111111111111111110);
			{false,1} : create_with_false_8(0b11111111111111111111111111111101);
			{false,2} : create_with_false_8(0b11111111111111111111111111111011);
			{false,3} : create_with_false_8(0b11111111111111111111111111110111);
			{false,4} : create_with_false_8(0b11111111111111111111111111101111);
			{false,5} : create_with_false_8(0b11111111111111111111111111011111);
			{false,6} : create_with_false_8(0b11111111111111111111111110111111);
			{false,7} : create_with_false_8(0b11111111111111111111111101111111);
			{false,8} : create_with_false_8(0b11111111111111111111111011111111);
			{false,9} : create_with_false_8(0b11111111111111111111110111111111);
			{false,10} : create_with_false_8(0b11111111111111111111101111111111);
			{false,11} : create_with_false_8(0b11111111111111111111011111111111);
			{false,12} : create_with_false_8(0b11111111111111111110111111111111);
			{false,13} : create_with_false_8(0b11111111111111111101111111111111);
			{false,14} : create_with_false_8(0b11111111111111111011111111111111);
			{false,15} : create_with_false_8(0b11111111111111110111111111111111);
			{false,16} : create_with_false_8(0b11111111111111101111111111111111);
			{false,17} : create_with_false_8(0b11111111111111011111111111111111);
			{false,18} : create_with_false_8(0b11111111111110111111111111111111);
			{false,19} : create_with_false_8(0b11111111111101111111111111111111);
			{false,20} : create_with_false_8(0b11111111111011111111111111111111);
			{false,21} : create_with_false_8(0b11111111110111111111111111111111);
			{false,22} : create_with_false_8(0b11111111101111111111111111111111);
			{false,23} : create_with_false_8(0b11111111011111111111111111111111);
			{false,24} : create_with_false_8(0b11111110111111111111111111111111);
			{false,25} : create_with_false_8(0b11111101111111111111111111111111);
			{false,26} : create_with_false_8(0b11111011111111111111111111111111);
			{false,27} : create_with_false_8(0b11110111111111111111111111111111);
			{false,28} : create_with_false_8(0b11101111111111111111111111111111);
			{false,29} : create_with_false_8(0b11011111111111111111111111111111);
			{false,30} : create_with_false_8(0b10111111111111111111111111111111);
			{false,31} : create_with_false_8(0b01111111111111111111111111111111);
		}
	}

	action create_with_true_9(bit<32> bitstring){
		ig_md.disj_map_9 = bitstring | ig_md.disj_map_9;
	}
	
	action create_with_false_9(bit<32> bitstring){
		ig_md.disj_map_9 = bitstring & ig_md.disj_map_9;
	}

	table create_new_map_9{
		actions = {
			create_with_false_9;
			create_with_true_9;
		}
		key = {
			ig_md.disj_9 : exact;
			ig_md.conj_value_9 : exact;
		}
		size = 64;
		const entries = {
			{true,0} : create_with_true_9(0b00000000000000000000000000000001);
			{true,1} : create_with_true_9(0b00000000000000000000000000000010);
			{true,2} : create_with_true_9(0b00000000000000000000000000000100);
			{true,3} : create_with_true_9(0b00000000000000000000000000001000);
			{true,4} : create_with_true_9(0b00000000000000000000000000010000);
			{true,5} : create_with_true_9(0b00000000000000000000000000100000);
			{true,6} : create_with_true_9(0b00000000000000000000000001000000);
			{true,7} : create_with_true_9(0b00000000000000000000000010000000);
			{true,8} : create_with_true_9(0b00000000000000000000000100000000);
			{true,9} : create_with_true_9(0b00000000000000000000001000000000);
			{true,10} : create_with_true_9(0b00000000000000000000010000000000);
			{true,11} : create_with_true_9(0b00000000000000000000100000000000);
			{true,12} : create_with_true_9(0b00000000000000000001000000000000);
			{true,13} : create_with_true_9(0b00000000000000000010000000000000);
			{true,14} : create_with_true_9(0b00000000000000000100000000000000);
			{true,15} : create_with_true_9(0b00000000000000001000000000000000);
			{true,16} : create_with_true_9(0b00000000000000010000000000000000);
			{true,17} : create_with_true_9(0b00000000000000100000000000000000);
			{true,18} : create_with_true_9(0b00000000000001000000000000000000);
			{true,19} : create_with_true_9(0b00000000000010000000000000000000);
			{true,20} : create_with_true_9(0b00000000000100000000000000000000);
			{true,21} : create_with_true_9(0b00000000001000000000000000000000);
			{true,22} : create_with_true_9(0b00000000010000000000000000000000);
			{true,23} : create_with_true_9(0b00000000100000000000000000000000);
			{true,24} : create_with_true_9(0b00000001000000000000000000000000);
			{true,25} : create_with_true_9(0b00000010000000000000000000000000);
			{true,26} : create_with_true_9(0b00000100000000000000000000000000);
			{true,27} : create_with_true_9(0b00001000000000000000000000000000);
			{true,28} : create_with_true_9(0b00010000000000000000000000000000);
			{true,29} : create_with_true_9(0b00100000000000000000000000000000);
			{true,30} : create_with_true_9(0b01000000000000000000000000000000);
			{true,31} : create_with_true_9(0b10000000000000000000000000000000);
			{false,0} : create_with_false_9(0b11111111111111111111111111111110);
			{false,1} : create_with_false_9(0b11111111111111111111111111111101);
			{false,2} : create_with_false_9(0b11111111111111111111111111111011);
			{false,3} : create_with_false_9(0b11111111111111111111111111110111);
			{false,4} : create_with_false_9(0b11111111111111111111111111101111);
			{false,5} : create_with_false_9(0b11111111111111111111111111011111);
			{false,6} : create_with_false_9(0b11111111111111111111111110111111);
			{false,7} : create_with_false_9(0b11111111111111111111111101111111);
			{false,8} : create_with_false_9(0b11111111111111111111111011111111);
			{false,9} : create_with_false_9(0b11111111111111111111110111111111);
			{false,10} : create_with_false_9(0b11111111111111111111101111111111);
			{false,11} : create_with_false_9(0b11111111111111111111011111111111);
			{false,12} : create_with_false_9(0b11111111111111111110111111111111);
			{false,13} : create_with_false_9(0b11111111111111111101111111111111);
			{false,14} : create_with_false_9(0b11111111111111111011111111111111);
			{false,15} : create_with_false_9(0b11111111111111110111111111111111);
			{false,16} : create_with_false_9(0b11111111111111101111111111111111);
			{false,17} : create_with_false_9(0b11111111111111011111111111111111);
			{false,18} : create_with_false_9(0b11111111111110111111111111111111);
			{false,19} : create_with_false_9(0b11111111111101111111111111111111);
			{false,20} : create_with_false_9(0b11111111111011111111111111111111);
			{false,21} : create_with_false_9(0b11111111110111111111111111111111);
			{false,22} : create_with_false_9(0b11111111101111111111111111111111);
			{false,23} : create_with_false_9(0b11111111011111111111111111111111);
			{false,24} : create_with_false_9(0b11111110111111111111111111111111);
			{false,25} : create_with_false_9(0b11111101111111111111111111111111);
			{false,26} : create_with_false_9(0b11111011111111111111111111111111);
			{false,27} : create_with_false_9(0b11110111111111111111111111111111);
			{false,28} : create_with_false_9(0b11101111111111111111111111111111);
			{false,29} : create_with_false_9(0b11011111111111111111111111111111);
			{false,30} : create_with_false_9(0b10111111111111111111111111111111);
			{false,31} : create_with_false_9(0b01111111111111111111111111111111);
		}
	}

	


	action set_disj_map_1_true(){
		ig_md.disj_1 = true;
    }

	action set_disj_map_1_false(){
        ig_md.disj_1 = false;
    }
	
	table check_disj_map_1{
		actions = {
			set_disj_map_1_true;
			set_disj_map_1_false;
		}
		key = {
			ig_md.disj_map_1: exact;

		}
		size = 1;
		const default_action = set_disj_map_1_true;
		const entries = {
			{0} : set_disj_map_1_false();
		}
	}

	action set_disj_map_2_true(){
		ig_md.disj_2 = true;
    }

	action set_disj_map_2_false(){
        ig_md.disj_2 = false;
    }
	
	table check_disj_map_2{
		actions = {
			set_disj_map_2_true;
			set_disj_map_2_false;
		}
		key = {
			ig_md.disj_map_2: exact;

		}
		size = 1;
		const default_action = set_disj_map_2_true;
		const entries = {
			{0} : set_disj_map_2_false();
		}
	}

	action set_disj_map_3_true(){
		ig_md.disj_3 = true;
    }

	action set_disj_map_3_false(){
        ig_md.disj_3 = false;
    }
	
	table check_disj_map_3{
		actions = {
			set_disj_map_3_true;
			set_disj_map_3_false;
		}
		key = {
			ig_md.disj_map_3: exact;

		}
		size = 1;
		const default_action = set_disj_map_3_true;
		const entries = {
			{0} : set_disj_map_3_false();
		}
	}

	action set_disj_map_4_true(){
		ig_md.disj_4 = true;
    }

	action set_disj_map_4_false(){
        ig_md.disj_4 = false;
    }
	
	table check_disj_map_4{
		actions = {
			set_disj_map_4_true;
			set_disj_map_4_false;
		}
		key = {
			ig_md.disj_map_4: exact;

		}
		size = 1;
		const default_action = set_disj_map_4_true;
		const entries = {
			{0} : set_disj_map_4_false();
		}
	}

	action set_disj_map_5_true(){
		ig_md.disj_5 = true;
    }

	action set_disj_map_5_false(){
        ig_md.disj_5 = false;
    }
	
	table check_disj_map_5{
		actions = {
			set_disj_map_5_true;
			set_disj_map_5_false;
		}
		key = {
			ig_md.disj_map_5: exact;

		}
		size = 1;
		const default_action = set_disj_map_5_true;
		const entries = {
			{0} : set_disj_map_5_false();
		}
	}

	action set_disj_map_6_true(){
		ig_md.disj_6 = true;
    }

	action set_disj_map_6_false(){
        ig_md.disj_6 = false;
    }
	
	table check_disj_map_6{
		actions = {
			set_disj_map_6_true;
			set_disj_map_6_false;
		}
		key = {
			ig_md.disj_map_6: exact;

		}
		size = 1;
		const default_action = set_disj_map_6_true;
		const entries = {
			{0} : set_disj_map_6_false();
		}
	}

	action set_disj_map_7_true(){
		ig_md.disj_7 = true;
    }

	action set_disj_map_7_false(){
        ig_md.disj_7 = false;
    }
	
	table check_disj_map_7{
		actions = {
			set_disj_map_7_true;
			set_disj_map_7_false;
		}
		key = {
			ig_md.disj_map_7: exact;

		}
		size = 1;
		const default_action = set_disj_map_7_true;
		const entries = {
			{0} : set_disj_map_7_false();
		}
	}

	action set_disj_map_8_true(){
		ig_md.disj_8 = true;
    }

	action set_disj_map_8_false(){
        ig_md.disj_8 = false;
    }
	
	table check_disj_map_8{
		actions = {
			set_disj_map_8_true;
			set_disj_map_8_false;
		}
		key = {
			ig_md.disj_map_8: exact;

		}
		size = 1;
		const default_action = set_disj_map_8_true;
		const entries = {
			{0} : set_disj_map_8_false();
		}
	}

	action set_disj_map_9_true(){
		ig_md.disj_9 = true;
    }

	action set_disj_map_9_false(){
        ig_md.disj_9 = false;
    }
	
	table check_disj_map_9{
		actions = {
			set_disj_map_9_true;
			set_disj_map_9_false;
		}
		key = {
			ig_md.disj_map_9: exact;

		}
		size = 1;
		const default_action = set_disj_map_9_true;
		const entries = {
			{0} : set_disj_map_9_false();
		}
	}



    action store_disj_1_true() {
		ig_md.disj_map_1 = set_disj_map_1_register_true.execute(ig_md.conj_value_1);
	}

    action store_disj_1_false() {
		ig_md.disj_map_1 = set_disj_map_1_register_false.execute(ig_md.conj_value_1);
	}

	table store_disj_map_1{
		actions = {
			store_disj_1_true;
			store_disj_1_false;
		}
		key = {
			ig_md.disj_1 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_1_true();
			{false} : store_disj_1_false();
		}
	}

    action store_disj_2_true() {
		ig_md.disj_map_2 = set_disj_map_2_register_true.execute(ig_md.conj_value_2);
	}

    action store_disj_2_false() {
		ig_md.disj_map_2 = set_disj_map_2_register_false.execute(ig_md.conj_value_2);
	}

	table store_disj_map_2{
		actions = {
			store_disj_2_true;
			store_disj_2_false;
		}
		key = {
			ig_md.disj_2 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_2_true();
			{false} : store_disj_2_false();
		}
	}

    action store_disj_3_true() {
		ig_md.disj_map_3 = set_disj_map_3_register_true.execute(ig_md.conj_value_3);
	}

    action store_disj_3_false() {
		ig_md.disj_map_3 = set_disj_map_3_register_false.execute(ig_md.conj_value_3);
	}

	table store_disj_map_3{
		actions = {
			store_disj_3_true;
			store_disj_3_false;
		}
		key = {
			ig_md.disj_3 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_3_true();
			{false} : store_disj_3_false();
		}
	}

    action store_disj_4_true() {
		ig_md.disj_map_4 = set_disj_map_4_register_true.execute(ig_md.conj_value_4);
	}

    action store_disj_4_false() {
		ig_md.disj_map_4 = set_disj_map_4_register_false.execute(ig_md.conj_value_4);
	}

	table store_disj_map_4{
		actions = {
			store_disj_4_true;
			store_disj_4_false;
		}
		key = {
			ig_md.disj_4 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_4_true();
			{false} : store_disj_4_false();
		}
	}

    action store_disj_5_true() {
		ig_md.disj_map_5 = set_disj_map_5_register_true.execute(ig_md.conj_value_5);
	}

    action store_disj_5_false() {
		ig_md.disj_map_5 = set_disj_map_5_register_false.execute(ig_md.conj_value_5);
	}

	table store_disj_map_5{
		actions = {
			store_disj_5_true;
			store_disj_5_false;
		}
		key = {
			ig_md.disj_5 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_5_true();
			{false} : store_disj_5_false();
		}
	}

    action store_disj_6_true() {
		ig_md.disj_map_6 = set_disj_map_6_register_true.execute(ig_md.conj_value_6);
	}

    action store_disj_6_false() {
		ig_md.disj_map_6 = set_disj_map_6_register_false.execute(ig_md.conj_value_6);
	}

	table store_disj_map_6{
		actions = {
			store_disj_6_true;
			store_disj_6_false;
		}
		key = {
			ig_md.disj_6 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_6_true();
			{false} : store_disj_6_false();
		}
	}

    action store_disj_7_true() {
		ig_md.disj_map_7 = set_disj_map_7_register_true.execute(ig_md.conj_value_7);
	}

    action store_disj_7_false() {
		ig_md.disj_map_7 = set_disj_map_7_register_false.execute(ig_md.conj_value_7);
	}

	table store_disj_map_7{
		actions = {
			store_disj_7_true;
			store_disj_7_false;
		}
		key = {
			ig_md.disj_7 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_7_true();
			{false} : store_disj_7_false();
		}
	}

    action store_disj_8_true() {
		ig_md.disj_map_8 = set_disj_map_8_register_true.execute(ig_md.conj_value_8);
	}

    action store_disj_8_false() {
		ig_md.disj_map_8 = set_disj_map_8_register_false.execute(ig_md.conj_value_8);
	}

	table store_disj_map_8{
		actions = {
			store_disj_8_true;
			store_disj_8_false;
		}
		key = {
			ig_md.disj_8 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_8_true();
			{false} : store_disj_8_false();
		}
	}

    action store_disj_9_true() {
		ig_md.disj_map_9 = set_disj_map_9_register_true.execute(ig_md.conj_value_9);
	}

    action store_disj_9_false() {
		ig_md.disj_map_9 = set_disj_map_9_register_false.execute(ig_md.conj_value_9);
	}

	table store_disj_map_9{
		actions = {
			store_disj_9_true;
			store_disj_9_false;
		}
		key = {
			ig_md.disj_9 : exact;
		}
		size = 2;
		const entries = {
			{true} : store_disj_9_true();
			{false} : store_disj_9_false();
		}
	}


	action sum_conj_set_true(){
        ig_md.summed_conj = true;
    }
	
	action sum_conj_set_false(){
        ig_md.summed_conj = false;
    }
	
	table sum_conj{
		actions = {
			sum_conj_set_true;
			sum_conj_set_false;
		}
		key = {
			ig_md.disj_1: exact;
			ig_md.disj_2: exact;
			ig_md.disj_3: exact;
			ig_md.disj_4: exact;


		}
		size = 1;
		const default_action = sum_conj_set_false;
		const entries = {
			{true,true,true,true} : sum_conj_set_true();
		}
	}


	table sum_conj_2{
		actions = {
			sum_conj_set_true;
			sum_conj_set_false;
		}
		key = {
			ig_md.summed_conj: exact;
			ig_md.disj_5: exact;
			ig_md.disj_6: exact;


		}
		size = 1;
		const default_action = sum_conj_set_false;
		const entries = {
			{true, true, true} : sum_conj_set_true();
		}
	}



	table sum_conj_3{
		actions = {
			sum_conj_set_true;
			sum_conj_set_false;
		}
		key = {
			ig_md.summed_conj: exact;
			ig_md.disj_7: exact;
			ig_md.disj_8: exact;
			ig_md.disj_9: exact;


		}
		size = 1;
		const default_action = sum_conj_set_false;
		const entries = {
			{true, true, true, true} : sum_conj_set_true();
		}
	}

	

    // #ingress
    apply {        
        if (hdr.sensor.isValid()){
			lpf_input = (bit<32>)hdr.sensor.sensorValue;
			lpf_output_1 = lpf_1.execute(lpf_input, hdr.sensor.sensorId);
			ig_md.historical_value = get_map_1.execute(hdr.sensor.sensorId);
			ig_md.historical_value = get_map_2.execute(hdr.sensor.sensorId);
			ig_md.historical_value = get_map_3.execute(hdr.sensor.sensorId);
			ig_md.historical_value = get_map_4.execute(hdr.sensor.sensorId);

			
			conj_table_1.apply();
			conj_table_2.apply();
			conj_table_3.apply();
			conj_table_4.apply();
			conj_table_5.apply();
			conj_table_6.apply();
			conj_table_7.apply();
			conj_table_8.apply();
			conj_table_9.apply();


			assign_data.apply();
		
			subtract_table_1.apply();
			subtract_table_upper_1.apply();
			subtract_table_2.apply();
			subtract_table_upper_2.apply();
			subtract_table_3.apply();
			subtract_table_upper_3.apply();
			subtract_table_4.apply();
			subtract_table_upper_4.apply();
			subtract_table_5.apply();
			subtract_table_upper_5.apply();
			subtract_table_6.apply();
			subtract_table_upper_6.apply();
			subtract_table_7.apply();
			subtract_table_upper_7.apply();
			subtract_table_8.apply();
			subtract_table_upper_8.apply();
			subtract_table_9.apply();
			subtract_table_upper_9.apply();

		

            if(ig_md.disj_op_1 == 1 || ig_md.disj_op_1 == 5)
            {
                eval_greater_disj_1.apply();
                
            }
            else if(ig_md.disj_op_1 == 2)
            {
                eval_smaller_disj_1.apply();
            }
            else if(ig_md.disj_op_1 == 3 || ig_md.disj_op_1 == 0)
            {
                eval_equal_disj_1.apply();
            }
            else if(ig_md.disj_op_1 == 4)
            {
                eval_not_equal_disj_1.apply();
            }
            if(ig_md.disj_op_1 == 5 && ig_md.disj_1)
            {
            eval_range_disj_1.apply();
            }
                
    
            if(ig_md.disj_op_2 == 1 || ig_md.disj_op_2 == 5)
            {
                eval_greater_disj_2.apply();
                
            }
            else if(ig_md.disj_op_2 == 2)
            {
                eval_smaller_disj_2.apply();
            }
            else if(ig_md.disj_op_2 == 3 || ig_md.disj_op_2 == 0)
            {
                eval_equal_disj_2.apply();
            }
            else if(ig_md.disj_op_2 == 4)
            {
                eval_not_equal_disj_2.apply();
            }
            if(ig_md.disj_op_2 == 5 && ig_md.disj_2)
            {
            eval_range_disj_2.apply();
            }
                
    
            if(ig_md.disj_op_3 == 1 || ig_md.disj_op_3 == 5)
            {
                eval_greater_disj_3.apply();
                
            }
            else if(ig_md.disj_op_3 == 2)
            {
                eval_smaller_disj_3.apply();
            }
            else if(ig_md.disj_op_3 == 3 || ig_md.disj_op_3 == 0)
            {
                eval_equal_disj_3.apply();
            }
            else if(ig_md.disj_op_3 == 4)
            {
                eval_not_equal_disj_3.apply();
            }
            if(ig_md.disj_op_3 == 5 && ig_md.disj_3)
            {
            eval_range_disj_3.apply();
            }
                
    
            if(ig_md.disj_op_4 == 1 || ig_md.disj_op_4 == 5)
            {
                eval_greater_disj_4.apply();
                
            }
            else if(ig_md.disj_op_4 == 2)
            {
                eval_smaller_disj_4.apply();
            }
            else if(ig_md.disj_op_4 == 3 || ig_md.disj_op_4 == 0)
            {
                eval_equal_disj_4.apply();
            }
            else if(ig_md.disj_op_4 == 4)
            {
                eval_not_equal_disj_4.apply();
            }
            if(ig_md.disj_op_4 == 5 && ig_md.disj_4)
            {
            eval_range_disj_4.apply();
            }
                
    
            if(ig_md.disj_op_5 == 1 || ig_md.disj_op_5 == 5)
            {
                eval_greater_disj_5.apply();
                
            }
            else if(ig_md.disj_op_5 == 2)
            {
                eval_smaller_disj_5.apply();
            }
            else if(ig_md.disj_op_5 == 3 || ig_md.disj_op_5 == 0)
            {
                eval_equal_disj_5.apply();
            }
            else if(ig_md.disj_op_5 == 4)
            {
                eval_not_equal_disj_5.apply();
            }
            if(ig_md.disj_op_5 == 5 && ig_md.disj_5)
            {
            eval_range_disj_5.apply();
            }
                
    
            if(ig_md.disj_op_6 == 1 || ig_md.disj_op_6 == 5)
            {
                eval_greater_disj_6.apply();
                
            }
            else if(ig_md.disj_op_6 == 2)
            {
                eval_smaller_disj_6.apply();
            }
            else if(ig_md.disj_op_6 == 3 || ig_md.disj_op_6 == 0)
            {
                eval_equal_disj_6.apply();
            }
            else if(ig_md.disj_op_6 == 4)
            {
                eval_not_equal_disj_6.apply();
            }
            if(ig_md.disj_op_6 == 5 && ig_md.disj_6)
            {
            eval_range_disj_6.apply();
            }
                
    
            if(ig_md.disj_op_7 == 1 || ig_md.disj_op_7 == 5)
            {
                eval_greater_disj_7.apply();
                
            }
            else if(ig_md.disj_op_7 == 2)
            {
                eval_smaller_disj_7.apply();
            }
            else if(ig_md.disj_op_7 == 3 || ig_md.disj_op_7 == 0)
            {
                eval_equal_disj_7.apply();
            }
            else if(ig_md.disj_op_7 == 4)
            {
                eval_not_equal_disj_7.apply();
            }
            if(ig_md.disj_op_7 == 5 && ig_md.disj_7)
            {
            eval_range_disj_7.apply();
            }
                
    
            if(ig_md.disj_op_8 == 1 || ig_md.disj_op_8 == 5)
            {
                eval_greater_disj_8.apply();
                
            }
            else if(ig_md.disj_op_8 == 2)
            {
                eval_smaller_disj_8.apply();
            }
            else if(ig_md.disj_op_8 == 3 || ig_md.disj_op_8 == 0)
            {
                eval_equal_disj_8.apply();
            }
            else if(ig_md.disj_op_8 == 4)
            {
                eval_not_equal_disj_8.apply();
            }
            if(ig_md.disj_op_8 == 5 && ig_md.disj_8)
            {
            eval_range_disj_8.apply();
            }
                
    
            if(ig_md.disj_op_9 == 1 || ig_md.disj_op_9 == 5)
            {
                eval_greater_disj_9.apply();
                
            }
            else if(ig_md.disj_op_9 == 2)
            {
                eval_smaller_disj_9.apply();
            }
            else if(ig_md.disj_op_9 == 3 || ig_md.disj_op_9 == 0)
            {
                eval_equal_disj_9.apply();
            }
            else if(ig_md.disj_op_9 == 4)
            {
                eval_not_equal_disj_9.apply();
            }
            if(ig_md.disj_op_9 == 5 && ig_md.disj_9)
            {
            eval_range_disj_9.apply();
            }
                
    
			

                if(ig_md.disj_op_1 != 0){
                    create_new_map_1.apply();
                }

                if(ig_md.disj_op_2 != 0){
                    create_new_map_2.apply();
                }

                if(ig_md.disj_op_3 != 0){
                    create_new_map_3.apply();
                }

                if(ig_md.disj_op_4 != 0){
                    create_new_map_4.apply();
                }

                if(ig_md.disj_op_5 != 0){
                    create_new_map_5.apply();
                }

                if(ig_md.disj_op_6 != 0){
                    create_new_map_6.apply();
                }

                if(ig_md.disj_op_7 != 0){
                    create_new_map_7.apply();
                }

                if(ig_md.disj_op_8 != 0){
                    create_new_map_8.apply();
                }

                if(ig_md.disj_op_9 != 0){
                    create_new_map_9.apply();
                }


               store_disj_map_1.apply();
               store_disj_map_2.apply();
               store_disj_map_3.apply();
               store_disj_map_4.apply();
               store_disj_map_5.apply();
               store_disj_map_6.apply();
               store_disj_map_7.apply();
               store_disj_map_8.apply();
               store_disj_map_9.apply();

			check_disj_map_1.apply();
			check_disj_map_2.apply();
			check_disj_map_3.apply();
			check_disj_map_4.apply();
			check_disj_map_5.apply();
			check_disj_map_6.apply();
			check_disj_map_7.apply();
			check_disj_map_8.apply();
			check_disj_map_9.apply();

			//check_disj_map_3.apply();
			sum_conj.apply();
			sum_conj_2.apply();

			sum_conj_3.apply();

			if(!ig_md.summed_conj)
			{
				ig_dprsr_md.drop_ctl = 1;
			}
			else
			{
				ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
			}
		}
		
		else{

		}
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

// EGRESS ************************************************************

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
	    tofino_parser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            //6: parse_tcp;
            17: parse_udp;
            default: accept; 
        } 
    }

    state parse_udp{
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort){
            default : accept;
        }
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    apply {

    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {

        hdr.ipv4.hdrChecksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4._reserved,
            hdr.ipv4.dont_fragment,
            hdr.ipv4.more_fragments,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            //hdr.ipv4.hdrChecksum,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr            
        });

        pkt.emit(hdr);
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;

