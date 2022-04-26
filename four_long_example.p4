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

	bit<32> disj_op_1;
	bool disj_1;
	bit<32> toCheck_1;
	bit<32> sensorValue_copy_1;



	
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


Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash;

	action copy1(){
		ig_md.sensorValue_copy_1 = identity_hash.get(hdr.sensor.sensorValue);

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


		}
		size = 1;
		const default_action = sum_conj_set_false;
		const entries = {
			{true} : sum_conj_set_true();
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


			assign_data.apply();
		
			subtract_table_1.apply();
			subtract_table_upper_1.apply();

		

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
                
    
			

                if(ig_md.disj_op_1 != 0){
                    create_new_map_1.apply();
                }


               store_disj_map_1.apply();

			check_disj_map_1.apply();

			//check_disj_map_3.apply();
			sum_conj.apply();


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

