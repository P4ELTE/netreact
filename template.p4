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
<CONJ_META>
<DISJ_META>
<DUMMY_META>

	
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

<HISTORY_REGISTERS>

<MAP_REGISTERS>

Hash<bit<32>>(HashAlgorithm_t.IDENTITY) identity_hash;

	action copy1(){
<HASH_ACTION>
	}
	
	table assign_data {
        actions = { copy1; }
        const default_action = copy1();
    }


<HISTORY_REGISTER_ACTIONS>

<MAP_REGISTER_ACTIONS>


	
	Lpf<bit<32>, bit<32>>(size=SENSOR_COUNT) lpf_1;
	
	bit<32> lpf_input;
	bit<32> lpf_output_1;

<DUMMY_TABLES>


<CONJ_TABLES>


<SUBTRACTION_TABLES>

<EVALUATION_TABLES>
	
<NEW_MAP_TABLES>
	

<CHECK_DISJ_MAP_TABLES>

<STORE_DISJ_MAP_TABLES>

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
<SUM_CONJ_KEYS>

		}
		size = 1;
		const default_action = sum_conj_set_false;
		const entries = {
			{<SUM_CONJ_ENTRY>} : sum_conj_set_true();
		}
	}

<SUM_CONJ_2_TABLE>

<SUM_CONJ_3_TABLE>
	

    // #ingress
    apply {        
        if (hdr.sensor.isValid()){
			lpf_input = (bit<32>)hdr.sensor.sensorValue;
			lpf_output_1 = lpf_1.execute(lpf_input, hdr.sensor.sensorId);
<REGISTER_CALLS>
			
<CONJ_TABLE_CALLS>

			assign_data.apply();
		
<SUBTRACT_TABLE_CALLS>
		
<CALL_EVALS>
			
<NEW_MAP_TABLE_CALLS>

<STORE_DISJ_MAP_TABLE_CALLS>
<CHECK_DISJ_MAP_TABLE_CALLS>
			//check_disj_map_3.apply();
			sum_conj.apply();
<SUM_CONJ_2_CALL>
<SUM_CONJ_3_CALL>
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
<DUMMY_TABLE_CALLS>
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

