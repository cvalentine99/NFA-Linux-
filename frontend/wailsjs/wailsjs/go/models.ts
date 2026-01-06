export namespace main {
	
	export class AlertDTO {
	    id: string;
	    timestamp: number;
	    severity: string;
	    category: string;
	    title: string;
	    description: string;
	    src_ip: string;
	    dst_ip: string;
	    flow_id: string;
	    packet_id: string;
	
	    static createFrom(source: any = {}) {
	        return new AlertDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestamp = source["timestamp"];
	        this.severity = source["severity"];
	        this.category = source["category"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.src_ip = source["src_ip"];
	        this.dst_ip = source["dst_ip"];
	        this.flow_id = source["flow_id"];
	        this.packet_id = source["packet_id"];
	    }
	}
	export class FileDTO {
	    id: string;
	    name: string;
	    size: number;
	    mime_type: string;
	    md5: string;
	    sha1: string;
	    sha256: string;
	    timestamp: number;
	    flow_id: string;
	    path: string;
	
	    static createFrom(source: any = {}) {
	        return new FileDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.size = source["size"];
	        this.mime_type = source["mime_type"];
	        this.md5 = source["md5"];
	        this.sha1 = source["sha1"];
	        this.sha256 = source["sha256"];
	        this.timestamp = source["timestamp"];
	        this.flow_id = source["flow_id"];
	        this.path = source["path"];
	    }
	}
	export class FlowDTO {
	    id: string;
	    src_ip: string;
	    dst_ip: string;
	    src_port: number;
	    dst_port: number;
	    protocol: string;
	    app_protocol: string;
	    state: string;
	    packet_count: number;
	    byte_count: number;
	    start_time: number;
	    last_activity: number;
	    duration: number;
	
	    static createFrom(source: any = {}) {
	        return new FlowDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.src_ip = source["src_ip"];
	        this.dst_ip = source["dst_ip"];
	        this.src_port = source["src_port"];
	        this.dst_port = source["dst_port"];
	        this.protocol = source["protocol"];
	        this.app_protocol = source["app_protocol"];
	        this.state = source["state"];
	        this.packet_count = source["packet_count"];
	        this.byte_count = source["byte_count"];
	        this.start_time = source["start_time"];
	        this.last_activity = source["last_activity"];
	        this.duration = source["duration"];
	    }
	}
	export class InterfaceInfo {
	    name: string;
	    description: string;
	    is_up: boolean;
	    has_address: boolean;
	    is_loopback: boolean;
	
	    static createFrom(source: any = {}) {
	        return new InterfaceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.is_up = source["is_up"];
	        this.has_address = source["has_address"];
	        this.is_loopback = source["is_loopback"];
	    }
	}
	export class PacketDTO {
	    id: string;
	    timestamp: number;
	    length: number;
	    src_ip: string;
	    dst_ip: string;
	    src_port: number;
	    dst_port: number;
	    protocol: string;
	    app_protocol: string;
	    info: string;
	    payload_size: number;
	    flow_id: string;
	
	    static createFrom(source: any = {}) {
	        return new PacketDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestamp = source["timestamp"];
	        this.length = source["length"];
	        this.src_ip = source["src_ip"];
	        this.dst_ip = source["dst_ip"];
	        this.src_port = source["src_port"];
	        this.dst_port = source["dst_port"];
	        this.protocol = source["protocol"];
	        this.app_protocol = source["app_protocol"];
	        this.info = source["info"];
	        this.payload_size = source["payload_size"];
	        this.flow_id = source["flow_id"];
	    }
	}
	export class StatsDTO {
	    packet_count: number;
	    byte_count: number;
	    flow_count: number;
	    alert_count: number;
	    file_count: number;
	    dropped_packets: number;
	    packets_per_sec: number;
	    bytes_per_sec: number;
	    memory_usage: number;
	    capture_time: number;
	    interface: string;
	    is_capturing: boolean;
	
	    static createFrom(source: any = {}) {
	        return new StatsDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.packet_count = source["packet_count"];
	        this.byte_count = source["byte_count"];
	        this.flow_count = source["flow_count"];
	        this.alert_count = source["alert_count"];
	        this.file_count = source["file_count"];
	        this.dropped_packets = source["dropped_packets"];
	        this.packets_per_sec = source["packets_per_sec"];
	        this.bytes_per_sec = source["bytes_per_sec"];
	        this.memory_usage = source["memory_usage"];
	        this.capture_time = source["capture_time"];
	        this.interface = source["interface"];
	        this.is_capturing = source["is_capturing"];
	    }
	}

}

