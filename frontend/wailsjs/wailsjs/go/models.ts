export namespace main {
	
	export class AlertDTO {
	    id: string;
	    timestamp: number;
	    severity: string;
	    category: string;
	    title: string;
	    description: string;
	    srcIP: string;
	    dstIP: string;
	    flowID: string;
	    packetID: string;
	
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
	        this.srcIP = source["srcIP"];
	        this.dstIP = source["dstIP"];
	        this.flowID = source["flowID"];
	        this.packetID = source["packetID"];
	    }
	}
	export class ByteStatsDTO {
	    total: number;
	    inbound: number;
	    outbound: number;
	
	    static createFrom(source: any = {}) {
	        return new ByteStatsDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total = source["total"];
	        this.inbound = source["inbound"];
	        this.outbound = source["outbound"];
	    }
	}
	export class FileDTO {
	    id: string;
	    name: string;
	    size: number;
	    mimeType: string;
	    md5: string;
	    sha1: string;
	    sha256: string;
	    timestamp: number;
	    flowID: string;
	    path: string;
	
	    static createFrom(source: any = {}) {
	        return new FileDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.size = source["size"];
	        this.mimeType = source["mimeType"];
	        this.md5 = source["md5"];
	        this.sha1 = source["sha1"];
	        this.sha256 = source["sha256"];
	        this.timestamp = source["timestamp"];
	        this.flowID = source["flowID"];
	        this.path = source["path"];
	    }
	}
	export class FlowDTO {
	    id: string;
	    srcIP: string;
	    dstIP: string;
	    srcPort: number;
	    dstPort: number;
	    protocol: string;
	    appProtocol: string;
	    state: string;
	    packetCount: number;
	    byteCount: number;
	    startTimeNano: number;
	    endTimeNano: number;
	    duration: number;
	
	    static createFrom(source: any = {}) {
	        return new FlowDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.srcIP = source["srcIP"];
	        this.dstIP = source["dstIP"];
	        this.srcPort = source["srcPort"];
	        this.dstPort = source["dstPort"];
	        this.protocol = source["protocol"];
	        this.appProtocol = source["appProtocol"];
	        this.state = source["state"];
	        this.packetCount = source["packetCount"];
	        this.byteCount = source["byteCount"];
	        this.startTimeNano = source["startTimeNano"];
	        this.endTimeNano = source["endTimeNano"];
	        this.duration = source["duration"];
	    }
	}
	export class FlowStatsDTO {
	    total: number;
	    active: number;
	    completed: number;
	
	    static createFrom(source: any = {}) {
	        return new FlowStatsDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total = source["total"];
	        this.active = source["active"];
	        this.completed = source["completed"];
	    }
	}
	export class InterfaceInfo {
	    name: string;
	    description: string;
	    isUp: boolean;
	    hasAddress: boolean;
	    isLoopback: boolean;
	
	    static createFrom(source: any = {}) {
	        return new InterfaceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.isUp = source["isUp"];
	        this.hasAddress = source["hasAddress"];
	        this.isLoopback = source["isLoopback"];
	    }
	}
	export class PacketDTO {
	    id: string;
	    timestampNano: number;
	    length: number;
	    srcIP: string;
	    dstIP: string;
	    srcPort: number;
	    dstPort: number;
	    protocol: string;
	    appProtocol: string;
	    info: string;
	    payloadSize: number;
	    flowID: string;
	    direction: string;
	
	    static createFrom(source: any = {}) {
	        return new PacketDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestampNano = source["timestampNano"];
	        this.length = source["length"];
	        this.srcIP = source["srcIP"];
	        this.dstIP = source["dstIP"];
	        this.srcPort = source["srcPort"];
	        this.dstPort = source["dstPort"];
	        this.protocol = source["protocol"];
	        this.appProtocol = source["appProtocol"];
	        this.info = source["info"];
	        this.payloadSize = source["payloadSize"];
	        this.flowID = source["flowID"];
	        this.direction = source["direction"];
	    }
	}
	export class PacketStatsDTO {
	    total: number;
	    tcp: number;
	    udp: number;
	    icmp: number;
	    other: number;
	
	    static createFrom(source: any = {}) {
	        return new PacketStatsDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total = source["total"];
	        this.tcp = source["tcp"];
	        this.udp = source["udp"];
	        this.icmp = source["icmp"];
	        this.other = source["other"];
	    }
	}
	export class TopPortDTO {
	    port: number;
	    protocol: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new TopPortDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.protocol = source["protocol"];
	        this.count = source["count"];
	    }
	}
	export class TopTalkerDTO {
	    ip: string;
	    packets: number;
	    bytes: number;
	
	    static createFrom(source: any = {}) {
	        return new TopTalkerDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.packets = source["packets"];
	        this.bytes = source["bytes"];
	    }
	}
	export class StatsDTO {
	    packets: PacketStatsDTO;
	    bytes: ByteStatsDTO;
	    flows: FlowStatsDTO;
	    protocols: {[key: string]: number};
	    topTalkers: TopTalkerDTO[];
	    topPorts: TopPortDTO[];
	    alertCount: number;
	    fileCount: number;
	    droppedPackets: number;
	    packetsPerSec: number;
	    bytesPerSec: number;
	    memoryUsage: number;
	    captureTime: number;
	    interface: string;
	    isCapturing: boolean;
	
	    static createFrom(source: any = {}) {
	        return new StatsDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.packets = this.convertValues(source["packets"], PacketStatsDTO);
	        this.bytes = this.convertValues(source["bytes"], ByteStatsDTO);
	        this.flows = this.convertValues(source["flows"], FlowStatsDTO);
	        this.protocols = source["protocols"];
	        this.topTalkers = this.convertValues(source["topTalkers"], TopTalkerDTO);
	        this.topPorts = this.convertValues(source["topPorts"], TopPortDTO);
	        this.alertCount = source["alertCount"];
	        this.fileCount = source["fileCount"];
	        this.droppedPackets = source["droppedPackets"];
	        this.packetsPerSec = source["packetsPerSec"];
	        this.bytesPerSec = source["bytesPerSec"];
	        this.memoryUsage = source["memoryUsage"];
	        this.captureTime = source["captureTime"];
	        this.interface = source["interface"];
	        this.isCapturing = source["isCapturing"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class TopologyLinkDTO {
	    source: string;
	    target: string;
	    protocol: string;
	    packets: number;
	    bytes: number;
	
	    static createFrom(source: any = {}) {
	        return new TopologyLinkDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.source = source["source"];
	        this.target = source["target"];
	        this.protocol = source["protocol"];
	        this.packets = source["packets"];
	        this.bytes = source["bytes"];
	    }
	}
	export class TopologyNodeDTO {
	    id: string;
	    ip: string;
	    type: string;
	    packetCount: number;
	    byteCount: number;
	
	    static createFrom(source: any = {}) {
	        return new TopologyNodeDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.ip = source["ip"];
	        this.type = source["type"];
	        this.packetCount = source["packetCount"];
	        this.byteCount = source["byteCount"];
	    }
	}
	export class TopologyDTO {
	    nodes: TopologyNodeDTO[];
	    links: TopologyLinkDTO[];
	
	    static createFrom(source: any = {}) {
	        return new TopologyDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.nodes = this.convertValues(source["nodes"], TopologyNodeDTO);
	        this.links = this.convertValues(source["links"], TopologyLinkDTO);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

