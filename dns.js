var dns = require('./dns_packet.js')


var between = function(value, min, max) {
  return (value >= min) && (value <= max)
}

DNSParser = function (buffer) {
  var self   = this
  var buffer = buffer
  var pos    = 0
  var nameCache = {}
	this.packet = new dns.packet()

  this.parse = function (callback) {
    parseHeader()
    parseQuestion()
    parseAnswer()
    parseAuthority()
    parseAdditional()
    self.packet.complete = true
    if (callback) {
      callback(null, self.packet)
    }
  }


  var parseHeader = function () {
    var header = {}
        header.id      = u16(); 
        header.flags   = take(2)
        header.qdcount = u16(); 
        header.ancount = u16()
        header.nscount = u16()
        header.arcount = u16()

    handleFlags(header.flags)
    self.header = header
		self.packet.id = header.id
  }

  var handleFlags = function (header) {
		var flags = self.packet.flags

    header.qr = (header[0] & 0x80) >>> 7
		flags.query = (header.qr == 0)

    flags.opcode = (header[0] & 0x78) >>> 3
     

    header.aa = (header[0] & 0x04) >>> 2
		flags.aa = (header.aa ==1)

    header.tc = (header[0] & 0x02) >>> 1
		flags.tc = (header.tc == 1)

    header.rd = (header[0] & 0x01)
		flags.rd = (header.rd == 1)

    header.ra = (header[1] & 0x80) >>> 7
		flags.ra = header.ra == 1

    // header.zz -> ignore
    
    header.rcode = (header[1] & 0x0F) 
		flags.rcode  = header.rcode
    switch ( header.rcode ) {
      case 0 : flags.response = "No error condition"; break
      case 1 : flags.response = "Format error"; break
      case 2 : flags.response = "Server failure"; break
      case 3 : flags.response = "Name Error"; break
      case 4 : flags.response = "Not Implemented"; break
      case 5 : flags.response = "Refused"; break
      default: flags.response = "RFU"; break
    }

  }

  var parseQuestion = function () {
    for (var i =0; i!= self.header.qdcount; ++i) { // TODO
      var question        = {}
          question.qname  = parseQname()
          question.qtype  = u16()
          question.qclass = u16()

      handleQtype (question)
      handleQclass(question)
      
      self.packet.questions.push(question)
    }
  }

  var parseQname = function () {
    var name = []
    var opos = pos
    nameCache[pos] = name
    while (true) {
      var len = take(1)
      if (len[0] == 0x00) {
        break;
      }
      if ( (len[0] & 0xC0) != 0) {
        var offset = take(1)[0]
            offset |= (len[0] & ~0xC0) << 8
        return nameCache[offset]
      }
      name.push( take(len[0]).toString('ascii') );
    }  
    return name
  }

  var parseAnswer = function () {
    parseRRs(self.packet.answers, self.header.ancount)
  }
  var parseAuthority = function () {
    parseRRs(self.packet.authorities, self.header.nscount)
  }
  var parseAdditional = function () {
    parseRRs(self.packet.additional, self.header.arcount)
  }

  var parseRRs = function (into, count) {
    for (var i = 0; i!= count; ++i) {
      into.push(parseRR())
    }
  }

  var parseRR = function() {
    var rr = {}
        rr.name     = parseQname()
        rr.type     = u16() 
        rr.class    = u16()
        rr.ttl      = u32()
        rr.rdlength = u16()
        rr.rdata    = take(rr.rdlength)

    handleType (rr)
    handleClass(rr)

    return rr
  }

  var handleType = function(rr) {
    // from http://www.iana.org/assignments/dns-parameters
    switch(rr.type) {
    case 1 :
      rr.type_name = "A";
      rr.type_desc = "a host address [RFC1035]";
      break;

    case 2 :
      rr.type_name = "NS";
      rr.type_desc = "an authoritative name server [RFC1035]";
      break;

    case 3 :
      rr.type_name = "MD";
      rr.type_desc = "a mail destination (Obsolete - use MX) [RFC1035]";
      break;

    case 4 :
      rr.type_name = "MF";
      rr.type_desc = "a mail forwarder (Obsolete - use MX) [RFC1035]";
      break;

    case 5 :
      rr.type_name = "CNAME";
      rr.type_desc = "the canonical name for an alias [RFC1035]";
      break;

    case 6 :
      rr.type_name = "SOA";
      rr.type_desc = "marks the start of a zone of authority [RFC1035]";
      break;

    case 7 :
      rr.type_name = "MB";
      rr.type_desc = "a mailbox domain name (EXPERIMENTAL) [RFC1035]";
      break;

    case 8 :
      rr.type_name = "MG";
      rr.type_desc = "a mail group member (EXPERIMENTAL) [RFC1035]";
      break;

    case 9 :
      rr.type_name = "MR";
      rr.type_desc = "a mail rename domain name (EXPERIMENTAL) [RFC1035]";
      break;

    case 10 :
      rr.type_name = "NULL";
      rr.type_desc = "a null RR (EXPERIMENTAL) [RFC1035]";
      break;

    case 11 :
      rr.type_name = "WKS";
      rr.type_desc = "a well known service description [RFC1035]";
      break;

    case 12 :
      rr.type_name = "PTR";
      rr.type_desc = "a domain name pointer [RFC1035]";
      break;

    case 13 :
      rr.type_name = "HINFO";
      rr.type_desc = "host information [RFC1035]";
      break;

    case 14 :
      rr.type_name = "MINFO";
      rr.type_desc = "mailbox or mail list information [RFC1035]";
      break;

    case 15 :
      rr.type_name = "MX";
      rr.type_desc = "mail exchange [RFC1035]";
      break;

    case 16 :
      rr.type_name = "TXT";
      rr.type_desc = "text strings [RFC1035]";
      break;

    case 17 :
      rr.type_name = "RP";
      rr.type_desc = "for Responsible Person [RFC1183]";
      break;

    case 18 :
      rr.type_name = "AFSDB";
      rr.type_desc = "for AFS Data Base location [RFC1183][RFC5864]";
      break;

    case 19 :
      rr.type_name = "X25";
      rr.type_desc = "for X.25 PSDN address [RFC1183]";
      break;

    case 20 :
      rr.type_name = "ISDN";
      rr.type_desc = "for ISDN address [RFC1183]";
      break;

    case 21 :
      rr.type_name = "RT";
      rr.type_desc = "for Route Through [RFC1183]";
      break;

    case 22 :
      rr.type_name = "NSAP";
      rr.type_desc = "for NSAP address, NSAP style A record [RFC1706]";
      break;

    case 23 :
      rr.type_name = "NSAP-PTR";
      rr.type_desc = "for domain name pointer, NSAP style [RFC1348] ";
      break;

    case 24 :
      rr.type_name = "SIG";
      rr.type_desc = "for security signature [RFC4034][RFC3755][RFC2535]";
      break;

    case 25 :
      rr.type_name = "KEY";
      rr.type_desc = "for security key [RFC4034][RFC3755][RFC2535]";
      break;

    case 26 :
      rr.type_name = "PX";
      rr.type_desc = "X.400 mail mapping information [RFC2163]";
      break;

    case 27 :
      rr.type_name = "GPOS";
      rr.type_desc = "Geographical Position [RFC1712]";
      break;

    case 28 :
      rr.type_name = "AAAA";
      rr.type_desc = "IP6 Address [RFC3596]";
      break;

    case 29 :
      rr.type_name = "LOC";
      rr.type_desc = "Location Information [RFC1876]";
      break;

    case 30 :
      rr.type_name = "NXT";
      rr.type_desc = "Next Domain - OBSOLETE [RFC3755][RFC2535]";
      break;

    case 31 :
      rr.type_name = "EID";
      rr.type_desc = "Endpoint Identifier [Patton]";
      break;

    case 32 :
      rr.type_name = "NIMLOC";
      rr.type_desc = "Nimrod Locator [Patton]";
      break;

    case 33 :
      rr.type_name = "SRV";
      rr.type_desc = "Server Selection [RFC2782]";
      break;

    case 34 :
      rr.type_name = "ATMA";
      rr.type_desc = "ATM Address [ATMDOC]";
      break;

    case 35 :
      rr.type_name = "NAPTR";
      rr.type_desc = "Naming Authority Pointer [RFC2915][RFC2168][RFC3403]";
      break;

    case 36 :
      rr.type_name = "KX";
      rr.type_desc = "Key Exchanger [RFC2230]";
      break;

    case 37 :
      rr.type_name = "CERT";
      rr.type_desc = "CERT [RFC4398]";
      break;

    case 38 :
      rr.type_name = "A6";
      rr.type_desc = "A6 (Experimental) [RFC3226][RFC2874]";
      break;

    case 39 :
      rr.type_name = "DNAME";
      rr.type_desc = "DNAME [RFC2672]";
      break;

    case 40 :
      rr.type_name = "SINK";
      rr.type_desc = "SINK [Eastlake]";
      break;

    case 41 :
      rr.type_name = "OPT";
      rr.type_desc = "OPT [RFC2671]";
      break;

    case 42 :
      rr.type_name = "APL";
      rr.type_desc = "APL [RFC3123]";
      break;

    case 43 :
      rr.type_name = "DS";
      rr.type_desc = "Delegation Signer [RFC4034][RFC3658]";
      break;

    case 44 :
      rr.type_name = "SSHFP";
      rr.type_desc = "SSH Key Fingerprint [RFC4255]";
      break;

    case 45 :
      rr.type_name = "IPSECKEY";
      rr.type_desc = "IPSECKEY [RFC4025]";
      break;

    case 46 :
      rr.type_name = "RRSIG";
      rr.type_desc = "RRSIG [RFC4034][RFC3755]";
      break;

    case 47 :
      rr.type_name = "NSEC";
      rr.type_desc = "NSEC [RFC4034][RFC3755]";
      break;

    case 48 :
      rr.type_name = "DNSKEY";
      rr.type_desc = "DNSKEY [RFC4034][RFC3755]";
      break;

    case 49 :
      rr.type_name = "DHCID";
      rr.type_desc = "DHCID [RFC4701]";
      break;

    case 50 :
      rr.type_name = "NSEC3";
      rr.type_desc = "NSEC3 [RFC5155]";
      break;

    case 51 :
      rr.type_name = "NSEC3PARAM";
      rr.type_desc = "NSEC3PARAM [RFC5155]";
      break;

    // 52-54 unassigned

    case 55 :
      rr.type_name = "HIP";
      rr.type_desc = "Host Identity Protocol [RFC5205]";
      break;

    case 56 :
      rr.type_name = "NINFO";
      rr.type_desc = "NINFO [Reid]";
      break;

    case 57 :
      rr.type_name = "RKEY";
      rr.type_desc = "RKEY [Reid]";
      break;

    case 58 :
      rr.type_name = "TALINK";
      rr.type_desc = "Trust Anchor LINK [Wijngaards]";
      break;

    // 59-98 unassigned

    case 99 :
      rr.type_name = "SPF";
      rr.type_desc = "[RFC4408]";
      break;

    case 100 :
      rr.type_name = "UINFO";
      rr.type_desc = "[IANA-Reserved]";
      break;

    case 101 :
      rr.type_name = "UID";
      rr.type_desc = "[IANA-Reserved]";
      break;

    case 102 :
      rr.type_name = "GID";
      rr.type_desc = "[IANA-Reserved]";
      break;

    case 103 :
      rr.type_name = "UNSPEC";
      rr.type_desc = "[IANA-Reserved]";
      break;

    // 104-248 unassigned

    case 249 :
      rr.type_name = "TKEY";
      rr.type_desc = "Transaction Key [RFC2930]";
      break;

    case 250 :
      rr.type_name = "TSIG";
      rr.type_desc = "Transaction Signature [RFC2845]";
      break;

    case 251 :
      rr.type_name = "IXFR";
      rr.type_desc = "incremental transfer [RFC1995]";
      break;

    case 252 :
      rr.type_name = "AXFR";
      rr.type_desc = "transfer of an entire zone [RFC1035][RFC5936]";
      break;

    case 253 :
      rr.type_name = "MAILB";
      rr.type_desc = "mailbox-related RRs (MB, MG or MR) [RFC1035]";
      break;

    case 254 :
      rr.type_name = "MAILA";
      rr.type_desc = "mail agent RRs (Obsolete - see MX) [RFC1035]";
      break;

    case 255 :
      rr.type_name = "*";
      rr.type_desc = "A request for all records [RFC1035]";
      break;

    case 32768 :
      rr.type_name = "TA";
      rr.type_desc = "DNSSEC Trust Authorities [Weiler] 2005-12-13";
      break;

    case 32768 :
      rr.type_name = "DLV";
      rr.type_desc = "DNSSEC Lookaside Validation [RFC4431]"
      break;

    case 65535 :
      rr.type_name = "Reserved";
      rr.type_desc = "Reserved";
      break;

    default :
      if( (between(rr.type,    52,    54))|| 
          (between(rr.type,    59,    98))||
          (between(rr.type,   104,   248))||
          (between(rr.type,   256, 32767))|| 
          (between(rr.type, 32770, 65279)) 
        ) {
        rr.type_name = "Unassigned"
        rr.type_desc = "Unassigned"
      } else if ( between(rr.type, 65280, 65534)) {
        rr.type_name = "Private" 
        rr.type_desc = "Private" 
      } else {
        rr.type_name = "<unknown>" 
        rr.type_desc = "<unknown>" 
        
      }
    } // end switch
  }
  var handleQtype = function(q) {
    var r      = {}
        r.type = q.qtype
    
    handleType(r)

    q.qtype_name = r.type_name
    q.qtype_desc = r.type_desc
  }


  var handleClass = function (rr) {
    switch(rr.class) {
      case 1    : rr.class_name = "IN"; break;// the Internet
      case 2    : rr.class_name = "CS"; break;// the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
      case 3    : rr.class_name = "CH"; break;// the CHAOS class
      case 4    : rr.class_name = "HS"; break;// Hesiod [Dyer 87]
      case 254  : rr.class_name = "NONE"; break;
      case 255  : rr.class_name = "*";  break;// any class    
      case 0    :
      case 65535:
                  rr.class_name = "Reserved"; break;
      default   : 
        if ( between(rr.class, 5, 252) || between(rr.class, 256, 65279) ) {
          rr.class_name = "Unassigned"
        } else if (between(rr.class, 65280, 65534)) {
          rr.class_name = "Reserved for private use"
        } 
    }
  }

  var handleQclass = function(q) {
    var r = {}
        r.class = q.qclass

    handleClass(r)
    q.qclass_name = r.class_name
  }

  var u16 = function () {
    var buf  = take(2)
    var   i  = buf[1]
          i |= (buf[0] << 8)
    
    return i
  }

  var u32 = function () {
    var buf  = take(4)
    var   i  = buf[3]
          i |= buf[2] << 8
          i |= buf[1] << 16
          i |= buf[0] << 24
    
    return i
  }
  var take = function (count) {
    var ret = buffer.slice(pos, pos+count)
    pos += count
    return ret
  }

  
}
exports.parser = DNSParser
