var dns = require('./dns_packet.js'),
      C = require('./dns_constants.js')


var between = function(value, min, max) {
  return (value >= min) && (value <= max)
}

/************************************************************************3Y
 * DEBUGGING (temporary)
************************************************************************/
var log = function (msg) {
  console.log(msg)
  process.stdout.flush()
}
function lh (msg, num) {
  log(msg +": "+num.toString(16))
}

/************************************************************************3Y
 * DEBUGGING (temporary)
************************************************************************/

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
    return self.packet
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

    header.qr   = (header[0] & 0x80) >>> 7
    flags.query = (header.qr == 0)

    flags.opcode = (header[0] & 0x78) >>> 3

    header.aa = (header[0] & 0x04) >>> 2
    flags.aa  = (header.aa ==1)

    header.tc = (header[0] & 0x02) >>> 1
    flags.tc  = (header.tc == 1)

    header.rd = (header[0] & 0x01)
    flags.rd  = (header.rd == 1)

    header.ra = (header[1] & 0x80) >>> 7
    flags.ra  = header.ra == 1

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
    for (var i =0; i!= self.header.qdcount; ++i) { 
      var question        = {}
          question.qname  = parseQname()
          question.qtype  = u16()
          question.qclass = u16()

      handleQtype (question)
      handleQclass(question)
      
      self.packet.questions.push(question)
    }
  }
  /*
   * incorrectly named, should be parseName
   * handling compressed names is a bit tricky.
   * 
   * names are encoded: 
   *  <num>(1byte)<name>(`num` bytes)
   *
   * names are delimited with a `num` value of 0
   * 
   * UNLESS the two high bits of `num` are set, in which
   * case a name the value of num and the following bytes
   * (minus the two high bits of `num`) are an absolute
   * offset into the packet and point at the location
   * of the compressed value. This location may in turn 
   * also use compression...
   *
   * this function will return the name as an array of
   * strings, finally delimited with an empty string, e.g.
   * 
   *  www.example.com (03www07example03com) 
   *
   *    will return
   *  
   *  ["www","example","com", ""]
   *
   *  This function is nearly copy&pasted below, the first 
   *  version reads names off the buffer, advancing the 
   *  current position, the second version reads compressed 
   *  strings from arbitrary positions within the buffer.
   */

  var parseQname = function () {
    var name     = [],
        orig_pos = pos
    

    while (true) {
      if ("" === name[name.length-1]) {
        // previous passed reached the end of the string.
        break
      }

      var len = take(1)
      if (len[0] == 0x00) {
        //reached the end of the string.
        name.push("")
      } else if ( (len[0] & 0xC0) != 0) {
        // reached a compressed string, follow offset.
        var offset = take(1)[0]
            offset |= (len[0] & ~0xC0) << 8
        
        // probably entirely superfluous premature optimization
        // check if this compressed name has already been used.
        if (!nameCache[offset]) { 
          nameCache[offset] = parseCompressed(offset)
        }

        name = name.concat( nameCache[offset] )
      } else {
        name.push( take(len[0]).toString('ascii') );
      }
    } 

    nameCache[orig_pos] = name
    return name
  }

  /*
   * See above
   * Fuck this! compression chains are possible...
   */
  var parseCompressed = function(offset) {
    var name = []
      
    while(true) {
      if ("" === name[name.length-1]) {
        break
      }
      var len = buffer[offset++]
      if (len == 0x00) {
        name.push("")
      } else if ( (len & 0xC0) != 0) {
        var chainedOffset = buffer[offset++]
            chainedOffset |= (len & ~0xC0) << 8
          
        name = name.concat(parseCompressed(chainedOffset))
      } else {
        var nameSlice = buffer.slice(offset, offset+len)
        offset+=len
        name.push(nameSlice.toString('ascii'))
      }
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
  
  /*
   * this needs to be moved to dns_constants
   */
  var handleType = function(rr) {
    
    rr.type_name = C.record_type(rr.type)

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

    var ret = null
    try {
      ret = buffer.slice(pos, pos+count)
    } 
    catch (e) {
      log(e);
      lh("pos", pos)
      throw e
    }
    pos += count
    return ret
  }

  
}
exports.parser = DNSParser
