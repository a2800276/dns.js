
var Packet = require('./dns_packet.js').packet,
         C = require('./dns_constants.js')



function DNSParser (buffer) {
  this.buffer = buffer
  this.pos    = 0
  this.packet = new Packet()
}

function flags(pflags, bflags) {
  // `pflags` are the flags in the PACKET class which is the target
  // `bflags` are the BINARY flags which are being decoded.
  pflags.query  = (0 == ((bflags[0] & 0x80) >>> 7) )
  pflags.opcode =        (bflags[0] & 0x78) >>> 3
  pflags.aa     = (1 == ((bflags[0] & 0x04) >>> 2) )
  pflags.tc     = (1 == ((bflags[0] & 0x02) >>> 1) )
  pflags.rd     = (1 ==  (bflags[0] & 0x01))
  pflags.ra     = (1 == ((bflags[1] & 0x08) >>> 7) )
  pflags.rcode  = bflags[1] & 0x0F
  // TODO nice rcode ...
}

function nameParser() {
  var name = []

  this.pos += parseCompressed(name, this.pos, this.buffer)

  return name 
}

function parseCompressed = function(name, offset, buffer) {
  var ooffset = offset 
  while(true) {
    if ("" === name[name.length-1]) {
      break
    }
    var len = buffer[offset++]
    if (len == 0x00) {
      name.push("")
      break
    } else if ( (len & 0xC0) != 0) {
      var chainedOffset = buffer[offset++]
          chainedOffset |= (len & ~0xC0) << 8
        
      parseCompressed(name, chainedOffset, buffer)
    } else {
      var nameSlice = buffer.slice(offset, offset+len)
      offset+=len
      name.push(nameSlice.toString('ascii'))
    }
  }
  return offset - ooffset
}



DNSParser.prototype = {
  parse : function() {
    this.parseHeader()
    this.parseQuestion()
    this.parseAnswer()
    this.parseAuthority()
    this.parseAdditional()
    
    this.packet.complete = true
    return this.packet
  },
  parseHeader    : function(){
    this.packet.id = u16()
    flags(this.packet.flags, this.take(2))
    this.packet.questions   = new Array(u16())
    this.packet.answers     = new Array(u16())
    this.packet.authorities = new Array(u16())
    this.packet.additional  = new Array(u16())
  },
  parseQuestion  : function(){
    var qs = this.packet.questions
    for (var i=0; i!= qs.length, ++i) {
      var q = {}
          q.qname  = this.parseName()
          q.qtype  = this.u16()
          q.qclass = this.u16()
      // decode type and class, todo

          q.qtype_name = C.record_type(q.qtype)
      qs[i] = q
    }                 
  },
  parseAnswer    : function(){
    this.parseRRs(this.packet.questions)                 
  },
  parseAuthority : function(){
    this.parseRRs(this.packet.authorities)                 
  },
  parseAdditional: function(){
    this.parseRRs(this.packet.additional)                 
  },
  parseRRs       : function(r_arr) {
    for (var i = 0; i!= r_arr.length; ++i) {
      r_arr[i] = this.parseRR()
    }          
  },
  parseRR        : function() {
    var rr = {}      
        rr.name     = this.parseName()
        rr.type     = this.u16() 
        rr.class    = this.u16()
        rr.ttl      = this.u32()
        rr.rdlength = this.u16()
        rr.rdata    = this.take(rr.rdlength)

        rr.type_name = C.record_type(rr.type)
    // class and type
    return rr
  },
  u16            : function() {
    var buf  = this.take(2),
          i  = buf[1]
          i |= (buf[0] << 8)
    
    return i
  },
  u32            : function() {
    var buf  = this.take(4)
    var   i  = buf[3]
          i |= buf[2] << 8
          i |= buf[1] << 16
          i |= buf[0] << 24
    
    return i      
  },
  take           : function(count) {
   var ret = null,
       pos = this.pos

    try {
      ret = this.buffer.slice(pos, pos+count)
    } 
    catch (e) {
      // TODO error handling.
      lh("pos", pos)
      throw e
    }
    this. pos += count
    return ret
  },
  parseName     : nameParser

}
















function parse(buffer) {
  var parser = new DNSParser(buffer)

  return parser.parse()
}

exports.parse = parse
