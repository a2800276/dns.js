

var DNSEncoder = function (packet) {
  var self    = this
  var packet = packet
  var buffer = new Buffer(1024)
  var pos    = 0
  

  this.encode = function () {
    if (packet.complete) {
      encodeHeader()
      encodeQuestions()
      encodeAnswers()
      encodeAuthorities()
      encodeAdditional()
    }
    return buffer.slice(0, pos)
  }

  var encodeHeader = function () {
    u16(packet.id)

    encodeFlags(packet.flags)

    u16(packet.questions.length)
    u16(packet.answers.length)
    u16(packet.authorities.length)
    u16(packet.additional.length)

  }
  
  var encodeFlags = function(flags) {
    var val = 0x0000
    
    if (!flags.query) {
      val = set(val, 0)
    }

    val |= (flags.opcode << 10)
    
    if (flags.aa) {
      val = set(val, 5)
    }
    if (flags.tc) {
      val = set(val, 6)
    }
    if (flags.rd) {
      val = set(val, 7)
    }
    if (flags.ra) {
      val = set(val, 8)
    }
    val |= flags.rcode
    

    console.log(val)
    u16(val)
  }


  var encodeQuestions = function () {
    var questions = packet.questions
    for (var i=0; i!= questions.length; ++i) {
      encodeQname(questions[i].qname)
      u16(questions[i].qtype)
      u16(questions[i].qclass)
    }
  }

  var encodeAnswers = function() {
    encodeRRs(packet.answers);
  }

  var encodeAuthorities = function () {
    encodeRRs(packet.authorities)
  }
  var encodeAdditional = function () {
    encodeRRs(packet.additional)
  }

  var encodeRRs = function(records) {
    for (var i =0; i!=records.length; ++i) {
      encodeRR(records[i])
    }
  }
  var encodeRR = function(record) {
    encodeQname(record.name)
    u16(record.type)
    u16(record.class)
    u32(record.ttl)
    
    encodeRData(record)
  }

  var encodeRData = function (record) {
  
    var len = -1
    if (record.rdlength != undefined) {
      len = record.rdata.length  
    } else {
      len = record.rdlength;
    }
    u16(len)

    var rdata = null
    if (typeof(record.rdata) === "string") {
      rdata = new Buffer(record.rdata, "binary") // ?? TODO
    } else {
      // assume buffer
      rdata = record.rdata
    }

    rdata.copy(buffer, pos, 0)
    pos += len
  }

  var encodeQname = function(name) {
    /* stupid initial imp with no compression */
    /* name is an array like so: ["safebrowsing-cache","google","com"] */
    for (var i=0; i!=name.length; ++i) {
      encodeQnamePart(name[i])
    }
    buffer[pos++] = 0x00
  }

  var encodeQnamePart = function(namePart) {
    var l = namePart.length
    buffer[pos++] = l 
    buffer.write(namePart, pos, 'ascii')
    pos += l
  }

  /* set bits 0 - 15 of num  and returns
   * num with this corresponding bit set
   */
  var set = function(num, bit) {
    num |= (0x8000 >>> bit)
    return num
  }

  var u16 = function(num) {
    buffer[pos++] = (num >>> 8) & 0xff
    buffer[pos++] = num & 0xff

    console.log(num)
    console.log(buffer.slice(0, pos))
  }
}

exports.encoder = DNSEncoder
