

var packet  = require('./dns_packet.js'),
    encoder = require('./dns_encoder.js'),
    C       = require('./dns_constants.js')


var p = new packet.packet()

console.log(p.toString());

var e = new encoder.encoder(p);
console.log(e.encode())
p.id = 0x0003
p.flags.query  = true
p.flags.opcode = C.opcode("QUERY")
p.flags.rd = true
p.rcode = 0x0000

var question = {}
    question.qname  = ["www2","google", "com"]
    question.qtype  = 1
    question.qclass = 1

p.questions.push(question)
p.complete = true

console.log(e.encode())

