
var dgram = require('dgram'),
      dns = require('./dns.js')
      enc = require('./dns_encoder.js')

var dumpPacket = function (msg, err, packet) {
  return function (err, packet) {
    console.log(msg)
    console.log(packet.toString())
  }
}

var forward = function (server, msg, rinfo) {
  server.send(msg, 0, msg.length, rinfo.port, rinfo.address)
}

var server = dgram.createSocket('udp4', function(msg, rinfo) {

  console.log("msg.length:" + msg.length);

  var parser = new dns.parser(msg)
      parser.parse(dumpPacket("Question"))

  var proxy = dgram.createSocket('udp4', function(pmsg, prinfo) {
    var rparser = new dns.parser(pmsg)
        rparser.parse(dumpPacket("Answer"))
  
    forward(server, pmsg, rinfo)
  })


  var encoder = new enc.encoder(parser.packet)
  var new_mesg = encoder.encode()

  //proxy.send(msg, 0, msg.length, 53, "8.8.8.8")
  proxy.send(new_mesg, 0, new_mesg.length, 53, "8.8.8.8")

})


server.on("listening", function() {
    var addr = server.address()
    console.log("server listening on "+addr.address+":"+addr.port)
    process.setuid(process.getuid());
})

server.bind(53)
