
var dgram = require('dgram'),
      dns = require('./dns.js')

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

  proxy.send(msg, 0, msg.length, 53, "8.8.8.8")

})


server.on("listening", function() {
    var addr = server.address()
    console.log("server listening on "+addr.address+":"+addr.port)
    process.setuid(process.getuid());
})

server.bind(53)
