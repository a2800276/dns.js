
var dgram = require('dgram'),
      dns = require('./dns.js')

var server = dgram.createSocket('udp4', function(msg, rinfo) {

  console.log("msg.length:" + msg.length);

  var parser = new dns.parser(msg)
      parser.parse()

  console.log(parser.packet.toString());

})

server.on("listening", function() {
    var addr = server.address()
    console.log("server listening on "+addr.address+":"+addr.port)
    process.setuid(process.getuid());
})

server.bind(53)
