var fs = require('fs'),
    dgram = require('dgram'),
    dns = require('../lib/dns.js')

var dir_name = "test_collect"

function create_dir() {
  fs.stat(dir_name, function(err, stats) {
    if (err) {
      if (!err.errno == 2) {
        console.log("fs.stat returned: "+err+",giving up")
        process.exit(1)
      }
    } else if (stats.isDirectory()) {
      console.log(dir_name + ": already exists, cowardly giving up.")
      process.exit(1)
    }

    fs.mkdir(dir_name, 0755, function(err, files) {

      if (err) {
        console.log("Couldn't create "+dir_name+" giving up.")
      }
    })

  })
}


function create_server(callback) {
  var server = dgram.createSocket('udp4', function(msg, rinfo) {
    console.log("here")
    
    var parser = new dns.parser(msg),
        packet = parser.parse(),
        file   = fs.createWriteStream(dir_name+"/"+packet.id)
    file.write(msg)
    file.end()
  })

  server.on("listening", function() {
    console.log("server ready")
    process.setuid(process.getuid())

    callback()
  })

  server.bind(53)
}

create_server(create_dir)


