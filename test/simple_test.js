var fs = require('fs'),
    dns = require('../lib/dns.js')

// look through a directory for files with matching *.json files
// parse such files and make sure they correspond to the *.json

function loadJSON(filename) {
  var json = fs.readFileSync(filename)
  return JSON.parse(json)
}

function loadPacket(filename) {
  var packet = fs.readFileSync(filename),
      parser = new dns.parser(packet)
  return parser.parse()
}

function assert(msg, should, is) {
  if (!should === is) {
    console.log(msg+" failed: should be:"+should+" is "+ is);
  }
}
function compare(should, is) {
  var p1 = should,
      p2 = is

  assert("complete: ", p1.complete, p2.complete)
  assert("id: ", p1.id, p2.id)
  assert("flags.query: ", p1.flags.query, p2.flags.query)
  assert("flags.opcode: ", p1.flags.opcode, p2.flags.opcode)
  assert("flags.aa: ", p1.flags.aa, p2.flags.aa)
  assert("flags.tc: ", p1.flags.tc, p2.flags.tc)
  assert("flags.rd: ", p1.flags.rd, p2.flags.rd)
  assert("flags.ra: ", p1.flags.ra, p2.flags.ra)
  assert("flags.rcode: ", p1.flags.rcode, p2.flags.rcode)
}

function exists(fn) {
  try {
    return fs.statSync(fn).isFile()
  } catch (e) {
    return false
  }
}

var dir_name = process.argv[2],
    files    = fs.readdirSync(dir_name)

files.forEach(function (file) {
  if (file.match(/\.json$/)) {
    var pfile = file.replace(/\.json$/, "")
        pfile = dir_name + pfile
        file  = dir_name + file
        
    if (exists(pfile)) {
      console.log(pfile)
      compare(loadJSON(file), loadPacket(pfile))  
    }
  }
  
})


