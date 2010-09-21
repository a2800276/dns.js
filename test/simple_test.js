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
      parser = new dns.parser(packet),
      result   = parser.parse()
     
  return result
}

function assert(msg, should, is) {
  if (!should === is) {
    console.log(msg+" failed: should be:"+should+" is "+ is);
    return false
  }
  return true
}
function compare(should, is) {
  var p1 = should,
      p2 = is,
      ret = true

  ret &= assert("complete: ", p1.complete, p2.complete)
  ret &= assert("id: ", p1.id, p2.id)
  ret &= assert("flags.query: ", p1.flags.query, p2.flags.query)
  ret &= assert("flags.opcode: ", p1.flags.opcode, p2.flags.opcode)
  ret &= assert("flags.aa: ", p1.flags.aa, p2.flags.aa)
  ret &= assert("flags.tc: ", p1.flags.tc, p2.flags.tc)
  ret &= assert("flags.rd: ", p1.flags.rd, p2.flags.rd)
  ret &= assert("flags.ra: ", p1.flags.ra, p2.flags.ra)
  ret &= assert("flags.rcode: ", p1.flags.rcode, p2.flags.rcode)

  return ret
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
      var ok = compare(loadJSON(file), loadPacket(pfile)) ? "ok" : "failed"
      console.log(ok)
    }
  }
  
})


