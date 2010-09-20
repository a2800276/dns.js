var fs = require('fs'),
    dns = require('../lib/dns.js')

var stat = fs.statSync,
    readdir = fs.readdirSync

var dir = process.argv[2]

var files = readdir(dir)

for (var i=0; i!=files.length; ++i) {
  var filename = dir+"/"+files[i],
             s = stat(filename)
               console.log(filename)
  if (s.isFile()) {
    // read
    data = fs.readFileSync(filename)
    parseAndSave(data, filename+".json")
    // parse
    // JSON
    // save
  }
}

function parseAndSave(data, fn) {
  var parser = new dns.parser(data),
      packet = parser.parse()
  
  fs.writeFile(fn, JSON.stringify(packet))
      
}


