
var DNSFlags = function () {
  this.query = null;
  this.opcode = null;
  this.aa = null;
  this.tc = null;
  this.rd = null;
  this.ra = null;
	this.rcode = null;

	this.toString = function () {
		return "\nquery  : " + this.query +
    "\nopcode : " + this.opcode +
    "\naa     : " + this.aa +
    "\ntc     : " + this.tc +
    "\nrd     : " + this.rd +
    "\nra     : " + this.ra +
		"\nrcode   : " + this.rcode 
	}
}

DNSPacket = function(){
	this.complete    = false;
	this.id          = -1;
	this.flags       = new DNSFlags();
	this.questions   = [];
	this.answers     = [];
	this.authorities = [];
	this.additional  = [];

}
DNSPacket.prototype.toString= function () {
		var string =
    "complete : " + this.complete + "\n" +
    "id : " + this.id + "\n" +
    "flags : " + this.flags.toString() + "\n" +

    "questions : " + "\n"
		for (var i in this.questions) {
			string += JSON.stringify(this.questions[i])
			string += "\n"
		}

    string += "answers : " + "\n"
		for (var i in this.answers) {
			string += this.answers[i]	
		}
    string += "authorities : " + "\n"
		for (var i in this.authorities) {
			string += this.authorities[i]	
		}

    string += "additional : " + "\n"
		for (var i in this.additional) {
			string += this.additional[i]	
		}
		return string
	}


//var d = new DNSPacket()
//console.log(d.toString())
exports.flags  = DNSFlags
exports.packet = DNSPacket
