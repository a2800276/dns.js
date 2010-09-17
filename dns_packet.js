
DNSFlags = {
  query : false,
  opcode: "",
  aa    : "",
  tc    : "",
  rd    : "",
  ra    : "",
  resp  : ""
}

DNSPacket = {
  id    : "",
  flags : new DNSFlags(),
  questions : [],
  answers   : [],

  
}
