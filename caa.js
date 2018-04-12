
const dns = require('native-dns');
const CAA_RRTYPE = 257;
const SERVFAIL = dns.consts.NAME_TO_RCODE.SERVFAIL;

const checkCAA = name => {
  const req = dns.Request({
    question: dns.Question({
        name: name,
        type: CAA_RRTYPE,
    }),
    server: { address: '8.8.8.8', port: 53, type: 'udp' },
    timeout: 60000,
  });
   
  req.on('timeout', () => {
    console.log('Timeout in making request');
  });
   
  req.on('message', (err, response) => {
    //console.log(err);
    //console.log(response);

    response.answer.forEach(({ data: { buffer: buffer }}) => { 
      // [ flags ] [ tagLength ] [ tag ... ] [ value ... ]
      const tagLength = buffer[1];
      const criticalFlag = buffer[0] & 0x1;
      const tag = buffer.toString('ascii', 2, 2 + tagLength); 
      const value = buffer.toString('ascii', 2 + tagLength); 

      //console.log(buffer); 
      console.log(`${criticalFlag} ${tag} ${value};`);
    });
    console.log('status: ' + dns.consts.RCODE_TO_NAME[response.header.rcode])
  });
   
  req.send();
}

checkCAA(process.argv[2]);

