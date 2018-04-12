
const dns = require('native-dns');
const CAA_RRTYPE = 257;
const NXDOMAIN = dns.consts.NAME_TO_RCODE.NOTFOUND;
const NOERROR = dns.consts.NAME_TO_RCODE.NOERROR;

const checkCAA = name => {
  return new Promise((resolve, reject) => {
    const req = dns.Request({
      question: dns.Question({
          name: name,
          type: CAA_RRTYPE,
      }),
      server: { address: '8.8.8.8', port: 53, type: 'udp' },
      timeout: 60000,
    });
     
    req.on('timeout', () => {
      reject(Error('Timeout in making request'));
    });
     
    req.on('message', (err, response) => {
      const status = response.header.rcode;

      console.log('status: ' + dns.consts.RCODE_TO_NAME[status])
      //console.log(err);
      //console.log(response);

      const answers = response.answer.map(({ data: { buffer: buffer }}) => { 
        // [ flags ] [ tagLength ] [ tag ... ] [ value ... ]
        const tagLength = buffer[1];
        const criticalFlag = buffer[0] & 0x1;
        const tag = buffer.toString('ascii', 2, 2 + tagLength); 
        const value = buffer.toString('ascii', 2 + tagLength); 

        //console.log(buffer); 
        return `${criticalFlag} ${tag} ${value};`;
      });

      // any error rcode other than NXDOMAIN is a critical error
      if (status === NOERROR || status === NXDOMAIN) {
        resolve(answers);
      } else {
        reject(answers);
      }

    });
     
    req.send();
  });
}

checkCAA(process.argv[2]).then(console.log, console.log);

