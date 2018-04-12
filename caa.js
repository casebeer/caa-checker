
const dns = require('native-dns');
const CAA_RRTYPE = 257;
const NXDOMAIN = dns.consts.NAME_TO_RCODE.NOTFOUND;
const NOERROR = dns.consts.NAME_TO_RCODE.NOERROR;

const checkCAA = name => {
  console.log(`Checking CAA for ${name}`);
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

      //console.log(err);
      //console.log(response);

      const answers = response.answer.filter(({ type:type }) => type === CAA_RRTYPE)
        .map(({ data: { buffer: buffer }}) => { 
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
        console.log('status: ' + dns.consts.RCODE_TO_NAME[status])
        reject(answers);
      }

    });
     
    req.send();
  });
}

// https://tools.ietf.org/html/rfc6844#section-3
//
//   Given a request for a specific domain X, or a request for a wildcard
//   domain *.X, the relevant record set R(X) is determined as follows:
//
//   Let CAA(X) be the record set returned in response to performing a CAA
//   record query on the label X, P(X) be the DNS label immediately above
//   X in the DNS hierarchy, and A(X) be the target of a CNAME or DNAME
//   alias record specified at the label X.
//
//   o  If CAA(X) is not empty, R(X) = CAA (X), otherwise
//
//   o  If A(X) is not null, and R(A(X)) is not empty, then R(X) =
//      R(A(X)), otherwise
//
//   o  If X is not a top-level domain, then R(X) = R(P(X)), otherwise
//
//   o  R(X) is empty.

const CAA = checkCAA;

const P = name => {
  const parent = name.split(/\.(.+)/)[1];
  if (parent === undefined) {
    return '.';
  }
  return parent;
};

const A = async name => {
  // TODO: DNAME
  // TODO: General DNS query Promise wrapper
  return new Promise((resolve, reject) => {
    dns.resolveCname(name, (err, addresses) => {
      if (!!addresses && addresses.length > 0) {
        resolve(addresses[0]);
      }
      resolve(null);
    });
  });
};
const R = async X => {
  const caa = await CAA(X);
  if (caa.length > 0) {
    return caa;
  }
  const alias = await A(X);
  if (!!alias) {
    const aliasCAA = await R(alias);
    if (aliasCAA.length > 0) {
      return aliasCAA;
    }
  }
  const parent = P(X);
  if (parent !== '.') {
    return R(parent);
  }
  return [];
};

R(process.argv[2]).then(console.log, console.log);

