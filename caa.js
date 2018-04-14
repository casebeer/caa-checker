
const dns = require('native-dns');
const CAA_RRTYPE = 257;
const RESOLVER = '8.8.8.8';
const TIMEOUT = 10000;
const { CNAME, DNAME } = dns.consts.NAME_TO_QTYPE;
const { NOTFOUND:NXDOMAIN, NOERROR } = dns.consts.NAME_TO_RCODE;

// memoization function from http://inlehmansterms.net/2015/03/01/javascript-memoization/
const memoize = function (func) {
  const cache = {};
  return function () {
    const key = JSON.stringify(arguments);
    if (cache[key] === undefined) {
      cache[key] = func.apply(this, arguments);
    }
    return cache[key];
  };
}

const dnsRequest = memoize((name, type) => {
  return new Promise((resolve, reject) => {
    const req = dns.Request({
      question: dns.Question({
          name: name,
          type: type,
      }),
      server: { address: RESOLVER, port: 53, type: 'udp' },
      timeout: TIMEOUT,
    });
     
    req.on('timeout', () => {
      reject(Error('Timeout in making request'));
    });
     
    req.on('message', (err, response) => {
      const { header: { rcode: status }, answer } = response;
      resolve({ answer, status });
    });
    req.send();
  });
});

const checkCAA = async name => {
  //console.log(`Checking CAA for ${name}`);

  const { answer, status } = await dnsRequest(name, CAA_RRTYPE);
  const caa = answer.filter(({ type:type }) => type === CAA_RRTYPE)
    .map(({ data: { buffer: buffer }}) => { 
    // [ flags ] [ tagLength ] [ tag ... ] [ value ... ]
    const criticalFlag = buffer[0] & 0x1;
    const tagLength = buffer[1];
    const tag = buffer.toString('ascii', 2, 2 + tagLength); 
    const value = buffer.toString('ascii', 2 + tagLength); 

    //console.log(buffer); 
    return `${criticalFlag} ${tag} ${value};`;
  });

  return {
    name,
    caa,
    status
  };
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
  const { answer:cnameAnswer } = await dnsRequest(name, CNAME);

  if (!!cnameAnswer && cnameAnswer.length > 0) {
    return cnameAnswer[0].data;
  }
  
  const { answer:dnameAnswer } = await dnsRequest(name, DNAME);

  if (!!dnameAnswer && dnameAnswer.length > 0) {
    return dnameAnswer[0].data;
  }
  
  return null;

};
const R = async (name, results = []) => {
  /*
  [
    git.fuwt.org,
    [
      tools.mgmt.int.fuwt.org,
      mgmt.int.fuwt.org,
      int.fuwt.org,
      fuwt.org
    ],
    fuwt.org
  ]
  */

  //   o  If CAA(X) is not empty, R(X) = CAA (X), otherwise
  const caa = await CAA(name);
  results.push(caa);

  if (caa.caa.length > 0) {
    return results;
  }

  //   o  If A(X) is not null, and R(A(X)) is not empty, then R(X) =
  //      R(A(X)), otherwise
  const alias = await A(name);
  if (!!alias) {
    const aliasResults = await R(alias),
      aliasCAA = aliasResults[aliasResults.length - 1].caa;
    results.push(aliasResults);

    console.log('=---');
    console.log(aliasCAA);
    if (!!aliasCAA && aliasCAA.length > 0) {
      console.log('DONE');
      return results;
    }
  }
  const parent = P(name);
  if (parent !== '.') {
    return R(parent, results);
  }
  return results;
};

const printTree = (results, prefix = '', errorParent = false) => {
  let ERROR = errorParent;
  results.forEach(entry => {
    if (Array.isArray(entry)) {
      console.log(`${prefix}ALIAS for ${entry[0].name}`);
      printTree(entry, prefix + '  ', ERROR);
    } else {
      const { name, caa, status } = entry;
      let message = `${ERROR ? '[IGNORED]' : ''}${prefix}${name}`;

      if (status === NXDOMAIN) {
        message += ' cannot be found';
      } else if (status === NOERROR) {
        if (caa.length === 0) {
          message += ' has no CAA record';
        } else {
          message += ' has CAA: ' + caa.join(' ');
        }
      } else {
        ERROR = true;
        message += ` ERROR ${dns.consts.RCODE_TO_NAME[status]}`;
      }

      console.log(message);
    }
  });
};

R(process.argv[2]).then(printTree, console.log);

