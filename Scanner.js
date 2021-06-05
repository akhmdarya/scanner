var express = require("express");

var portscanner = require('portscanner');


var cors = require('cors');
const isPortReachable = require('is-port-reachable');
var app = express();
app.listen(4400, () => {
  console.log("Server running on port 4400");
});
app.use(cors())

app.use(express.static(__dirname + '/build'));


app.get("/parse", async (req, res, next) => {
  const queryObject = req.query.url;
  const kek = await checker(queryObject);
  console.log(kek);
  res.send(kek);

});



app.get("/", async (req, res) => {
  res.sendFile(__dirname + '/build/index.html');
});


app.get("*", async (req, res) =>{
  res.sendFile(__dirname+'/build/index.html');
})
const puppeteer = require('puppeteer');
const PuppeteerHar = require('puppeteer-har');
const tcpp = require('tcp-ping');
const util = require('util');
const qs = require('qs');
const dns = require('dns');

const fetch = require('node-fetch');
const { getParsedCommandLineOfConfigFile } = require("typescript");

const getBrowserData = async (url, timeout) => {
  const browser = await puppeteer.launch();
  const context = await browser.createIncognitoBrowserContext();
  const page = await context.newPage();
  const data = {};

  const recording = new PuppeteerHar(page);
  await recording.start();

  await page.goto(url);
  await page.waitFor(timeout);

  data.har = await recording.stop();

  data.cookies = await page._client.send('Network.getAllCookies');

  data.localStorage = await page.evaluate(() => Object.assign({}, window.localStorage));
  // const reacheable=await 
  // portscanner.checkPortStatus(22, url).then(status => {
  //  const portStatus=status;
  //    data.ports.push(portStatus);
  // });


  data.sessionStorage = await page.evaluate(() => Object.assign({}, window.sessionStorage));

  data.caches = await page.evaluate(async () => {
    const result = {};
    if ('caches' in window) {
      const cacheNames = await window.caches.keys();
      for (const name of cacheNames) {
        result[name] = {};
        const cache = await window.caches.open(name);
        for (const request of await cache.keys()) {
          response = await cache.match(request);
          result[name][request.url] = response;
        }
      }
    }
    return result;
  });

  data.indexedDB = await page.evaluate(async () => {
    const result = {};
    const databases = await window.indexedDB.databases();

    const connect = (database) => new Promise(function (resolve, _) {
      const request = window.indexedDB.open(database.name, database.version);
      request.onsuccess = _ => resolve(request.result);
    });

    const getAll = (db, objectStoreName) => new Promise(function (resolve, _) {
      const request = db.transaction([objectStoreName]).objectStore(objectStoreName).getAll();
      request.onsuccess = _ => resolve(request.result);
    });

    for (database of databases) {
      const db = await connect(database);
      const dbName = db.name;
      result[dbName] = {};
      for (objectStoreName of db.objectStoreNames) {
        result[dbName][objectStoreName] = [];
        const values = await getAll(db, objectStoreName);
        result[dbName][objectStoreName] = values;
      }
    }
    return result;
  });
  await browser.close();

  return data;
};

const sortUnique = (a) => a.sort().filter(function (elem, index, arr) {
  return index == arr.length - 1 || arr[index + 1] != elem;
});

const getFlags = (entries) => {

  // get all domains
  const domains = sortUnique(entries.map(e => new URL(e.request.url).host));

  // initialize flags
  const flags = domains.reduce((flags, domain) => {
    flags[domain] = {};
    return flags;
  }, {});

  // set no_ssl 
  // const noSslEntries = entries.filter(e => new URL(e.request.url).protocol === 'http:');
  // const noSslDomains = sortUnique(noSslEntries.map(e => new URL(e.request.url).host));
  // noSslDomains.forEach(domain => flags[domain]['no_ssl'] = true);

  // google analytics ga_aip flag
  const gaDomain = '.google-analytics.com';
  const gaEntries = entries.filter(e => {
    const u = new URL(e.request.url);
    return (u.host.endsWith(gaDomain)) && (u.pathname.endsWith('/collect') || u.pathname.endsWith('/__utm.gif'));
  });
  for (e of gaEntries) {
    const u = new URL(e.request.url);
    const get = e.request.queryString.reduce((get, pair) => {
      get[pair.name] = pair.value;
      return get;
    }, {});
    const post = e.request.postData ? qs.parse(e.request.postData.text) : {};
    const aip = 'aip' in get || 'aip' in post;
    flags[u.host][aip ? 'google_anonymip' : 'google_no_anonymip'] = true;
  }

  // set domain flags
  const domainFlags = {

    'fonts.googleapis.com': 'g_fonts',
    'stats.g.doubleclick.net': 'Google_DoubleClick_Ads',
    'googleads.g.doubleclick.net ': 'Google DoubleClick Ads',
    'px.ads.linkedin.com': 'li_ads',
    'connect.facebook.net': 'Facebook_Connect',
    'ping.chartbeat.net': 'Chartbeat_Analytics',
    'bam.nr-data.net': 'nr_in_us',

  };
  for (const domain of Object.keys(flags)) {
    if (domain in domainFlags) {
      const flag = domainFlags[domain];
      flags[domain][flag] = true;
    }
  }

  return flags;
};

const getDnsData = async (flags) => {

  const domains = Object.keys(flags);

  const nslookup = util.promisify(dns.lookup);
  const lookups = await Promise.all(domains.map((domain) => nslookup(domain)));
  const ips = domains.reduce((acc, domain, i) => (acc[domain] = lookups[i].address, acc), {});

  const rlookup = util.promisify(dns.reverse);
  const rlookups = await Promise.all(domains.map((domain) => rlookup(ips[domain]).catch(_ => [''])));
  const reverses = domains.reduce((acc, domain, i) => (acc[domain] = rlookups[i][0], acc), {});


  const ping = util.promisify(tcpp.ping);
  const times = {};
  for (var i = 0; i < 3; i++) {
    for (const domain of domains) {
      await new Promise(r => setTimeout(r, 100));
      const time = await ping({
        address: ips[domain],
        port: flags[domain]['no_ssl'] ? 80 : 443,
        attempts: 1
      });
      if (domain in times) {
        times[domain] = Math.min(times[domain], time.min);
      } else {
        times[domain] = time.min;
      }
    }
  }

  return {
    ips: ips,
    hostnames: reverses,
    pings: times
  };
};

const getLocationData = async (ips) => {
  const results = await fetch('http://ip-api.com/batch?fields=continentCode,country,org', {
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    method: 'POST',
    body: JSON.stringify(Object.values(ips))
  }).then(res => res.json());
  return Object.keys(ips).reduce((acc, domain, i) => (acc[domain] = results[i], acc), {});
};


const getData = async (url) => {

  // try{
  browserData = await getBrowserData(url, 2000);


  const entries = browserData.har.log.entries.filter(e => e.request.url);
  const flags = getFlags(entries);
  const dnsData = await getDnsData(flags);
  const locations = await getLocationData(dnsData.ips);
  const data = {
    domains: [],
    cookies: [],
    sessionStorage: [],
    localStorage: [],
    // ports:[]
  }




  for (domain of Object.keys(flags)) {
    const result = {
      domain: domain
    }
    result.flag = Object.keys(flags[domain]);
    result.ping = Math.round(dnsData.pings[domain]);
    result.hostname = dnsData.hostnames[domain];
    result.contintent = locations[domain].continentCode == 'EU' ? 'EU' : '';
    result.country = locations[domain].country;
    result.organization = locations[domain].org;
    data.domains.push(result);
  }
  for (cookie of browserData.cookies.cookies) {
    const fields = ['name', 'value', 'domain', 'path', 'expires', 'size', 'httpOnly', 'secure', 'session', 'priority', 'sameSite', 'flagCookies']





    const cookieFlags = ['_gid', '_gat', '_ga', 'VISITOR_INFO1_LIVE*', 'ASP.NET_SessionId', '__zjc*', 'language', 'CookieControl',
      '_ym_isad', '_ym_uid', '_ym_d', '_ym_visorc_NNNNN', '1P_JAR', 'NID', '	SSID', 'SIDCC', '	SID'];
    for (const cookieFlag of cookieFlags) {
      if ((cookieFlag === cookie.name)) {
        cookie.flagCookies = cookieFlag;

      }

    }

    data.cookies.push(cookie);
  }


  for (key of Object.keys(browserData.sessionStorage)) {
    data.sessionStorage.push({
      key: key,
      value: browserData.sessionStorage[key],
      type: "session"
    });
  }
  for (key of Object.keys(browserData.localStorage)) {

    let flag = ''


    const localStorageFlags = ['_ym_synced', '_ym_retryReqs', '_ym_uid', '_reqNum', '_lsid', '	sb_wiz.'];
    for (const localStorageFlag of localStorageFlags) {
      if ((key.includes(localStorageFlag))) {
        // console.log('TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT');
        data.localStorage.flaglocalStorage = localStorageFlag;
        data.localStorage.push({ flaglocalStorage: browserData.localStorage.flaglocalStorage })
        flag = data.localStorage.flaglocalStorage;

      }
    }
    data.localStorage.push({
      key: key,
      value: browserData.localStorage[key],
      type: "local",
      flaglocalStorage: flag

    });

  }
  return data;

};

function checkPorts(url1) {
  let response = [];
  const Evilscan = require('evilscan');

  const options = {
    target: url1,
    port: '1-65535',
    status: 'O', // Timeout, Refused, Open, Unreachable

    banner: true
  };
  new Evilscan(options, (err, scan) => {

    if (err) {
      console.log(err);
      return;
    }

    scan.on('result', data => {
      response.push(data);
    });
    scan.on('error', err => {
      throw new Error(data.toString());

    });
    scan.on('done', () => {
    });

    scan.run();
  });
  return response;

}



async function checker(url1) {
  let response = [];
  response = checkPorts(url1);
  //url1='82.200.154.121';
  if (/(([0-9]{1,3}[\.]){3}[0-9]{1,3})/.test(url1)) {
    dns.lookupService(url1, 80, (err, hostname, service) => {
      console.log(hostname, service);
      url1 = hostname;
      console.log(url1 + "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
      // Prints: localhost ssh
    });
  }
  const arg = url1;
  const url = arg.startsWith('http') ? arg : 'http://' + arg;



  try {

    const data = await getData(url);
    for (key of Object.keys(data)) {
      console.log('==' + key + '==');
      for (record of data[key]) {
        response.push(record)

      }
    }


  } catch (e) {
    console.log(e);
  }

  return response;

}