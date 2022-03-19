import compare from 'k6/x/compare';
import http from 'k6/http';
const url = 'https://maskinporten-systest.dev.eid.digdirnfl.no/token';
//const url = 'https://test1.maskinporten.no/token';

export default function () {
  //console.log(compare.isGreater(2, 1));
  console.log("JWT- assertion",compare.isGreater());




  let data = {
    "assertion": compare.isGreater(),
    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer"
  };

  // Using a JSON string as body
  let res = http.post(url, JSON.stringify(data), {
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
  });


  // Using an object as body, the headers will automatically include
  // 'Content-Type: application/x-www-form-urlencoded'.
  res = http.post(url, data);
  console.log(res.body); // Bert

}
