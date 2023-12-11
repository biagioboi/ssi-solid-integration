//var form = document.getElementById("submit");
//var jwt = "";
//function setItem() {
//console.log("OK");
//window.location.href = 'showCredential.html';
//}
//
//function onError(error) {
//console.log(error)
//}
//
//
//function onRemoved(){
//	console.log("Rimosso");
//	browser.tabs.create({url: "http://localhost:8080/admin"});
//	window.location.href = 'showCredential.html';
//
//}
//
//function sendCredential(cred){
//
//var myHeaders = new Headers();
//myHeaders.append("Content-Type", "application/json");
//
//
//var requestOptions = {
//  method: 'POST',
//  headers: myHeaders,
//  body: JSON.stringify(cred),
//  redirect: 'follow'
//};
//
//console.log(requestOptions);
//
//fetch("http://localhost:8080/authenticate", requestOptions)
//  .then(response =>
//  	response.json()
//
//  )
//  .then(result => {
//
//		jwt = "Bearer " + result.token;
//		addEvent();
//		console.log(jwt);
//
//  	let remove = browser.storage.local.remove("ssi");
//			remove.then(onRemoved, onError);
//
//  })
//  .catch(error => console.log('error', error));
//
//}
//
//async function getCredential(){
//
//var requestOptions = {
//  method: 'GET',
//  redirect: 'follow'
//};
//
//var cred = {
//	username: "",
//		password: ""
//};
//
//var addr = await browser.storage.local.get("addr");
//
//fetch("http://"+addr.addr+"/credentials", requestOptions)
//  .then(response => response.json())
//  .then(result => {
//  			/*
//  			for (let key in result.results[i].attrs) {
//		  		let value = result.results[i].attrs[key];
//		  	}*/
//
//
//  			cred.username = result.results[0].attrs["username"];
//  			cred.password = result.results[0].attrs["password"];
//  			sendCredential(cred);
//  		});
//}
//
//function addAuthorizzazionHeader(e) {
//
//	const asyncRewrite = new Promise((resolve, reject) => {
//    e.requestHeaders.push({name:"Authorization",value:jwt})
//  	console.log(e.requestHeaders);
//    resolve({ requestHeaders: e.requestHeaders });
//
//  });
//
//  return asyncRewrite;
//
///*
//
//  return { requestHeaders: e.requestHeaders };
//  */
//}
//
//
//form.addEventListener("click", getCredential);
//function addEvent(){
//	browser.webRequest.onBeforeSendHeaders.addListener(
//	  addAuthorizzazionHeader,
//	  { urls: ["<all_urls>"] },
//	  ["blocking", "requestHeaders"]
//	);
//}