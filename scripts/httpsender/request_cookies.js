var COOKIE_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.cookie;
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');

function sendingRequest(msg, initiator, helper) {
	// Debugging can be done using println like this
	var cookiesStr = ScriptVars.getGlobalVar("custom_cookies");
	var cookiesParsed = JSON.parse(cookiesStr)

	// add the saved authentication token as an Authentication header and a cookie
	var cookies = msg.getRequestHeader().getCookieParams();
	var cookiesKeys = Object.keys(cookiesParsed)
	for(var i = 0; i < cookiesKeys.length; i++) {
		var key = cookiesKeys[i]
		var cookie = new HtmlParameter(COOKIE_TYPE, key, cookiesParsed[key]);
		cookies.add(cookie);
	}
	msg.getRequestHeader().setCookieParams(cookies);
}

function responseReceived(msg, initiator, helper) {
	// Debugging can be done using println like this
	print('responseReceived called for url=' + msg.getRequestHeader().getURI().toString())
}