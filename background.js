// this is the background code...

// listen for our browerAction to be clicked
// for the current tab, inject the "inject.js" file & execute it


var currentTab;
var version = "1.0";

chrome.tabs.query( //get current Tab
    {
        currentWindow: true,
        active: true
    },
    function(tabArray) {
        currentTab = tabArray[0];
        chrome.tabs.executeScript(currentTab.ib, {
            file: 'inject.js'
        });
    }
)

chrome.storage.sync.get(['ranOnce'], function(ranOnce) {
    if (! ranOnce.ranOnce){
        chrome.storage.sync.set({"ranOnce": true});
        chrome.storage.sync.set({"originDenyList": ["https://www.google.com"]});
    }

})


let specifics = {
    "Slack Token": "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "AWS Secret Access key": "(?is)aws.{0,30}secret.{0,30}\\b([0-9a-z/+]{40})\\b",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9a-f]{32}['|\"]",
    "GitHub": "[gG][iI][tT][hH][uU][bB].{0,20}['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "GitHub V2": "(?i)\\b([\\w\\-]{11}:apa91b[\\w\\-+]{134})\\b",
   // "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
   // "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
   // "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
   // "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
   // "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
   // "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
   // "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
   // "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
   // "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
   // "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Json Web Token" : "eyJhbGciOiJ",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Stripe Webhook URL": "(whsec_[0-9a-zA-Z]{32,64})",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Github Auth Creds": "https:\/\/[a-zA-Z0-9]{40}@github\.com",
    
    "OpenAi Organization": "org-[\\w]{24}",
    "OpenAi Secret Token": "sk-[\\w]{48}",
    "Airtable API Key": "(?i)\\bkey[\\w]{14}\\b",
    "Alchemy API Key": "\\.alchemyapi\\.io/v2/([\\w-]{32})",
    "Discord Webhook URL": "((https://)?discord(app)?\\.com/api/webhooks/\\d{18,}/[a-zA-Z0-9-_]{68})",
    "Django Default secret key": "\\b(django-insecure-[a-z0-9!@#$%^&*(\\-_=+)]{50})",
    "Docker Hub Personal access": "\\b(dckr_pat_[\\w-]{27})\\b",
    "Figma Personal Access Token": "\\b(figd_[a-zA-Z0-9-_]{40})\\b",
    "Google FirebaseLegacy API key": "(?i)\\b([\\w\\-]{11}:apa91b[\\w\\-+]{134})\\b",
    "Alibaba Access Key IDs": "\\b(LTAI[0-9A-Za-z]{12}(:?[0-9A-Za-z]{8})?)\\b",
    "Alibaba Access Key Secrets": "(?i)\\bali(?:yun|baba|cloud).{0,50}['\"`]([0-9a-z]{30})['\"`]",
    "Alibaba Access Key Secrets": "(?i)(?:SECRET_?(?:ACCESS)?_?KEY|(?:ACCESS)?_?KEY_?SECRET)\\b[^0-9a-z]{0,10}([0-9a-z]{30})(?![a-z0-9\\/+=$\\-_])",
    "Artifactory API key": "\\b(AKCp\\d[A-Za-z0-9_-]{68})\\b",
    "Artifactory identity token": "\\b(cmVmdGtuO[A-Za-z0-9_-]{55})\\b",
    "Artifactory access token": "\\b(eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYiLCJraWQiOiJ[A-Za-z0-9_-]{30,}\\.[A-Za-z0-9_-]{100,}\\.[A-Za-z0-9_-]{100,})\\b",
    "AWS Secret Access Keys": "(?i)\\b(?:AWS)?_?SECRET_?(?:ACCESS)?_?KEY\\b.{0,10}\\b([0-9a-z\\/+]{40})\\b",
    "AWS Access Key IDs": "(?i)(?<!Expires.{1,200})\\b((?:AKIA|ASIA)[A-Z0-9]{16})\\b(?!.{1,200}Expires)",
    "AWS Session tokens": "(?i)session_?token(?:\"?\\s*[=:]\\s*\"?|>\\s*)([0-9a-z/+\"\\s=]{50,})(?:\\s*<|\\s*$|\"[;,]?|$)",
    "Azure Storage Account Keys": "AccountKey=([a-zA-Z0-9/\\+]{86}==)",
    "Azure Storage Account Keys": "['\"`]([a-zA-Z0-9/\\+]{86}==)['\"`]",
    "Azure subscription key": "(?is)(?<!@Microsoft\\.KeyVault\\([^)]{1,150})Subscription[_\\-\\.]Key.{1,15}\\b([a-f0-9]{32})\\b",
    "Azure subscription key": "(?is)api\\.[a-z0-9.]*microsoft.com(?:[^\\r\\n]*+\\r?\\n){1,3}?[^\\r\\n]*(?:secret|key).{1,15}\\b([a-f0-9]{32})\\b",
    "Azure subscription key": "(?is)(?:secret|key).{1,15}\\b([a-f0-9]{32})\\b(?:[^\\r\\n]*+\\r?\n){1,3}?[^\\r\\n]*api\\.[a-z0-9.]*microsoft.com",
    "Clarifai API key": "\\bKey[ \\t]+([a-f0-9]{32})\\b",
    "Clarifai API key": "(?i)clarifai(?:[^\\r\\n]*?\\r?\\n){0,3}?[^\\r\\n]*?(?:key|token).{0,15}?\\b([a-f0-9]{32})\\b",
    "DigitalOcean Personal Access Token": "\\b(do[opr]_v[0-9]_[0-9a-f]{64})\\b",
    "Django secret key": "\\b(django-insecure-[a-z0-9!@#$%^&*(\\-_=+)]{50})",
    "Django secret key": "\\bSECRET_KEY(?:_FALLBACKS)?\\s*=\\s*(?:os\\.getenv|env(?:\\.str)?)\\(\\s*['\"][^'\"\\r\\n]+['\"]\\s*,\\s*(?:default\\s*=\\s*)?['\"]([^'\"\\r\\n]+)",
    "Django secret key": "\\bSECRET_KEY(?:_FALLBACKS)?\\s*=\\s*['\"]([^'\"\\r\\n]+)",
    "Django secret key": "(?m)\\bSECRET_KEY(?:_FALLBACKS)?\\s*=\\s*(.*)$",
    "Docker Hub token": "\\b(dckr_pat_[\\w-]{27})\\b",
    "Facebook app key": "(?i)facebook.{0,15}secret.{1,15}\\b([a-f0-9]{32})\\b",
    "Figma personal access token": "\\b(figd_[a-zA-Z0-9-_]{40})\\b",
    "Legacy Firebase Cloud Messaging API Key": "(?i)\\b([\\w\\-]{11}:apa91b[\\w\\-+]{134})\\b",
    "Github V2 token": "\\b(gh[pusor]_(?<rand>\\w{36,255}))\\b",
    "Github Fine Grained Tokens": "\\b(github_pat_(?<rand>[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}))\\b",
    "Github token": "(?is)(?:client.?secret|access.?token).{1,30}?\\b([a-f0-9]{40})\\b",
    "Gitlab V2 Token": "\\b(glpat-(?<rand>[a-zA-Z0-9_-]{20}))\\b",
    "reCaptcha secret key": "(?si)(?:secret|private).{0,15}\\b(6L[\\w\\-]{6}AAAAA[\\w\\-]{27})\\b",
    "Grafana API token": "\\b(eyJrIjoi[a-zA-Z0-9+/]{48,}(?:={1,2}|\\b))",
    "Grafana Cloud access token": "\\b(glc_eyJ[a-zA-Z0-9+/]{48,}(?:={1,2}|\\b))",
    "Grafana service account token": "\\b(glsa_[a-zA-Z0-9]{32}_[a-f0-9]{8})\\b",
    "Hashicorp Batch token": "\\b((?:hv)?b\\.AAAAAQ[\\w-]{120,})",
    "IBM API keys": "(?is)(?:ibm|apikey).{0,50}['\"`]([a-z0-9_\\-]{44})['\"`]",
    "Infura Api Keys": "\\.infura\\.io/v3/([\\w]{32})",
    "Mailgun Primary Key": "(?i)\\b(key-[a-f0-9]{32})\\b",
    "MongoDB database": "\\bmongo(?:db)?(?:\\+\\w+)?://[^:@/ ]+:([^@/ ]+)@",
    "MongoDB database": "\\bmongo(?:dump|import|restore|sh)?(?=[ \\t]).{0,100}[ \\t](?:-p|--password)[ \\t]+\\\\?[\"']([^\\r\\n\"']{3,})\\\\?[\"']",
    "MongoDB database": "\\bmongo(?:dump|import|restore|sh)?(?=[ \\t]).{0,100}[ \\t](?:-p|--password)[ \\t]+([^\"'\\s]{3,})",
    "Microsoft Teams Webhook Urls": "((?:https://)?[a-z0-9_-]{1,50}\\.webhook\\.office\\.com/webhookb2/[a-z0-9\\-]{1,50}@[a-z0-9\\-]{1,50}/IncomingWebhook/[a-z0-9]{1,50}/[a-z0-9\\-]{1,50})",
    "Amazon MWS authentication tokens": "\\b(amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
    "MySQL database password": "\\bmysqlx?(?:\\+\\w+)?://(?:\\{+[^}]*\\}+|[^{][^:@/ ]+):([^@/ ]{2,})@",
    "MySQL database password": "\\bmysql(?:admin|dump)?(?=[ \\t]).{0,100}[ \\t](?:-p|--password=)(?!\"')([^\\s\"']{3,})",
    "MySQL database password": "\\bmysql(?:admin)?(?=[ \\t]).{0,100}[ \\t](?:-p|--password=)\\\\?[\"']([^\\r\\n\"']{3,})\\\\?[\"']",
    "MySQL database password": "\\bmysql(?:admin)?(?=[ \\t]).{0,100}[ \\t]\\\\?[\"'](?:-p|--password=)([^\\r\\n\"']{3,})\\\\?[\"']",
    "MySQL database password": "\\bMYSQL_PASSWORD=\\\\?[\"']([^\\r\\n\"']+)\\\\?[\"']",
    "MySQL database password": "\\bMYSQL_PASSWORD=(?!\\\\?[\"'])([^\\s]+)(?:$|\\s)",
    "NPM access token": "(npm_[0-9A-Za-z]{36})\\b",
    "ODBC/JDBC Connection String": "\\b[0-9a-z_\\-\\.]+\\.datasource(?:\\.[0-9a-z_\\-\\.]+){0,400}\\.password[ \\t]*=[ \\t]*(?!\")([^\\s]+)",
    "ODBC/JDBC Connection String": "\\bjdbc:[^\"\\s?]+\\?(?:[^&\"\\s]+&){0,400}password=([^&\"'`\\s]+)[&\"'`\\s]",
    "ODBC/JDBC Connection String": "(?i)[;\"](?:password|pwd)=([^;\"'\\r\\n]+)[;\"'\\r\\n]",
    "ODBC/JDBC Connection String": "(?<!\"[^\\r\\n\"]{0,6})\\b[0-9a-z_\\-\\.]+\\.datasource(?:\\.[0-9a-z_\\-\\.]+){0,400}\\.password[ \\t]*=[ \\t]*\"([^\"]+)\"",
    "OpenWeather API key": "\\bapi\\.openweathermap\\.org\\b.*?appid=([a-f0-9]{32})",
    "Planetscale database": "(?i)\\b(pscale_pw_[\\w\\-\\.]{43})",
    "PostgreSQL database": "\\bPG_PASSWORD=\\\\?[\"']([^\\r\\n\"']+)\\\\?[\"']",
    "PostgreSQL database": "\\bPGPASSWORD=\\\\?[\"']([^\\r\\n\"']+)\\\\?[\"'].{1,40}\\bpsql\\b",
    "PostgreSQL database": "\\bPGPASSWORD=(?!\\\\?[\"'])([^\\s;]+).{1,40}\\bpsql\\b",
    "PostgreSQL database": "\\bPG_PASSWORD=(?!\\\\?[\"'])([^\\s]+)(?:$|\\s)",
    "PostgreSQL database": "\\bpostg(?:res(?:ql)?|is)(?:\\+\\w+)?://[^:@/ ]+(?::[^:@/ ]+){0,100}?:\\$\\{[^:]+:-([^@/ ]+)\\}@",
    "PostgreSQL database": "(?is)(?<!regex.{1,50})\\bpostg(?:res(?:ql)?|is)(?:\\+\\w+)?://[^:@/ ]++:([^@/ ]++)@",
    "Postman token": "\\b(PMAK-(?i)[a-f0-9]{24}\\-[a-f0-9]{34})\\b",
    "PyPI API token": "\\b(pypi-[a-zA-Z_\\-0-9]{150,})\\b",
    "Rabbit MQ": "\\bamqp(?:s)?://(\\w+:[^@\\s]+)@[-\\w%.\\+]+\\b[-\\w%.\\+()@:~#?&/=]*",
    "RapidAPI key": "\\b([a-f0-9]{10}msh[a-f0-9]{15}p[a-f0-9]{6}jsn[a-f0-9]{12})\\b",
    "Redis URL": "\\bredis(?:s)?://(\\w+:[^@\\s]+)@[-\\w%.\\+]+\\b[-\\w%.\\+()@:~#?&/=]*",
    "Riot API key": "\\b(RGAPI-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\\b",
    "Sendgrid key": "\\b(SG\\.[a-zA-Z0-9_\\-]{20,}\\.[a-zA-Z0-9_\\-]{40,})\\b",
    "Shippo token": "\\b(shippo_live_[a-f0-9]{40})\\b",
    "Shopify Partners CLI token": "\\b(atkn_[a-f0-9]{64})\\b",
    "Shopify Partners API token": "\\b(prtapi_[a-f0-9]{32})\\b",
    "Shopify app access token": "\\b(shp(at|ca|pa|ua)_[a-f0-9]{32})\\b",
    "Shopify app shared secret": "\\b(shpss_[a-f0-9]{32})\\b",
    "Slack Incoming Webhook URLs": "((https://)?hooks\\.slack\\.com/services/T[A-Za-z0-9+\\/]{42,45})",
    "Slack Workflow Webhook URLs": "((https://)?hooks\\.slack\\.com/workflows/T[A-Za-z0-9+\\/]{42,70})",
    "Slack Bot Tokens": "(xox[bpar]\\-\\d{10,13}\\-\\d{10,13}-[\\w\\-]+)",
    "SonarQube token": "\\b(sq[apu]_[0-9a-f]{40})\\b",
    "SonarQube token": "(?is)\\bD?sonar(?:qube)?[_.]?(?:login|token)\\b.{1,30}?\\b([0-9a-f]{40})\\b(?<!sq[apu]_.{40})",
    "Spotify API secret": "(?i)spotify(?:[^\\r\\n]*?\\r?\\n){0,3}?[^\\r\\n]*secret.{0,15}?\\b([a-f0-9]{32})\\b",
    "SSH PuTTY": "(PuTTY-User-Key-File-\\d+:)",
    "Typeform personal access token": "\\b(tfp_[a-zA-Z0-9-_]{44}_[a-zA-Z0-9-_]{12,14})\\b",
    "WakaTime OAuth refresh token": "\\b(waka_ref_[a-zA-Z\\d]{80})\\b",
    "WakaTime OAuth secret": "\\b(waka_sec_[a-zA-Z\\d]{80})\\b",
    "WakaTime OAuth token": "\\b(waka_tok_[a-zA-Z\\d]{80})\\b",
    "WeChat app key": "\\bwx[a-f0-9]{16}\\b(?:[^\\r\\n]*?\\r?\\n){0,5}?[^\\r\\n]*?\\b([a-f0-9]{32})\\b",
    "Yandex IAM token": "\\b(t1\\.[\\w-]+={0,2}\\.[\\w-]{86}(?:={0,2}|\\b))",
    "Yandex OAuth token": "\\b(y[0-3]_[\\w-]{55})\\b",
    "Zapier Webhook Url": "(?:https://)?(?:hooks\\.)?zapier\\.com/hooks/catch/(\\d{3,}/[0-9a-zA-Z,]{3,})",
    "Zuplo API key": "\\b(zpka_[a-f\\d]{32}_[a-f\\d]{8})\\b",


   // "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
   // "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
}

let generics = {
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
}

let aws = {
    "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
}

let denyList = ["AIDAAAAAAAAAAAAAAAAA"]

a = ""
b = ""




var checkData = function(data, src, regexes, fromEncoded=false, parentUrl=undefined, parentOrigin=undefined){
    var findings = [];
    for (let key in regexes){
        let re = new RegExp(regexes[key])
        let match = re.exec(data);
        if (Array.isArray(match)){match = match.toString()}
        if (denyList.includes(match)){
            continue;
        }
        if (match){
            let finding = {};
            finding = {src: src, match:match, key:key, encoded:fromEncoded, parentUrl:parentUrl};
            a = data;
            b = re;
            findings.push(finding);

        }
    }
    if (findings){
        chrome.storage.sync.get(["leakedKeys"], function(result) {
            if (Array.isArray(result.leakedKeys) || ! result.leakedKeys){
                var keys = {};
            }else{
                var keys = result.leakedKeys;
            };
            for (let finding of findings){
                if(Array.isArray(keys[parentOrigin])){
                    var newFinding = true;
                    for (key of keys[parentOrigin]){
                        if (key["src"] == finding["src"] && key["match"] == finding["match"] && key["key"] == finding["key"] && key["encoded"] == finding["encoded"] && key["parentUrl"] == finding["parentUrl"]){
                            newFinding = false;
                            break;
                        }
                    }
                    if(newFinding){
                        keys[parentOrigin].push(finding)
                        chrome.storage.sync.set({"leakedKeys": keys}, function(){
                            updateTabAndAlert(finding);
                        });
                    }
                }else{
                    keys[parentOrigin] = [finding];
                    chrome.storage.sync.set({"leakedKeys": keys}, function(){
                        updateTabAndAlert(finding);
                    })
                }
             }
        })
    }
    let decodedStrings = getDecodedb64(data);
    for (encoded of decodedStrings){
        checkData(encoded[1], src, regexes, encoded[0], parentUrl, parentOrigin);
    }
}
var updateTabAndAlert = function(finding){
    var key = finding["key"];
    var src = finding["src"];
    var match = finding["match"];
    var fromEncoded = finding["encoded"];
    chrome.storage.sync.get(["alerts"], function(result) {
        console.log(result.alerts)
        if (result.alerts == undefined || result.alerts){
            if (fromEncoded){
                alert(key + ": " + match + " found in " + src + " decoded from " + fromEncoded.substring(0,9) + "...");
            }else{
                alert(key + ": " + match + " found in " + src);
            }
        }
    })
    updateTab();
}

var updateTab = function(){
     chrome.tabs.getSelected(null, function(tab) {
        var tabId = tab.id;
        var tabUrl = tab.url;
        var origin = (new URL(tabUrl)).origin
        chrome.storage.sync.get(["leakedKeys"], function(result) {
            if (Array.isArray(result.leakedKeys[origin])){
                var originKeys = result.leakedKeys[origin].length.toString();
            }else{
                var originKeys = "";
            }
            chrome.browserAction.setBadgeText({text: originKeys});
            chrome.browserAction.setBadgeBackgroundColor({color: '#ff0000'});
        })
    });
}

chrome.tabs.onActivated.addListener(function(activeInfo) {
    updateTab();
});

var getStringsOfSet = function(word, char_set, threshold=20){
    let count = 0;
    let letters = "";
    let strings = [];
    if (! word){
        return []
    }
    for(let char of word){
        if (char_set.indexOf(char) > -1){
            letters += char;
            count += 1;
        } else{
            if ( count > threshold ){
                strings.push(letters);
            }
            letters = "";
            count = 0;
        }
    }
    if(count > threshold){
        strings.push(letters);
    }
    return strings
}

var getDecodedb64 = function(inputString){
    let b64CharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let encodeds = getStringsOfSet(inputString, b64CharSet);
    let decodeds = [];
    for (encoded of encodeds){
        try {
            let decoded = [encoded, atob(encoded)];
            decodeds.push(decoded);
        } catch(e) {
        }
    }
    return decodeds;
}

var checkIfOriginDenied = function(check_url, cb){
    let skip = false;
    chrome.storage.sync.get(["originDenyList"], function(result) {
        let originDenyList = result.originDenyList;
        for (origin of originDenyList){
            if(check_url.startsWith(origin)){
                skip = true;
            }
        }
        cb(skip);
    })
}
var checkForGitDir = function(data, url){
    if(data.startsWith("[core]")){
        alert(".git dir found in " + url + " feature to check this for secrets not supported");
    }

}
var js_url;
chrome.extension.onMessage.addListener(function(request, sender, sendResponse) {

    chrome.storage.sync.get(['generics'], function(useGenerics) {
        chrome.storage.sync.get(['specifics'], function(useSpecifics) {
            chrome.storage.sync.get(['aws'], function(useAws) {
                chrome.storage.sync.get(['checkEnv'], function(checkEnv) {
                    chrome.storage.sync.get(['checkGit'], function(checkGit) {
                        let regexes = {};
                        if(useGenerics["generics"] || useGenerics["generics"] == undefined){
                            regexes = {
                                ...regexes,
                                ...generics
                            }
                        }
                        if(useSpecifics["specifics"] || useSpecifics["specifics"] == undefined){
                            regexes = {
                                ...regexes,
                                ...specifics
                            }
                        }
                        if(useAws["aws"] || useAws["aws"] == undefined){
                            regexes = {
                                ...regexes,
                                ...aws
                            }
                        }
                        if (request.scriptUrl) {
                            let js_url = request.scriptUrl;
                            let parentUrl = request.parentUrl;
                            let parentOrigin = request.parentOrigin;
                            checkIfOriginDenied(js_url, function(skip){
                                if (!skip){
                                    fetch(js_url, {"credentials": 'include'})
                                        .then(response => response.text())
                                        .then(data => checkData(data, js_url, regexes, undefined, parentUrl, parentOrigin));
                                }

                            })

                        }else if(request.pageBody){
                            checkIfOriginDenied(request.origin, function(skip){
                                if (!skip){
                                    checkData(request.pageBody, request.origin, regexes, undefined, request.parentUrl, request.parentOrigin);
                                }
                            })
                        }else if(request.envFile){
                            if(checkEnv['checkEnv']){
                                fetch(request.envFile, {"credentials": 'include'})
                                    .then(response => response.text())
                                    .then(data => checkData(data, ".env file at " + request.envFile, regexes, undefined, request.parentUrl, request.parentOrigin));
                            }
                        }else if(request.openTabs){
                            for (tab of request.openTabs){
                                window.open(tab);
                                console.log(tab)
                            }
                        }else if(request.gitDir){
                            if(checkGit['checkGit']){
                            fetch(request.gitDir, {"credentials": 'include'})
                                    .then(response => response.text())
                                    .then(data => checkForGitDir(data, request.gitDir));
                            }

                        }
                    });
                });
            });

        });
    });



});

