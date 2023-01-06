var data = [

//CME
{"title":"cme","Link: ./cheats/Active_directory/cme.md"},

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
