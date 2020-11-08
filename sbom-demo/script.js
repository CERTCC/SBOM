/* SBOM-Demo script.js version 4.2 ability to export CyconeDX as JSON and Graph as PNG  */
const _version = 4.9
/* Internal JSON representation */
var fjson
var swidHead = '<?xml version="1.0" ?>\n<SwidTags>'
var swidTail = '\n</SwidTags>'
var cyclonedxSerialNumber = "urn:uuid:"+generate_uuid()
var cyclonedxHead = '<?xml version="1.0"?>\n<bom '+
    'serialNumber="'+cyclonedxSerialNumber+'" \n'+
    'version = "1" '+
    'xmlns="http://cyclonedx.org/schema/bom/1.2">\n'
var cyclonedxTail = '\n</bom>\n'
var cyclonedxJson = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.2",
    "serialNumber": cyclonedxSerialNumber,
    "version": 1,
    "metadata": {},
    "components": [],
    "dependencies": []
}
var $metadata = {
    "timestamp": "$Created",
    "authors": [
	{"name": "$Creator"},
    ],
    "component": {
	"type": "device",
	"bom-ref": "$BomRef",
	"name": "$PackageName",
	"purl": "pkg:supplier/$UrlSupplierName/$UrlPackageName@$PackageVersion",
	"supplier": {
	    "name": "$SupplierName"
	},
	"version": "$PackageVersion"
    },
    "manufacture": {
	"name": "$SupplierName"
    }
}
var $component = {
    "type": "library",
    "bom-ref": "$BomRef",
    "name": "$PackageName",
    "purl": "pkg:supplier/$UrlSupplierName/$UrlPackageName@$PackageVersion",
    "publisher": "$SupplierName",
    "version": "$PackageVersion"
}
var $dependency = {
    "ref": "$MyBomRef",
    "dependsOn": [
	"$DependBomRef"
    ]
}
var cyclonedxdeps = ''

var diagonal,tree,svg,duration,root
var treeData = []
var vul_data = []
var cve_data = []
var alltreeData = []
/* Allow these to override URL and other validators */
var DefaultEmpty = {"NONE":true,"NOASSERTION":true}
/* jQuery document.ready equivalent or body onload*/
$(function () {
    $('[data-toggle="tooltip"]').tooltip()	
    if(self != self.parent) {
	$('th.parent-header').addClass('d-none')
	if(parent.window.document.body.classList.contains('blackbody'))
	    $('body').addClass('blackbody')
	else
	    $('body').removeClass('blackbody')	    
	/* No granchildren for now */
	$('.childbomframe').remove()
	if(typeof tempValue != "undefined") {
	    parse_spdx(tempValue,null,false,tempId)
	}
    }
})
function iframeautoheight(frameObj) {
    /* Not working right now */
    if(frameObj) {
	var nh = frameObj.contentWindow.$('.container').height() + 12
	frameObj.style.height = String(nh)+'px'
	return 1
    }
    return 0
}

document.onkeydown = function(evt) {
    evt = evt || window.event;
    if (evt.keyCode == 27) {
	$('.coverpage').hide()
    }
}
function vtoggle(w,fclass) {
    function replacer(match, p1) {
	var fh = {'x+':'-','x-':'+'}
	return fh['x'+match]
    }
    var wh = $(w).html().replace(/([\+\-])/,replacer)
    $(w).html(wh)
    $('.'+fclass).toggleClass('d-none')
}
function viewChild(w) {
    var cId = $(w).closest('table').attr('id')
    if(cId) {
	//iframeautoheight($('#c-'+cId).find('.iframeTemplate')[0])
	$('#c-'+cId).show()
    }
}
function setmvalue(w) {
    var aid = $(w).closest('table').attr("id")
    w.value = aid
}
function clearall() {
    swal({title: "Are you sure?",
	  text: "All Entries will be cleared!",
	  icon: "warning",
	  buttons: true,
	  dangerMode: true,
	 }).then((willDelete) => {
	     if (willDelete) 
		 location.reload()
	 })
}
function enablecbom(w){
    $(w).closest("table").find(".form-control").prop("disabled",w.checked)
    if(w.checked) 
	$(w).closest("table").find("tr.childbomtr").show()
    else
	$(w).closest("table").find("tr.childbomtr").hide()	
}
function add_sbom() {
    swal("Experimental!","Attaching an SBOM as a child SBOM is being tested","warning")
    return
}
function usage_privacy() {
    $('#info_privacy').modal()
}
function OBJtoXML(obj) {
    var xml = '';
    for (var prop in obj) {
	xml += obj[prop] instanceof Array ? '' : "<" + prop + ">";
	if (obj[prop] instanceof Array) {
	    for (var array in obj[prop]) {
		xml += "<" + prop + ">";
		xml += OBJtoXML(new Object(obj[prop][array]));
		xml += "</" + prop + ">\n";
	    }
	} else if (typeof obj[prop] == "object") {
	    xml += OBJtoXML(new Object(obj[prop]));
	} else {
	    xml += obj[prop];
	}
	xml += obj[prop] instanceof Array ? '' : "</" + prop + ">";
    }
    var xml = xml.replace(/<\/?[0-9]{1,}>/g, '');
    return xml
}


function readFile(input,mchild) {
    var file = input.files[0]
    if(!('name' in file)) {
	swal("Failed!","Failed to collect file name on upload!","error")
	return
    }
    if (file.name.toLowerCase().endsWith(".xlsx") ||
	file.name.toLowerCase().endsWith(".xls")) {
	console.log("Excel")
	var xl2json = new ExcelToJSON()
	xl2json.parseExcel(file)
	swal("Experimental!", "Excel file upload, Please update relationship"+
	     " before generating SBOM!",
	     "warning")
	return
    }
    var reader = new FileReader()
    reader.readAsText(file);
    reader.onload = function() {
	//console.log(reader.result);
	//sessionStorage.setItem("reader",reader.result)
	if(mchild == "childbom") {
	    //swal("Experimental!", "Child bom has been loaded!",
	    //"warning")
	    clear_vuls()
	    var qt = $(input).closest('table')
	    if($('.cbomfileExternal').is(':checked')) {
		var cfPid = qt.attr("id")
		var cframeId = "c-"+cfPid
		var cloneFrame = $('.cframeTemplate').clone()
		$('#'+cframeId).remove()
		var cframe = $('.cframeTemplate').attr("id",cframeId).
		    removeClass('cframeTemplate')
		/* save a cloned frame for next Embed event*/
		cframe.before(cloneFrame)
		var parentsTitle = $('#PrimaryComponent').find('[name="PackageName"]').val()
		cframe.find('.parentTitle').html(parentsTitle)
		var ciFrame = $('#'+cframeId).find(".iframeTemplate").attr("name",cframeId)
		var zIndexBase = parseInt($("#scontent").css("z-index"))
		cframe.css({'z-index': zIndexBase + $('.coverpage').length*10})
		var cWindow = ciFrame[0].contentWindow
		/* New method uses iframe postMessage*/
		cWindow.postMessage({childSPDX:reader.result,parentcId:cfPid})
		/* Legacy method for sending data to child frame 
		ciFrame.attr("onload",function() {
		    cWindow.tempValue = reader.result
		    cWindow.tempId = cfPid
		    //parse_spdx(reader.result,null,false,false)
		})
		*/
		//$('#'+cframeId).find(".iframeTemplate")[0].contentWindow
		
		/* 
		setTimeout(function() {
		    cWindow.parse_spdx(reader.result,null,false,false) }, 4000)
		*/
		return
	    }
	    if($(qt).find(".PackageName").val()  != "") {
		swal({
		    title: "Are you sure?",
		    text: "Adding a childbom as NOT External Reference will "+
			"replace the current component and all its child components "+
			" of this element!",
		icon: "warning",
		buttons: true,
		dangerMode: true,
	    }).then((willDelete) => {
		if (willDelete) {
		    var componentId = qt.attr("id")
		    recurse_remove(componentId)
		    parse_spdx(reader.result,mchild,input,false)
		} else {
		    swal("Your SBOM is left as is!");
		}
	    });
	    }	
	} else {
	    if (file.name.toLowerCase().endsWith(".xml")) {
		/* Assume Cyclone DX or SWID */
	    }
	    else if (file.name.toLowerCase().endsWith(".json")) {
		/* Assume Cyclone DX JSON */
	    }	    
	    else 
		parse_spdx(reader.result,mchild,input,false)
	}
	return
    }
    reader.onerror = function() {
	console.log(reader.error);
	swal("File Read Error","File reading as text failed","error")
    }
}
function msgReceiver(info) {
    if(!('data' in info)) {
	console.log("Error message data is missing")
	return
    }
    /* cWindow.postMessage({childSPDX:reader.result,parentcId:cfPid}) */
    if((info.source != info.target) && ('childSPDX' in info.data) && ('parentcId' in info.data))
	parse_spdx(info.data.childSPDX,null,false,info.data.parentcId)
}

if ( window.addEventListener ) {
    window.addEventListener('message', msgReceiver, false);
} else if ( window.attachEvent ) { 
    window.attachEvent('onmessage', msgReceiver);
}

function recurse_remove(componentId) {
    $("select.ParentComponent").each(function(i,s) {
	if($(s).val() == componentId) {
	    var ctable = $(s).closest('table')
	    var childcId = ctable.attr('id')
	    console.log("Removing this table "+childcId)
	    ctable.remove()
	    return recurse_remove(childcId)
	}
    })
}

function do_example() {
    $('#main_table .cmp_table').remove()
    $('#main_table .nmk').remove()
    add_cmp()
    var inputs = $('#main_table :input').not('select').not('.spdx-lite-field').not('.prefill')
    inputs.map(i => inputs[i].value = inputs[i].placeholder)
    var sample_array=[{PackageName:"Windows Embedded Standard 7 with SP1 patches",
		       PackageVersion:"3.0", SupplierName:"Microsoft"},
		      {PackageName:"SQL 2005 Express", PackageVersion:"9.00.5000.00,SP4",
		       SupplierName:"Microsoft"},
		      {ParentComponent:"Component1",PackageName:".Net Frame Work",
		       PackageVersion:"V2.1.21022.8,SP2",SupplierName:"Microsoft"},
		      {PackageName:"Java 8",PackageVersion:"v1.8",SupplierName:"Oracle"},
		      {ParentComponent:"Component5",PackageName:"Tomcat 9",
		       PackageVersion:"v9.037",SupplierName:"Apache Foundation"},
		      {ParentComponent:"Component5",PackageName:"Spring Framework",
		       PackageVersion:"v4.7",SupplierName:"Apache Foundation"}]		      
    for(var i=0; i<sample_array.length; i++) {
	add_cmp()
	var q = sample_array[i]
	var j = String(i+2)
	Object.keys(q).map(function(k,v) {
	    $('#Component'+j+' [name="'+k+'"]').val(q[k])
	})
    }
    var dcmps = $('#main_table [name="PackageName"]')
    for(var i=0; i<dcmps.length; i++) {
	update_cmp_names(dcmps[i])
    }
    /* Some unique field to update */
    $('input[type="datetime-local"]').val(new Date().toISOString().replace("Z",""))
    generate_spdx()
    setTimeout(function() {
	vul_data.push({vul_part:3,cve:'CVE-2019-2697',cvss_score:8.1})
	add_vul()
	load_vuls()
	simulate_vuls()
	add_heatmap(8.1)
    }, 1000)
    
}
var khash = {}
function parse_spdx(spdxin,mchild,input,fPid) {
    if(spdxin == "")
	spdxin = $('pre#pspdx').text()
    /* This is filled if there is a childbom being inserted  with class mclass*/
    var mcurrent_rowid = 0
    var mclass = ""
    if(mchild == "childbom") {
	console.log("Trying Child bom")
	mcurrent_rowid = parseInt($(input).closest('table').prop("id").replace("Component",""))
	console.log(mcurrent_rowid )
	mclass = "childbom"
    }
    spdxin = spdxin.replace(/\n\s+/g,'\n')
    khash = {}
    var lines = spdxin.split("\n")
    for (var i=0; i<lines.length; i++) {
	/* Bug Id: carraige returrn from Windows world can cause problems */
	lines[i] = lines[i].replace(/\r/g,'')
	/* Ignore Comments */
	if(lines[i][0] == '#') continue;
	var line = lines[i].split(':')
	var key = line.shift()
	var val =  line.join(":").replace(/^\s+/,'')
	if(key == "Relationship") {
	    /* Modify this key to capture "relationship" matchmaking problems*/
	    if(val.indexOf(" CONTAINS ") < -1) {
		key = "RelationshipUnsupported"
	    } else if (val.indexOf("CONTAINS NO") > -1) {
		key = "RelationshipNONE"
		if (val.indexOf("CONTAINS NOASSERTION") > -1)
		    key = "RelationshipNOASSERTION"
	    } else if (val.indexOf("CONTAINS Document") >-1) {
		key = "RelationshipExternal"
	    }
	}
	key in khash ? khash[key].push(val) : khash[key] = [val]
    }
    /* Some data clean up and ordering */
    if('SPDXID' in khash)     /* SPDXID is repeated collect components SPDXID*/
	khash["CSPDXID"] = khash["SPDXID"].splice(1)
    /* Remove <text> HTML stuff from Comment */
    if('CreatorComment' in khash)
	khash["CreatorComment"][0] = $('<div>').html(khash["CreatorComment"][0]).text()
    if('Creator' in khash) {
	var allcreators = khash['Creator'].splice(1)
	/* Mandatory but many values allowed  but not supported
	khash['Creator'][0] = khash['Creator'][0] +"\n"+allcreators.join("\n")
	*/
	/* For this demo only use simplify this ignore all others */
	var creatordata =  khash['Creator'][0].split(":")
	if(creatordata.length > 1) {
	    khash['CreatorType'] = [creatordata.shift()]
	    khash['Creator'][0] = creatordata.join(":")
	}else
	    khash['CreatorType'][0] = "Organization"
    }
    /* Check for child SBOM if not fill the top SBOM*/
    if(mcurrent_rowid == 0) {
	/* Process the head as normal */
	var headkeys = $('#main_table .thead :input').not("has-default")
	for(var i=0; i< headkeys.length; i++) {
	    var field = headkeys[i]
	    if(!(field.name in khash)) {
		swal("Data Error","Data does not contain required field "+field.name,"error")
		add_invalid_feedback(field,"No header data found for "+headkeys[i])
		return false
	    }
	    if(khash[field.name].length != 1) {
		swal("Data Error",
		     "Cardinality error for "+field.name+", only one value allowed found "+
		     khash[field.name].length+" values","error")
		return false
	    }
	    if(field.type == "datetime-local") {
		try {
		    field.value = new Date(khash[field.name][0]).toISOString().replace("Z","")
		} catch(err) {
		    console.log("Error when parsing date "+khash[field.name][0]+"XX")
		    field.value = new Date().toISOString().replace("Z","")
		    add_invalid_feedback(field,"Imported Date was incorrect! Replaced with current date")
		    console.log(err)
		}
	    }
	    else 
		field.value = khash[field.name][0] || ""
	}
    } 

    var plen = khash["PackageName"].length
    /* Create empty array for supplier name and supplier type comes from 
       PackageSupplier: $SupplierType: $SupplierName 
       variables */
    khash['SupplierType'] = Array(plen).fill("Organization")
    khash['SupplierName'] = Array(plen)
    khash["CRelationship"] = khash['Relationship']
    khash['Relationship'] = Array(plen).fill("Included")
    khash['ParentComponent'] = Array(plen).fill("PrimaryComponent")
    khash['Relationship'][0] = 'Primary'
    /* Default primary component index is 0, search for DESCRIBES  */
    var pIndex = 0
    /* Default components to fill starts with 0 unless a child bom is selected */
    
    for(var i=0; i< plen; i++) {
	if(khash["CRelationship"][i].indexOf(khash['SPDXID']+' DESCRIBES ') > -1) {
	    pIndex = i
	    /* Capture parent SPDXID */
	    //khash["PSPDXID"] = khash["CSPDXID"][i]
	}
	else
	    add_cmp(mclass)
    }	
    /* SPDXID */
    var cmps = $('#main_table .cmp_table')
    console.log(mcurrent_rowid)
    if(mcurrent_rowid > 0) {
	/* Child BOM is true , process this for current field */
	console.log(mcurrent_rowid,pIndex)
	$('#Component'+mcurrent_rowid).attr("data-spdxid",khash["CSPDXID"][pIndex])
	var bcmps = $('#Component'+mcurrent_rowid+' :input')
	cmps = $('#main_table .cmp_table.childbom')
	fill_component(bcmps,pIndex)
	/* Remove the parent SPDXID of this as the one for the full document */
	khash["PSPDXID"] = "DEFAULT"
    } else {
	/* No child bom involved, fill the primary component with pindex element */
	$('#main_table .pcmp_table').attr("data-spdxid",khash["CSPDXID"][pIndex])
	var pcmps = $('#main_table .pcmp_table :input')
	fill_component(pcmps,pIndex)
    }
    /* Remove the primary Index Element from CSPDXID References */
    var jkeys = Object.keys(khash)
    for(var j=0; j< jkeys.length; j++) {
	if(Array.isArray(khash[jkeys[j]]))
	   if(khash[jkeys[j]].length == plen)
	       khash[jkeys[j]].splice(pIndex,1)
    }

    //console.log(pIndex)
    for(var i=0; i<  khash["CSPDXID"].length; i++) {
	$(cmps[i]).attr("data-spdxid",khash["CSPDXID"][i])
	var scmps = $(cmps[i]).find(":input")
	if(scmps.length > 0) 
	    fill_component(scmps,i)
    }
    update_relationships_psuedo(cmps)
    if(fPid) {
	/* We have a parent iFrame update the table there with the primary component
	   data and show the button */
	self.parent.window.$('#'+fPid).find(".childbomButton").removeClass("d-none")
	$('#PrimaryComponent').find("input.form-control").each(function(i,v) {
	    self.parent.window.$('#'+fPid).find('[name="'+v.name+'"]').val(v.value)
	})
	self.parent.window.swal("Child SBOM is loaded as an External Reference!")
	/* Update hidden field in parent with External Reference information */
	/* ExternalDocumentRef: DocmentRef-$ExtDocumentName $ExtDocumentNamespace  $ExtOptionalSHA256Singature
	   Relationship: SPDXRef-$EscPackageName CONTAINS DocumentRef-$ExtDocumentName:SPDXRef-$EscPrimaryPackageName
	*/
	generate_spdx()
	if($('#dlspdx').data('sha256')) {
	    /* If sha256 signature exists use it*/
	    var fsha256 = $('#dlspdx').data('sha256')
	    $('#main_form').append($('<input>').attr('type','hidden').addClass('tempH').
				   attr('id','OptionalSHA256Signature').val('SHA256: '+fsha256))
	}
	if($('#PrimaryPackageName').val()) {
	    /* Escp primary packagename to be added as well*/
	    var escpkgname = $('#PrimaryPackageName').val().replace(/[^A-Z0-9\.\-]/gi,'-')
	    $('#main_form').append($('<input>').attr('type','hidden').addClass('tempH').
				   attr('id','EscPackageName').val(escpkgname))
	}
	var externalInfo = $('.externalreference').html().
	    replace(/\$([A-Za-z0-9]+)/gi, x => { var y = x.replace("$Ext","")
						 return $('#'+y).val() || ""
					       })
	console.log(externalInfo)
	self.parent.window.$('#'+fPid).find(".ExtReferencePayload").html(externalInfo)
    }
}
function update_relationships_psuedo(cmps) {
    if(cmps.length != khash["CRelationship"].length) {
	console.log("Relationship could not be updated")
	console.log(cmps)
	swal("Relationship mismatch","SPDX data on component relationships are not matching"+
	     ", may require a manual check","warning")
	return false
    }
    if("RelationshipExternal" in khash) {
	var external_count = khash["RelationshipExternal"].length
	for(var i=0; i<external_count; i++) {
	    var kExt = khash["RelationshipExternal"][i].replace(/^\s+/,'').split(/\s+/)
	    var tExt = $("table[data-spdxid='"+kExt[0]+"']")
	    if(tExt.length == 1) {
		tExt.find('.cbomenable').click()
		tExt.find('.cbomfileExternal').click()
	    }
	}
	swal("External Relationships detected!",
	     "SPDX data on component relationships that may require additional ["+
	     String(khash["RelationshipExternal"].length)+"] SPDX document(s). \nUse"+
	     " Child BOM feature to add external SPDX references. ",
	     "warning")
    }
    for(var i=0; i<cmps.length; i++) {
	var parts = khash["CRelationship"][i].split(/\s+/)
	var componentid = $("table[data-spdxid='"+parts[0]+"']").attr("id")
	console.log(componentid,parts[0])
	if (componentid)
	    $(cmps[i]).find(".ParentComponent").val(componentid)
    }
    $('[name="PackageName"]').trigger('change')
}

function fill_component(xcmps,xIndex) {
    for(var i=0; i< xcmps.length; i++) {
	var field = xcmps[i]
	/* PackageSupplier: $SupplierType: $SupplierName  */
	var supplierdata =  khash['PackageSupplier'][xIndex].split(":")
	if(supplierdata.length > 1) {
	    khash['SupplierType'][xIndex] = supplierdata.shift()
	    khash['SupplierName'][xIndex] = supplierdata.join(":")
	}else
	    khash['SupplierType'][xIndex] = "Organization"
	if(field.name in khash)
	    field.value = khash[field.name][xIndex] || ""
	else 
	    console.log("Skipping field "+field.name+", with value "+field.value)

    }
}
function update_cmp_names(w) {
    var mtable = $(w).closest('table')
    var nval = ' ('+$(w).val()+')'
    var tid = mtable.attr('id')
    mtable.find('.cmp_title').html(tid +nval)
    var otables = $('#main_table .cmp_table').not('#'+tid)
    var tselect = otables.find('.ParentComponent')
    for(var i=0; i< tselect.length; i++) {
	var cval = $(tselect[i]).find('option[value="'+tid+'"]').text()
	if(cval[cval.length-1] == ')')
	    $(tselect[i]).find('option[value="'+tid+'"]').text(cval.replace(/\(.*\)$/,nval))
	else
	    $(tselect[i]).find('option[value="'+tid+'"]').text(cval+nval)
    }
}

function add_cmp(mclass) {
    $('#main_table .cmp_table .btn-danger').remove()
    var clen = 0
    $('.cmp_table').each(function(i,c) {
	var xId = parseInt($(c).attr("id").replace("Component","")) + 1
	if(xId > clen) /* Find max */
	    clen = xId
    },0)
    if(clen < 1)
	clen = $('.cmp_table').length
    //console.log(clen)
    var dx = $('.cmp_template').html().replace(/d_count/g,clen)
    $('#main_table .tail').before('<tr class="nmk"><td colspan="2">'+dx+'</td></tr>')
    if(mclass) {
	$('#Component'+clen).addClass(mclass)
    }
    $('#Component'+clen).attr('data-bomref',generate_uuid())
    var pcs = $('#main_table .ParentComponent')
    for(var i=0; i<pcs.length; i++) {
	var id = $(pcs[i]).closest('table').attr('id')
	if(id != 'Component'+clen) {
	    $(pcs[i]).append(new Option('Component '+clen,'Component'+clen))
	}
    }
    for(var i=1; i<clen;i++) {
	var xname = $('#Component'+i).find('[name="PackageName"]').val() || ""
	//console.log(xname)
	if(xname != "") {
	    xname = " ("+xname+")"
	}
	var nopt = new Option('Component '+i+xname,'Component'+i)
	$('#Component'+clen+' .ParentComponent').append(nopt)
    }
    //console.log($('#Component'+clen).find(".cbomfileExternal").val('Component'+clen))
    
}
function rm_cmp(w) {
    $(w).closest('table').remove()
}
function add_invalid_feedback(xel,msg) {
    $('.invalid-feedback').remove()
    $('.valid-feedback').remove()    
    if(msg == "")
	msg = 'Please provide valid data for '+$(xel).attr('name')
    var err = $('<div>').html(msg)
    $(xel).after(err)
    $(err).addClass('invalid-feedback').show()
    $(xel).focus()
}
function add_valid_feedback(xel,msg) {
    $('.invalid-feedback').remove()
    $('.valid-feedback').remove()        
    if(msg == "")
	msg = 'Looks good'
    var gdg = $('<div>').html(msg)
    $(xel).after(gdg)
    $(gdg).addClass('valid-feedback').show()
}
function verify_inputs() {
    var inputs=$('#main_table :input').not('button')
    for (var i=0; i< inputs.length; i++) {
	if(!$(inputs[i]).val()) {
	    if(!$(inputs[i]).hasClass("not_required")) {
	       add_invalid_feedback(inputs[i],"")
		return false
	    }
	} else {
	    if($(inputs[i])[0].type == "datetime-local") {
		/* Not really necessary but we will do to be safe */
		if(isNaN(parseInt(new Date($(inputs[i])[0].value).getTime()))) {
		    add_invalid_feedback(inputs[i],"")
		    return false
		}
	    }
	    else if(!$(inputs[i])[0].checkValidity()) {
		if($(inputs[i])[0].value.toUpperCase() in DefaultEmpty)
		    return true
	       add_invalid_feedback(inputs[i],"")
		return false
	    }
	}
    }
    return true
}
function safeXML(inText) {
    return inText.replace(/[&<>"'`=]/g, function (s) {
	return "&#" + s.charCodeAt(0) + ";";
    })
}
function safeTXT(inText) {
    inText = inText.replace(/^\s+/,'').replace(/\s+$/,'')
    if(inText.toUpperCase() in DefaultEmpty) return inText.toUpperCase()
    return "<text>"+inText.replace(/[&<>"'`=\/]/g, function (s) {
	return "&#" + s.charCodeAt(0) + ";";
    })+"</text>"
}
function validateXML(inXML) {
    var p = new DOMParser();
    var o = p.parseFromString(inXML,"text/xml")
    var err  = o.getElementsByTagName("parsererror")
    if(err.length> 0) {
	swal("XML invalid!", "Sorry XML is not valid", "error");
    } else {
	swal("Good job!", "XML Validates right, you can use it", "success");
    }
}
function spdx_lite_content(el,hkey) {
    var spdx_lite_add = ""
    el.each(function() {
	if(this.name in hkey)
	    spdx_lite_add += this.name+": "+this.value+"\n"
    })
    return spdx_lite_add
}
function populate_dependencies(mybomref,componentId) {
    var xmlp = '<dependency ref="$MyBomRef">\n'.replace("$MyBomRef",mybomref)
    var xmlu = ''
    var index = cyclonedxJson['dependencies'].push({ref: mybomref, dependsOn: [] })
    index = index -1
    var t = $('#main_table .cmp_table .ParentComponent').filter(function() {
	if($(this).val() == componentId) {
	    var cBomRef = $(this).closest(".cmp_table").data("bomref")
	    if(cBomRef) {
		cyclonedxJson['dependencies'][index]['dependsOn'].push(cBomRef)
		xmlu = xmlu + '  <dependency ref="$DepBomRef"/>\n'.replace("$DepBomRef",cBomRef)
	    }
	}
	return false
    })
    if(cyclonedxJson['dependencies'][index]['dependsOn'].length < 1) 
	cyclonedxJson['dependencies'].pop()
    else
	cyclonedxdeps = cyclonedxdeps+xmlp+xmlu+"</dependency>\n"
}

function generate_spdx() {
    if(verify_inputs() == false)
	return
    /* Clear past vuls */
    if(window.safari)
	$('#dlsvg').hide()
    //$('.vul_template').not('.d-none').remove()
    $('.scontent').hide()
    var spdx = ""
    var swid = swidHead
    var cyclonedx = cyclonedxHead
    alltreeData = []
    $('#graph svg').remove()
    treeData = []
    fjson = {}
    fjson={"Header":{},"PrimaryComponent":{},"Packages":[]}
    var hinputs = $('#main_table > tbody > tr > td > :input')
    var hkey = {}
    hinputs.map(i => hkey[hinputs[i].name] = safeXML(hinputs[i].value))
    try {
	hkey['Created'] = new Date($('[name="Created"]').val())
	    .toISOString().replace(/\.\d{3}Z/,'Z')
    } catch(err) { /* Safari nonsense date parser */
	hkey['Created'] = new Date($('[name="Created"]').val().split(",")[0])
	    .toISOString().replace(/\.\d{3}Z/,'Z')
    }
    fjson.Header = hkey
    var thead = $('#spdx .head').html()
    spdx += thead.replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")])
    hinputs = $('.pcmp_table tr :input')
    var pc = {}
    hinputs.map(i => {
	if(!hinputs[i].value) return "dummy";
	if(hinputs[i].type.toLowerCase() == "textarea") {
	    hkey[hinputs[i].name] = safeTXT(hinputs[i].value)
	    pc[hinputs[i].name] = safeTXT(hinputs[i].value);
	} else {
	    hkey[hinputs[i].name] =  safeXML(hinputs[i].value);
	    pc[hinputs[i].name] = safeXML(hinputs[i].value);
	}
    })
    fjson.PrimaryComponent = pc
    var tpcmp = $('#spdx .pcomponent').html()

    hkey['EscPackageName'] = hkey['PackageName'].replace(/[^A-Z0-9\.\-]/gi,'-')
    hkey['UrlSupplierName'] = encodeURIComponent(hkey['SupplierName'])
    hkey['UrlPackageName'] = encodeURIComponent(hkey['PackageName'])
    /* Used in CycloneDX only */
    hkey['BomRef'] = generate_uuid()
    hkey['PrimaryBomRef'] = hkey['BomRef']
    $('.pcmp_table').attr('data-bomref', hkey['BomRef'])
    var PrimaryPackageName = hkey['PackageName']
    hkey['EscPrimaryPackageName'] = hkey['EscPackageName']    
    var swidcmp = $('#swid .cmp').val()
	.replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")])
    var cyclonedxcmp = $('#cyclonedx .cyclonedxpcmp').val()
	.replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")])
    cyclonedxJson['metadata'] = JSON.parse(JSON.stringify($metadata).replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")]))
    alltreeData.push({props:JSON.stringify(hkey),
		      name: hkey['PackageName'],
		      parent: null,
		      children:[]})
    swid += swidcmp
    cyclonedx += cyclonedxcmp 
    spdx += tpcmp.replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")])
    spdx += spdx_lite_content($('.pcmp_table .spdx-lite-field'),hkey)
    //console.log(spdx)
    /* Add option spdx_lite_fields */
    cyclonedxJson['components'] = []
    cyclonedxdeps = ''
    populate_dependencies(hkey['PrimaryBomRef'],"PrimaryComponent")

    var cmps = $('#main_table .cmp_table')
    var tpcmps = ""
    var swidpcmps = ""
    var cyclonedxpcmps = ""
    for(var i=0; i< cmps.length; i++) {
	hkey = {}
	hkey['PrimaryPackageName'] = PrimaryPackageName
	hkey['EscPrimaryPackageName'] = PrimaryPackageName.replace(/[^A-Z0-9\.\-]/gi,'-')
	var parent = PrimaryPackageName
	hkey['BomRef'] = $(cmps[i]).data('bomref') || generate_uuid()
	hkey['DependBomRef'] = hkey['PrimaryBomRef']
	hkey['MyBomRef'] = hkey['BomRef']
	hinputs = $(cmps[i]).find(':input').not('button')
	var xdepJ = []
	if($(cmps[i]).find(".ParentComponent").val() != "PrimaryComponent") {
	    /* This is a child relationship of level 2 or more */
	    var parentTable = $(cmps[i]).find(".ParentComponent").val()
	    var parentPackageName = $('#'+parentTable).find('input[name="PackageName"]').val()
	    parent = parentPackageName
	    hkey['EscPrimaryPackageName'] = parentPackageName.replace(/[^A-Z0-9\.\-]/gi,'-')
	} else {
	    var tid = $(cmps[i]).attr("id")
	    populate_dependencies(hkey['MyBomRef'],tid)
	}
	if(xdepJ.length > 0)
	    cyclonedxJson['dependencies'].push(xdepJ)
	hinputs.map( i => {
	    if(!hinputs[i].value) return "dummy";
	    if(hinputs[i].type.toLowerCase() == "textarea") {
		hkey[hinputs[i].name] = safeTXT(hinputs[i].value)
	    } else {
		hkey[hinputs[i].name] =  safeXML(hinputs[i].value);
	    }
	})
	alltreeData.push({props: JSON.stringify(hkey),name: hkey['PackageName'],parent: parent,
			  children:[]})	
	fjson.Packages.push(hkey)
	hkey['EscPackageName'] = hkey['PackageName'].replace(/[^A-Z0-9\.\-]/gi,'-')
	hkey['UrlPackageName'] = encodeURIComponent(hkey['PackageName'])
	hkey['UrlSupplierName'] = encodeURIComponent(hkey['SupplierName'])	
	tpcmp = $('#spdx .subcomponent').html()
	tpcmps += tpcmp.replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")])
	tpcmps += spdx_lite_content($(cmps[i]).find('.spdx-lite-field'),hkey)
	tpcmps += $(cmps[i]).find('.ExtReferencePayload').html()
	swidpcmps += $('#swid .cmp').val().
	    replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")])
	var xcmpsJ = JSON.parse(JSON.stringify($component).replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")]))
	cyclonedxJson['components'].push(xcmpsJ)
	cyclonedxpcmps += $('#cyclonedx .cyclonedxcmp').val().
	    replace(/\$([A-Za-z0-9]+)/gi, x => hkey[x.replace("$","")])	
    }
    spdx += tpcmps
    swid += swidpcmps+swidTail
    cyclonedx +=  '<components>\n' + cyclonedxpcmps + '</components>\n'+
	'<dependencies>\n'+ cyclonedxdeps + '</dependencies>\n'+
	cyclonedxTail
    //alert(spdx)
    $('#swidtext').val(swid)
    $('#cyclonedxXML').val(cyclonedx)
    $('#cyclonedxJSON').val(JSON.stringify(cyclonedxJson,null,2))    
    $('#spdxcontent').html('<pre id="pspdx">'+spdx+'</pre>').show()
    $('#scontent').show()
    var spdxdl = $('pre#pspdx').text().replace(/\n\s+/g,'\n')
    /* File Prefix */
    var fPfx = $('input[name="DocumentName"]').val().replace(/[^0-9A-Z]/gi,'-')+'-'
    $('#dlspdx').attr('download','SPDX-'+fPfx+timefile()+'.spdx')
    $('#dlspdx').attr('href','data:text/plain;charset=utf-8,' + encodeURIComponent(spdxdl))
    if(typeof sha256 == "function") 
	$('#dlspdx').data("sha256",sha256(spdxdl))
    $('#dlswid').attr('download','SWID-'+fPfx+timefile()+'.xml')
    $('#dlswid').attr('href','data:text/plain;charset=utf-8,' + encodeURIComponent(swid))
    $('#dlcyclonedx').attr('download','CycloneDX-'+fPfx+timefile()+'.xml')
    $('#dlcyclonedx').attr('href','data:text/plain;charset=utf-8,'
			   + encodeURIComponent(cyclonedx))
    /* Create png but don't download */
    treeData=grapharray(alltreeData)
    draw_graph()
    $('.cactive').removeClass('cactive')
    $('#scontent a:first-of-type').addClass('cactive')
}
function generate_uuid() {
    var uuid = Math.random().toString(16).substr(2,8)
    for (var i=0; i<3; i++)
	uuid += '-'+Math.random().toString(16).substr(2,4)
    return uuid+'-'+Math.random().toString(16).substr(2,12)
}


function draw_graph() {
    var margin = {top: 20, right: 120, bottom: 20, left: 120},
	width = 960 - margin.right - margin.left,
	height = 500 - margin.top - margin.bottom;

    duration = 750
    tree = d3.layout.tree()
	.size([height, width]);

    diagonal = d3.svg.diagonal()
	.projection(function(d) { return [d.y, d.x]; });

    svg = d3.select("#graph").append("svg")
	.attr("width", width + margin.right + margin.left)
	.attr("height", height + margin.top + margin.bottom)
	.append("g")
	.attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    var def = svg.append("defs").append("pattern")
	.attr({ id:"hash4_4", width:"8", height:"8", patternUnits:"userSpaceOnUse", 
		patternTransform:"rotate(90)"})
    def.append("circle").attr({r:10,fill:"white"})
    def.append("rect")
      .attr({ width:"4", height:"8", transform:"translate(0,0)", fill:"#88AAEE" })

    root = treeData[0];
    root.x0 = height / 2;
    root.y0 = 0;

    update(root)

    d3.select(self.frameElement).style("height", "500px");
    /* SVG download is unique 
    var svgx = $('svg')[0].outerHTML
    $('#dlsvg').attr('href','data:image/svg+xml;charset=utf-8,'+ encodeURIComponent(svgx))
    $('#dlsvg').attr('download','SVG-'+timefile()+'.svg')
    */
}
function update(source) {
    var i = 0
    // Compute the new tree layout.
    var nodes = tree.nodes(root).reverse(),
	links = tree.links(nodes);

    // Normalize for fixed-depth.
    nodes.forEach(function(d) { d.y = d.depth * 180;});

    // Update the nodes…
    var node = svg.selectAll("g.node")
	.data(nodes, function(d) { return d.id || (d.id = ++i); });

    // Enter any new nodes at the parent's previous position.
    var nodeEnter = node.enter().append("g")
	.attr("class", "node")
	.attr("transform", function(d) { return "translate(" + source.y0 + "," + source.x0 + ")"; })
	.on("click", doclick)
	.on("contextmenu",dorightclick)
	.on("mouseover",showdiv)
	.on("mouseout",hidediv)    

    nodeEnter.append("circle")
	.attr("r", 1e-6)
	.style("fill", function(d) {
	    /* This gets updated with the Update routine below */
	    return d._children ? "lightsteelblue" : "#fff";
	});
    nodeEnter.append("text")
	.attr("x", function(d) { return d.children || d._children ? -13 : 13; })
	.attr("dy", ".35em")
	.attr("text-anchor", function(d) { return d.children || d._children ? "end" : "start"; })
	.text(function(d) { return d.name; })
	.style("fill-opacity", 1e-6);

    // Transition nodes to their new position.
    var nodeUpdate = node.transition()
	.duration(duration)
	.attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; });

    nodeUpdate.select("circle")
	.attr("r", 10)
	.attr("sid",function(d) { return d.id;})
	.style("fill", function(d) {
	    try {
		x = JSON.parse(d.props)
		if("ExternalReference" in x) 
		    if($('#c-'+x.ExternalReference).length > 0)
			return "url(#hash4_4)"
	    } catch(err) {
		console.log("Error in parsing JSON "+err)
	    }	    
	    return d._children ? "lightsteelblue" : "#fff";
	});

    nodeUpdate.select("text")
	.style("fill-opacity", 1);

    // Transition exiting nodes to the parent's new position.
    var nodeExit = node.exit().transition()
	.duration(duration)
	.attr("transform", function(d) { return "translate(" + source.y + "," + source.x + ")"; })
	.remove();

    nodeExit.select("circle")
	.attr("r", 1e-6);

    nodeExit.select("text")
	.style("fill-opacity", 1e-6);

    // Update the links…
    var link = svg.selectAll("path.link")
	.data(links, function(d) { return d.target.id; });

    // Enter any new links at the parent's previous position.
    link.enter().insert("path", "g")
	.attr("class", "link")
	.attr("d", function(d) {
	    var o = {x: source.x0, y: source.y0};
	    return diagonal({source: o, target: o});
	});

    // Transition links to their new position.
    link.transition()
	.duration(duration)
	.attr("d", diagonal);

    // Transition exiting nodes to the parent's new position.
    link.exit().transition()
	.duration(duration)
	.attr("d", function(d) {
	    var o = {x: source.x, y: source.y};
	    return diagonal({source: o, target: o});
	})
	.remove();

    // Stash the old positions for transition.
    nodes.forEach(function(d) {
	d.x0 = d.x;
	d.y0 = d.y;
    });
    if(vul_data.length > 0) {
	$('circle').removeData()
	/* resort vul_data by cvss_Score */
	setTimeout(simulate_vuls,1000)
    }
}

function clear_vuls() {
    vul_data = []
    $('#heatmap').remove()
}

function showdiv(d) {
    var iconPos = this.getBoundingClientRect();
    //console.log(JSON.parse(d.props))
    var props = JSON.parse(d.props)
    //console.log(d)
    //console.log(this)
    var bgcolor = 'rgba(70, 130, 180, 0.4)'
    var vul_data = $(this).data()
    if($(this).is('g'))
	vul_data = $(this).find('circle').data()
    //console.log(vul_data)
    var addons = ''
    if('Created' in props)
	addons = '<br>Created on:'+props.Created
    if('Creator' in props)
	addons += '<br>Created by:'+props.Creator
    if('CreatorComment' in props)
	addons += '<br>Comments:'+props.CreatorComment
    if(('ExternalReference' in props) && ($('#c-'+props.ExternalReference).length > 0)) {
	var btitle = $('#'+props.ExternalReference).find('[name="PackageName"]').val()
	addons += '<br>External BOM: '+btitle+'<br><i>click to open child BOM</i>'
    }
    if('vul_part' in vul_data) {
	var vid = parseInt(vul_data.vul_part)
	if(d.id != vid) {
	    var findex = alltreeData.findIndex(x => x.id == vid)
	    if(findex > -1)
	    addons += '<br>Vul: <b><i>Inherited from '+alltreeData[findex]['name']+'</i></b>'
	} else {
	    addons += '<br> Vul: <b>'+vul_data.cve+' with CVSS score of '+
		vul_data.cvss_score+'</b>'
	}
	bgcolor = 'rgba('+cvss_tocolor(vul_data.cvss_score)+',0.6)'
    }
    $('#mpopup h5').html(props.PackageName)
    $('#mpopup p').html('Version: '+props.PackageVersion
			+'<br>Supplier:'+props.SupplierName+addons)
    $('#mpopup').css({left:(iconPos.right + 20) + "px",
		      top:(window.scrollY + iconPos.top - 60) + "px",
		      background: bgcolor,
		      display:"block"})
    
    //$(this).append("<div class='boom'>Hello</div>")
    //console.log(this)
    //console.log(d)
}
function hidediv(d) {
    $('#mpopup').hide()

    //$('.boom').hide()
    //$(this).append("<div class='boom'>Hello</div>")
    //console.log(this)
    //console.log(d)
}
function dorightclick(d) {
    return
    /*
    console.log(d)
    console.log($(d))
    console.log($(d).attr('parent'))    
    $(d).css({fill:'red'})
    */
}

function doclick(d) {
    /*
    if(($(this).is('g') && $(this).find('circle').hasClass('has_vul')) ||
       ($(this).hasClass('has_vul'))) {
	showdiv(d)
	return
    }
    */
    //console.log(d)
    try {
	var x = JSON.parse(d.props)
	if(('ExternalReference' in x) && ($('#c-'+x.ExternalReference).length > 0)) {
	    var iframeObj = $('#c-'+x.ExternalReference).find('.iframeTemplate')[0]
	    //iframeautoheight(iframeObj)
	    var cW = iframeObj.contentWindow
	    cW.generate_spdx()
	    cW.$('#graphshow').click()
	    $('#c-'+x.ExternalReference).show()
	    return
	}
    } catch(err) {
	console.log("Error in parsing JSON "+err)
    }
    if (d.children) {
	d._children = d.children;
	d.children = null;
    } else {
	d.children = d._children;
	d._children = null;
    }
    update(d);
}


function grapharray(array){
    var map = {};
    for(var i = 0; i < array.length; i++){
	var obj = array[i];
	obj.children= [];

	map[obj.name] = obj;

	var parent = obj.parent || '-';
	if(!map[parent]){
	    map[parent] = {
		children: []
	    };
	}
	map[parent].children.push(obj);
    }

    return map['-'].children;
}
function timefile() {
    var d = new Date();
    return d.getDate()  + "-" + (d.getMonth()+1) + "-" + d.getFullYear() + "-" +
	d.getHours() + "-" + d.getMinutes()
    
}
function showme(showdiv,vul_flag,hidediv,el) {
    $(hidediv).hide()
    $(showdiv).show()
    $('.cactive').removeClass('cactive')
    if($(el).hasClass('childtab')) {
	if($(el).data('phref')) {
	    /* Upodate PArent HREF properties if present */
	    var parenthref = $(el).data('phref')
	    var parentext = $(el).data('ptype')
	    console.log("Updating "+parenthref+":"+parentext)
	    var fname = $('#'+parenthref).attr('download')
	    fname = fname.replace(/\.[^\.]+$/,'.'+parentext)
	    $('#'+parenthref).attr('download',fname)
	    var ndata = $(showdiv).val()
	    $('#'+parenthref).attr('href','data:text/plain;charset=utf-8,'
				   + encodeURIComponent(ndata))
	}
    } else {	
	$(showdiv).find('textarea').hide()
	$(showdiv).find('textarea:first-of-type').show()
	$(showdiv).find('.childtab:first-of-type').addClass('cactive')
    }
    $(el).addClass('cactive')
    if(vul_flag)
	$('#vuls').removeClass('d-none')
    else
	$('#vuls').addClass('d-none')
}
function add_heatmap(cvss_score) {
    if($('#heatmap').data('cvss_score') &&
       $('#heatmap').data('cvss_score') > cvss_score) {
	console.log("Previous CVSS score is higher not creating a new map, "+cvss_score)
	return
    }
    $('#heatmap').remove()
    $('#graph').append('<table align="center" id="heatmap" style="font-size:14px">'+
		       '<thead><tr><th colspan="2" style="text-align:center">CVSS '+
		       'Color Map</th></tr><tbody><tr><td colspan="2" id="heatbar"></td></tr>'+
		       '<tr><td>0.1</td><td style="text-align: right;">10.0'+
		       '</td></tr></tbody></table>')
    for (var i=0; i<101; i++) {
	var cscore = (i*0.1).toFixed(2)
	var x=$('<div style="display:inline">&nbsp;</div>')
	    .css({width:'1px',height:'20px',background:'rgb(255,'+String(200-2*i)+',0)'})
	    .attr('title',cscore)
	if(cscore >= cvss_score) {
	    x.html('&wedge;').css({color:'white',background:'black'})
	    $('#heatmap').data({cvss_score:cvss_score})
	    /* After saving it , Empty it out */
	    cvss_score = 100
	}
	$('#heatbar').append(x)
    }
}
function simulate_vuls() {
    $('.invalid-feedback').remove()
    var pratio = parseFloat($('#pratio').val())
    var vul_rows = $('#vul_table .vul_template').not('.d-none')
    if(!vul_rows.length) {
	if(vul_data.length > 0) {
	    if(confirm("Clear all current simulated vulnerabilities?")) {
		vul_data=[]
		$('circle').removeData().css({fill: 'rgb(255,255,255)'}).removeClass('has_vul')
		$('#vul_table').modal('hide')
		$('#heatmap').remove()
		return
	    }
	}
	alert("Nothing to add")
	return
    }
    vul_data = []
    for(var j=0; j<vul_rows.length; j++) {
	var inputs = $(vul_rows[j]).find(":input").not("button")
	for (var i=0; i< inputs.length; i++) {
	    if(!$(inputs[i]).val()) {
		add_invalid_feedback(inputs[i],"")
		return false
	    }
	}
	var vid = parseInt($(vul_rows[j]).find(".vul_part").val())
	var cve = $(vul_rows[j]).find(".cve").val()
	var cvss_score = parseFloat($(vul_rows[j]).find(".cvss_score").val())
	if(isNaN(cvss_score) || (cvss_score <= 0) || (cvss_score > 10)) {
	    add_invalid_feedback($(vul_rows[j]).find(".cvss_score"),"CVSS Score should be between 0.1 and 10.0")
	    return false
	}
	$('#vul_table').modal('hide')
	var vul_d = {vul_part:vid,cvss_score:cvss_score,cve:cve} 
	vul_data.push(vul_d)
	/* find children relationships using ID property */
	//var vcid = vid
	//console.log(vid)
	//console.log(vcid)
	//populate_vuls(vul_d)
	$('circle[sid="'+vid+'"]').css({fill:'rgb('+cvss_tocolor(cvss_score)+')'})
	    .data(vul_d).addClass('has_vul')
	setTimeout(function() {
	    add_color_child(vid,cvss_score*pratio,vul_d)}, 400)
	setTimeout( function () {
	    add_color_parent(vid,cvss_score*pratio,vul_d)}, 500)	
    }
    add_heatmap(cvss_score)
}
function add_color_child(vid,cvss_score,vul_d) {
    var vcid = alltreeData.findIndex(x => x.id == vid)
    if(vcid < 0) {
	console.log("Some mismatch between vulnerability and latest data")
	return
    }
    if(!('children' in alltreeData[vcid]))
	return
    for(var i=0; i<alltreeData[vcid].children.length; i++) {
	var tvcid = alltreeData[vcid].children[i]['id']
	//console.log(tvcid)
	var cel = $('circle[sid='+tvcid+']')
	if((cel.data('cvss_score')) &&
	   (cel.data('cvss_score') > cvss_score)) {
	    console.log("Already have higher score in cvss Ignoring");
	    continue
	}
	cel.css({fill:'rgb('+cvss_tocolor(cvss_score)+')'})
	    .data(vul_d).addClass('has_vul')
	add_color_child(tvcid,cvss_score,vul_d)
    }
}
function add_color_parent(vid,cvss_score,vul_d) {
    var vcid = alltreeData.findIndex(x => x.id == vid) 
    if(vcid < 0) {
	console.log("Some mismatch between vulnerability and latest data")
	return
    }
    //console.log(vcid)
    if(!alltreeData[vcid]) return
    var tnode = alltreeData[vcid]
    if(!('parent' in tnode))
	return
    if(!tnode['parent'])
	return
    if(!('id' in tnode['parent']))
	return
    var pratio = parseFloat($('#pratio').val())    
    var tvcid = tnode['parent']['id']
    var pel = $('circle[sid='+tvcid+']')
    if((pel.data('cvss_score')) &&
	   (pel.data('cvss_score') > cvss_score)) {
	console.log("Parent already has higher score in cvss Ignoring "+cvss_score);
	return
    }    
    pel.css({fill:'rgb('+cvss_tocolor(cvss_score)+')'})
	.data(vul_d).addClass('has_vul')
    setTimeout( function () {
	add_color_parent(tvcid,cvss_score*pratio,vul_d)}, 400)
}
function vul_modal() {
    $('#vul_table').modal()
    /* Remove all pending add vul rows */
    $('.vul_template').not('.d-none').remove()
    /* Provide an empty form for new entry then load the current data */
    add_vul()
    load_vuls()    

}
function load_vuls() {
    for(var i=0; i<vul_data.length; i++) {
	var ovul = $('.vul_template.d-none').clone().removeClass('d-none')
	var fselect = ovul.find("select")
	/* Add everything that has a parent and a name, ignore the root */
	alltreeData.map(x => { if(x.name && x.parent) fselect.append(new Option(x.name,x.id))})
	for (k in vul_data[i])
	    ovul.find("."+k).val(vul_data[i][k])
	$('#vul_table .row').after(ovul)
    }
}
function remove_vul(w) {
    var rvul = $(w).parent()
    rvul.remove()
}
function add_vul() {
    //<p class="vul_template d-none">
    var nvul = $('.vul_template.d-none').clone().removeClass('d-none')
    var fselect = nvul.find("select")
    /* Add everything that has a parent and a name, ignore the root */
    alltreeData.map(x => { if(x.name && x.parent) fselect.append(new Option(x.name,x.id))})
    $('#vul_table .modal-body').append(nvul)

}
function cvss_tocolor(cvss) {
    var ncvs = parseFloat(cvss).toFixed(2)
    /* rgb match sent as a string of number r,g,b */
    return [255,200-(ncvs*20),0].join(",")
}
function cve_check(w) {
/* 
Provide CVE browsing capability.
https://cve.circl.lu/api/cve/CVE-2010-3333 
https://olbat.github.io/nvdcve/CVE-2017-1000369.json

*/
    var cve = w.value.toUpperCase()
    if(!cve.match(/^CVE\-\d{4}\-\d{4,}$/)) {
	add_invalid_feedback(w,"CVE score should be properly formatted")
	return
    }
    $.getJSON("https://olbat.github.io/nvdcve/"+cve+".json",function(data) {
	cve_data.push(data)
	if("impact" in data) {
	    if(("baseMetricV3" in data.impact) && ("cvssV3" in data.impact.baseMetricV3) &&
	       ("baseScore" in data.impact.baseMetricV3.cvssV3)) {
		console.log(data.impact.baseMetricV3.cvssV3.baseScore)
		add_valid_feedback($(w).closest('input'),"Mitre Score is "+data.impact.baseMetricV3.cvssV3.baseScore)
	    }
	}
    }).done(function() {
	console.log( "second success" );
    }).fail(function() {
	console.log( "error" );
	add_invalid_feedback(w,"Warning: CVE not found")
    }).always(function() {
	console.log( "complete" );
    });
}

var ExcelToJSON = function() {
    this.parseExcel = function(file) {
	var reader = new FileReader()
	var dexcel = {Document: false,Components:false}

	reader.onload = function(e) {
	    var data = e.target.result
	    var workbook = XLSX.read(data, {
		type: 'binary'
	    })
	    workbook.SheetNames.forEach(function(sheetName) {
		// Here is your object
		console.log(sheetName)
		var XL_row_object = XLSX.utils
		    .sheet_to_row_object_array(workbook.Sheets[sheetName])
		var json_object = JSON.stringify(XL_row_object)
		console.log(JSON.parse(json_object))
		dexcel[sheetName] = JSON.parse(json_object)
		//jQuery( '#xlx_json' ).val( json_object )
	    })
	    if((dexcel['Document'] === false) ||(dexcel['Components'] === false)) {
		swal("Sorry!","An Error ocurred while processing Excel file. Please use"+
		     " provided template and do not change sheet names to headers", "error")
		return
	    }
	    if('Instructions' in dexcel) /* Remote instructions reduce memory if we can */
		delete dexcel['Instructions']
	    FillFromExcel(dexcel)
	}

	reader.onerror = function(ex) {
	    swal("Sorry!","An Error ocurred while processing your file, check console","error")
	    console.log(ex)
	}

	reader.readAsBinaryString(file)
    }
}
function FillFromExcel(dexcel) {
    console.log(dexcel)
    for(var i=0; i< dexcel.Document.length; i++) {
	var td = dexcel.Document[i]
	var key = td["Field Name"]
	var val = td["Field Value"]
	key in khash ? khash[key].push(val) : khash[key] = [val]
    }
    khash['SPDXID'] = ["SPDXRef-DOCUMENT"]
    for(var i=0; i< dexcel.Components.length; i++) {
	var td = dexcel.Components[i]
	for (var [key, val] of Object.entries(td))
	    key in khash ? khash[key].push(val) : khash[key] = [val]
	khash['SPDXID'][i+1] = 'SPDXRef-'+khash['PackageName'][i].replace(/[^A-Z0-9\.\-]/gi,'-')
    }
    /* SPDXID is repeated collect components SPDXID*/
    khash["CSPDXID"] = khash["SPDXID"].splice(1)
    /* Remove <text> HTML stuff from Comment */
    if('CreatorComment' in khash)
	khash["CreatorComment"][0] = $('<div>').html(khash["CreatorComment"][0]).text()
    if("Created" in khash) {
	var d = new Date()
	if(isNaN(Date.parse(khash.Created))) {
	    console.log("Date provided is overriden due to compatibility")
	} else {
	    d = new Date(Date.parse(khash.Created))
	}
	$('[name="Created"]').val(d.toISOString().replace("Z",""))
    }
    var headkeys = $('#main_table .thead :input').not(".has-default")
    for(var i=0; i< headkeys.length; i++) {
        var field = headkeys[i]
	if(!(field.name in khash)) {
	    swal("Field Missing","Data does not contain required field "+field.name)
	    add_invalid_feedback(field,"No header data found for "+headkeys[i],"error")
	    return false
	}
	if(khash[field.name].length != 1) {
	    Swal("Cardinality error",
		 "Cardinality error for "+field.name+", only one value allowed found "+
		 khash[field.name].length+" values","error")
	    return false
	}
	if(field.type != "datetime-local") /* DAte is already filled up there */
	    field.value = khash[field.name][0] || ""
    }
    var plen = khash["PackageName"].length
    /* Create empty array for supplier name and supplier type comes from 
       PackageSupplier: $SupplierType: $SupplierName 
       variables */
    khash["CRelationship"] = khash['Relationship']
    khash['Relationship'] = Array(plen).fill("Included")
    khash['ParentComponent'] = Array(plen).fill("PrimaryComponent")
    khash['Relationship'][0] = 'Primary'
    khash['PackageSupplier'] = khash['SupplierType'].map((x,i) => x+':'+
					       khash['SupplierName'][i])

    /* Default primary component index is 0, search for DESCRIBES  */
    var pIndex = 0
    for(var i=0; i< plen; i++) {
	if(khash["Relationship"][i] == "Primary") {
	    pIndex = i
	    /* Capture parent SPDXID */
	    khash["PSPDXID"] = khash["CSPDXID"][i]
	}
	else
	    add_cmp()
    }	
    /* SPDXID */
    var pcmps = $('#main_table .pcmp_table :input')
    fill_component(pcmps,pIndex)
    $('#main_table .pcmp_table').attr("data-spdxid",khash["CSPDXID"][pIndex])    
    /* Remove the primary Index Element from CSPDXID References */
    var jkeys = Object.keys(khash)
    for(var j=0; j< jkeys.length; j++) {
	if(Array.isArray(khash[jkeys[j]]))
	   if(khash[jkeys[j]].length == plen)
	       khash[jkeys[j]].splice(pIndex,1)
    }
    var cmps = $('#main_table .cmp_table')    
    //console.log(pIndex)
    for(var i=0; i<  khash["CSPDXID"].length; i++) {
	$(cmps[i]).attr("data-spdxid",khash["CSPDXID"][i])
	var scmps = $(cmps[i]).find(":input")
	if(scmps.length > 0) 
	    fill_component(scmps,i)
    }
    update_relationships_psuedo(cmps)
}

function triggerDownload (dataURI,fname,el) {
    var evt = new MouseEvent('click', {
	view: window,
	bubbles: false,
	cancelable: true
    })
    var a = document.createElement('a');
    var dfname = $('#DocumentName').val().replace(/[^A-Z0-9\-]/gi,'_')
    a.setAttribute('download', fname)
    a.setAttribute('href', dataURI)
    a.setAttribute('target', '_blank')
    a.dispatchEvent(evt);
    $(el).attr('href',dataURI)
    $(el).attr('download',fname)
    $(el).attr('onclick',null)
}

function make_png(nodownload,nextfun) {
    var linecolor = 'white'
    var fillcolor = 'black'
    if($('body').hasClass('blackbody')) {
	linecolor = '#222'
	fillcolor = 'white'
	$('text').css({fill: '#ffffff'})
    } else {
	$('svg').css({background: '#f5f5f5'})
    }
    $('.link').css({'fill-opacity': 0.01,stroke: fillcolor,'stroke-width':'6px'})
    $('circle').css({fill: '#B0C4DE',stroke: fillcolor,'stroke-width':'6px'})
    $('circle.has_vul').css({fill:'red',stroke: fillcolor,'stroke-width':'6px'})
    var svg = document.querySelector('svg')
    var canvas = document.getElementById('canvas')
    var width = $('svg').width()*2
    var height = $('svg').height()*2
    canvas.width = width
    canvas.height = height
    var ctx = canvas.getContext('2d');
    var data = (new XMLSerializer()).serializeToString(svg);
    var DOMURL = window.URL || window.webkitURL || window;
    var img = new Image()
    var svgBlob = new Blob([data], {type: 'image/svg+xml;charset=utf-8'})
    var url = DOMURL.createObjectURL(svgBlob)
    var dfname = $('#DocumentName').val().replace(/[^A-Z0-9\-]/gi,'_')+'.png'
    img.onload = function () {
	ctx.clearRect ( 0, 0, width, height );
	ctx.drawImage(img, 0, 0,width,height);
	DOMURL.revokeObjectURL(url);
	var imgURI = canvas
	    .toDataURL('image/png')
	    .replace('image/png', 'image/octet-stream')
	if(nodownload)
	    $('#pngblob').val(imgURI.split(";")[1].replace("base64,",""))
	else
	    triggerDownload(imgURI,dfname,'#dlsvg')
	if(typeof(nextfun) == "function")
	    nextfun()
    }
  img.src = url
}
function download_zip() {
    /* Create PNG file but do not download */
    $('#dlzip').addClass('processing')
    make_png(true, do_download_zip)
}
function do_download_zip() {
    var zname = $('#DocumentName').val().replace(/[^A-Z0-9\-]/gi,'_')    
    var zip = new JSZip()
    var dfolder = zip.folder(zname)
    var ws = []
    /* Child windows */
    var cws = $('.childbomframe').not('.cframeTemplate').find("iframe")
    for(var i=0; i<cws.length; i++) {
	ws = ws.concat(cws[i].contentWindow)
	cws[i].contentWindow.make_png(true)
    }
    dfolder.file(zname+".spdx", $('pre#pspdx').text().replace(/\n\s+/g,'\n'))
    dfolder.file(zname+"-swid.xml", $('#swidtext').val())
    dfolder.file(zname+"-cyclonedx.xml", $('#cyclonedxXML').val())
    dfolder.file(zname+".png",$('#pngblob').val(), {base64: true})
    var timer = cws.length*800 
    setTimeout(function() {
	for (var i =0; i< ws.length; i++) {
	    var vw = ws[i]
	    var vzname = vw.$('#DocumentName').val().replace(/[^A-Z0-9\-]/gi,'_')
	    dfolder.file(vzname+".spdx", vw.$('pre#pspdx').text().replace(/\n\s+/g,'\n'))
	    dfolder.file(vzname+"-swid.xml", vw.$('#swidtext').val())
	    dfolder.file(vzname+"-cyclonedx.xml", vw.$('#cyclonedxXML').val())
	    dfolder.file(vzname+".png",vw.$('#pngblob').val(), {base64: true})
	}
	zip.generateAsync({type:"base64"})
	    .then(function(content) {
		// see FileSaver.js
		//saveAs(content, "example.zip");
		sessionStorage.setItem("zip",content)
		console.log("done")
		var zcontent = "data:application/octet-stream;base64,"+content
	    triggerDownload(zcontent,zname+".zip",'#dlzip')
		$('#dlzip').removeClass('processing')	    
	    });
    },timer)
}
