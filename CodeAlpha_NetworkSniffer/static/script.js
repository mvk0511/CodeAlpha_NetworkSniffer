function startCapture() {

fetch("/start")
.then(res => res.json())
.then(data => {

alert("Capture Started");

});

}

setInterval(loadPackets,2000);

function loadPackets(){

fetch("/packets")
.then(res => res.json())
.then(data => {

let search =
document
.getElementById("search")
.value
.toLowerCase();

let table =
document
.getElementById("packetTable");

table.innerHTML="";

data.forEach(packet=>{

let rowData =
JSON.stringify(packet)
.toLowerCase();

if(
search &&
!rowData.includes(search)
){
return;
}

table.innerHTML += `

<tr>

<td>${packet.timestamp}</td>
<td>${packet.src}</td>
<td>${packet.dst}</td>
<td>${packet.protocol}</td>
<td>${packet.sport}</td>
<td>${packet.dport}</td>
<td>${packet.length}</td>

</tr>

`;

});

});

}