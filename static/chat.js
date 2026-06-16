let messages = [];

function addMsg(text, type){
  let div = document.createElement("div");
  div.className = type;
  div.innerText = text;
  document.getElementById("messages").appendChild(div);
}

async function send(){
  let input = document.getElementById("msg");
  let text = input.value;
  input.value = "";

  addMsg(text, "user");

  let aiDiv = document.createElement("div");
  aiDiv.className = "ai";
  document.getElementById("messages").appendChild(aiDiv);

  const res = await fetch("/api/chat-stream", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({messages:[{content:text}]})
  });

  const reader = res.body.getReader();
  const decoder = new TextDecoder();

  while(true){
    const {value, done} = await reader.read();
    if(done) break;

    let chunk = decoder.decode(value);
    let lines = chunk.split("\n");

    for(let line of lines){
      if(line.includes("data:")){
        let data = line.replace("data: ","");
        if(data.includes("[DONE]")) return;

        let json = JSON.parse(data);
        aiDiv.innerText += json.token;
      }
    }
  }
}