document.getElementById("scanBtn").addEventListener("click", scan);

async function scan(){
    try {
        const [tab] = await chrome.tabs.query({active:true, currentWindow:true});
        const url = tab.url;

        const res = await fetch("http://127.0.0.1:5000/check", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify({url})
        });

        const data = await res.json();

        const result = document.getElementById("result");
        const body = document.getElementById("body");

        result.innerText = data.status + " (" + data.score + ")";

        // 🔥 COLOR CHANGE
        body.className = "";

        if(data.status === "Dangerous"){
            body.classList.add("danger");
            result.innerText += " 🚨 Avoid this site!";
        }
        else if(data.status === "Suspicious"){
            body.classList.add("sus");
        }
        else{
            body.classList.add("safe");
        }

    } catch(err){
        document.getElementById("result").innerText = "Error connecting to server";
        console.error(err);
    }
}