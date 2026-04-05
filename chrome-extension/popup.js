async function scan(){
    try {
        const [tab] = await chrome.tabs.query({active:true, currentWindow:true});
        const url = tab.url;

        const res = await fetch("http://127.0.0.1:5000/check", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify({url}),
            credentials: "include"
        });

        const data = await res.json();

        document.getElementById("result").innerText =
            data.status + " (" + data.score + ")";
    }
    catch(err){
        document.getElementById("result").innerText = "Error connecting";
        console.error(err);
    }
}

// 🔥 FIX
document.addEventListener("DOMContentLoaded", function(){
    document.getElementById("scanBtn").addEventListener("click", scan);
});