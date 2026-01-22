
(function(){
  function setupSignature(canvasId, hiddenId, clearBtnId){
    const canvas = document.getElementById(canvasId);
    const hidden = document.getElementById(hiddenId);
    if(!canvas || !hidden) return;

    const ctx = canvas.getContext("2d");
    let drawing = false;

    function resizeForHiDPI(){
      const rect = canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.round(rect.width * dpr);
      canvas.height = Math.round(rect.height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); // map logical px to CSS px
      ctx.lineWidth = 2;
      ctx.lineCap = "round";
      ctx.strokeStyle = "#111";
      // clear
      ctx.clearRect(0,0,rect.width,rect.height);
    }

    function getPos(evt){
      const rect = canvas.getBoundingClientRect();
      const clientX = evt.touches ? evt.touches[0].clientX : evt.clientX;
      const clientY = evt.touches ? evt.touches[0].clientY : evt.clientY;
      return { x: clientX - rect.left, y: clientY - rect.top };
    }

    function start(evt){
      evt.preventDefault();
      drawing = true;
      const pos = getPos(evt);
      ctx.beginPath();
      ctx.moveTo(pos.x, pos.y);
    }

    function move(evt){
      if(!drawing) return;
      evt.preventDefault();
      const pos = getPos(evt);
      ctx.lineTo(pos.x, pos.y);
      ctx.stroke();
    }

    function end(evt){
      if(!drawing) return;
      evt.preventDefault();
      drawing = false;
    }

    function updateHidden(){
      // Export in standard size; use canvas bitmap as-is
      hidden.value = canvas.toDataURL("image/png");
    }

    window.addEventListener("resize", resizeForHiDPI);
    resizeForHiDPI();

    canvas.addEventListener("mousedown", start);
    canvas.addEventListener("mousemove", move);
    window.addEventListener("mouseup", end);

    canvas.addEventListener("touchstart", start, {passive:false});
    canvas.addEventListener("touchmove", move, {passive:false});
    canvas.addEventListener("touchend", end, {passive:false});

    // clear button
    const clearBtn = clearBtnId ? document.getElementById(clearBtnId) : null;
    if(clearBtn){
      clearBtn.addEventListener("click", function(e){
        e.preventDefault();
        const rect = canvas.getBoundingClientRect();
        ctx.clearRect(0,0,rect.width,rect.height);
        hidden.value = "";
      });
    }

    // update on submit
    const form = canvas.closest("form");
    if(form){
      form.addEventListener("submit", function(){
        updateHidden();
      });
    }
  }

  document.addEventListener("DOMContentLoaded", function(){
    setupSignature("sigFormeCanvas", "signature_forme", "clearSigForme");
const fileInput = document.getElementById("sigFormeFile");
const canvas = document.getElementById("sigFormeCanvas");
const hidden = document.getElementById("signature_forme");
if(fileInput && canvas && hidden){
  fileInput.addEventListener("change", function(){
    const f = fileInput.files && fileInput.files[0];
    if(!f) return;
    const reader = new FileReader();
    reader.onload = function(e){
      const img = new Image();
      img.onload = function(){
        const ctx = canvas.getContext("2d");
        const rect = canvas.getBoundingClientRect();
        // Clear + draw centered, preserving aspect ratio
        ctx.clearRect(0,0,rect.width,rect.height);
        const scale = Math.min(rect.width / img.width, rect.height / img.height);
        const w = img.width * scale;
        const h = img.height * scale;
        const x = (rect.width - w) / 2;
        const y = (rect.height - h) / 2;
        ctx.drawImage(img, x, y, w, h);
        hidden.value = canvas.toDataURL("image/png");
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(f);
  });
}

  });
})();
