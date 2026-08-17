/* ===== Password visibility toggle ===== */
function togglePw(){
  var el=document.getElementById('lgP');
  if(el){el.type=el.type==='password'?'text':'password'}
}

/* ===== Theme toggle ===== */
var thm=0;
function toggleTheme(){
  thm=(thm+1)%2;
  document.documentElement.setAttribute('data-theme',thm?'dark':'light');
  document.getElementById('thB').textContent=thm?'☀️':'🌙';
}
// Apply saved theme immediately on load (before boot)
(function(){try{var b=document.getElementById('thB');if(b)b.textContent=thm?'☀️':'🌙'}catch(e){}})();

/* ===== PDF/Excel libs load lazily on first use — saves ~1.5MB on initial page load ===== */
var _pdfLibsLoaded=false,_xlsxLoaded=false;
function _loadScript(src){
  return new Promise(function(resolve,reject){
    var s=document.createElement('script');s.src=src;
    s.onload=resolve;s.onerror=function(){reject(new Error('Failed: '+src))};
    document.head.appendChild(s);
  });
}
var _pdfLibsLoadingPromise=null;
function loadPdfLibs(){
  if(_pdfLibsLoaded)return Promise.resolve();
  if(_pdfLibsLoadingPromise)return _pdfLibsLoadingPromise; // already loading in background — reuse it, don't start a second download
  if(navigator.onLine===false){toast("No internet connection — internet is required to download the PDF (first time only)","err");return Promise.reject(new Error("offline"))}
  // Load html2canvas + jsPDF in parallel, then autotable (needs jsPDF first)
  _pdfLibsLoadingPromise=Promise.all([
    _loadScript('https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js'),
    _loadScript('https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js')
  ]).then(function(){
    return _loadScript('https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js');
  }).then(function(){_pdfLibsLoaded=true;_pdfLibsLoadingPromise=null})
    .catch(function(e){_pdfLibsLoadingPromise=null;toast('PDF library load failed: '+e.message,'err');throw e});
  return _pdfLibsLoadingPromise;
}
// Preload the PDF engine quietly in the background once the browser is idle,
// so by the time the user actually taps "Download PDF" the libraries are
// already sitting in memory — this removes the ~1.5MB download wait that was
// making the FIRST PDF of every session feel very slow.
(function(){
  var kick=function(){loadPdfLibs().catch(function(){})};
  if('requestIdleCallback' in window)requestIdleCallback(kick,{timeout:4000});
  else setTimeout(kick,2500);
})();
function loadXlsx(){
  return new Promise(function(resolve){
    if(_xlsxLoaded||window.XLSX){_xlsxLoaded=true;resolve();return}
    var s=document.createElement('script');s.src='https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js';
    s.onload=function(){_xlsxLoaded=true;resolve()};document.head.appendChild(s);
  });
}
