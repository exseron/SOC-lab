const $ = (selector) => document.querySelector(selector);
const safe = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
})[char]);
const num = new Intl.NumberFormat("tr-TR");
const dateTime = new Intl.DateTimeFormat("tr-TR", {dateStyle:"medium", timeStyle:"short"});
const priorities = {critical:["Kritik","#ff8396"],high:["Yüksek","#ffb480"],medium:["Orta","#f6d27a"]};
const states = {new:["Yeni","#a88fff"],review:["İnceleniyor","#67c9f4"],closed:["Kapatıldı","#5be2aa"]};
const storageKey = "soc-lab-investigations-v1";
const defaultSubtitle = "Sentetik güvenlik alarmlarını incele, logları ilişkilendir ve kararını kaydet.";
let reviews = {};
try { reviews = JSON.parse(localStorage.getItem(storageKey)) || {}; } catch {}
let page = "all";
let queuePage = 0;
const pageSize = 10;
const abbreviations = {ddos:"DDoS",sqli:"SQLi",xss:"XSS"};
const icons = {ddos:"ϟ",sqli:"▤",xss:"‹›"};
let selected = null;
let opener = null;
const canvas = $("#chart");
const dialog = $("#case-dialog");

// Türkçe büyük/küçük harf ve noktalı İ farkını yok sayan arama metni.
const searchable = (value) => String(value).normalize("NFC").toLowerCase().replace(/[ıİ]/g,"i").replace(/̇/g,"");
// Her alarmın aranabilir metni bir kez hesaplanır; her tuş vuruşunda JSON üretilmez.
const haystacks = new Map(alerts.map((alarm) => [alarm.id, searchable(
  [alarm.id, alarm.title, alarm.ip, alarm.target, scenarios[alarm.type].label, JSON.stringify(alarm.events)].join(" ")
)]));

function persist() {
  try { localStorage.setItem(storageKey, JSON.stringify(reviews)); return true; } catch { return false; }
}

function statusOf(alarm) {
  return reviews[alarm.id]?.status || alarm.status;
}

function pill(level) {
  const [label, color] = priorities[level];
  return `<span class="pill" style="--accent:${color}"><i></i>${label}</span>`;
}

function pageAlerts() {
  return alerts.filter((alarm) => page === "all" || alarm.type === page);
}

function renderProgress() {
  const closed = alerts.filter((alarm) => statusOf(alarm) === "closed").length;
  const noted = alerts.filter((alarm) => reviews[alarm.id]?.notes?.trim()).length;
  const percent = alerts.length ? Math.round(closed / alerts.length * 100) : 0;
  $("#progress-label").textContent = `${closed} / ${alerts.length}`;
  $("#progress-fill").style.width = `${percent}%`;
  $("#progress-bar").setAttribute("aria-valuenow", String(percent));
  $("#progress-detail").textContent = `%${percent} kapatıldı · ${noted} alarmda not var`;
}

function renderSummary() {
  const list = pageAlerts();
  const active = list.filter((alarm) => statusOf(alarm) !== "closed").length;
  const critical = list.filter((alarm) => alarm.severity === "critical" && statusOf(alarm) !== "closed").length;
  const logs = list.reduce((total, alarm) => total + alarm.events.length, 0);
  const sourceCounts = new Map();
  for (const alarm of list) {
    for (const [, source] of alarm.events) {
      sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
    }
  }
  const sources = [...sourceCounts].sort((first, second) => second[1] - first[1] || first[0].localeCompare(second[0], "tr"));
  const cards = [
    ["Toplam Alarm",list.length,"Seçili çalışma alanı","▦","#ae97ff"],
    ["Kritik Alarm",critical,"Açık kritik alarmlar","!","#ff8396"],
    ["Açık Alarm",active,"Yeni veya inceleniyor","◷","#50d9de"],
    ["Kanıt Kaydı",logs,"İlişkili log örnekleri","▤","#71dcb2"]
  ];
  $("#stats").innerHTML = cards.map(([label, value, sub, icon, color]) => `<article class="stat">
    <div class="stat-head">${label}<span class="stat-icon" style="--accent:${color}" aria-hidden="true">${icon}</span></div>
    <strong>${num.format(value)}</strong><small>${sub}</small></article>`).join("");
  $("#sources").innerHTML = sources.map(([label, count]) => `<div class="source">
    <span class="panel-icon" aria-hidden="true">◫</span>
    <strong>${safe(label)}</strong><div class="source-count">${count}<small>kayıt</small></div></div>`).join("");
  renderProgress();
}

function matchesStatus(alarm, filter) {
  if (!filter) return true;
  const status = statusOf(alarm);
  return filter === "open" ? status !== "closed" : status === filter;
}

function renderRows() {
  const list = pageAlerts();
  const query = searchable($("#search").value.trim());
  const severity = $("#severity").value;
  const statusFilter = $("#status-filter").value;
  const matches = list.filter((alarm) =>
    (!severity || alarm.severity === severity) && matchesStatus(alarm, statusFilter) && haystacks.get(alarm.id).includes(query));
  const pageCount = Math.max(1, Math.ceil(matches.length / pageSize));
  queuePage = Math.max(0, Math.min(queuePage, pageCount - 1));
  const offset = queuePage * pageSize;
  $("#queue-count").textContent = matches.length;
  $("#queue-footer").textContent = matches.length
    ? `${list.length} alarm · ${offset+1}–${Math.min(offset+pageSize,matches.length)} / ${matches.length} eşleşme · UTC`
    : `${list.length} alarm · 0 eşleşme · UTC`;
  $("#paging").hidden = pageCount === 1;
  $("#previous-page").disabled = queuePage === 0;
  $("#next-page").disabled = queuePage >= pageCount - 1;
  $("#page-label").textContent = `${queuePage+1} / ${pageCount}`;
  $("#rows").innerHTML = matches.slice(offset, offset+pageSize).map((alarm) => {
    const [label, color] = states[statusOf(alarm)];
    const noted = reviews[alarm.id]?.notes?.trim() ? ' <span title="Analist notu var" aria-label="Not var">✎</span>' : "";
    return `<tr data-id="${safe(alarm.id)}"><td>${safe(alarm.time)}</td><td><button type="button" class="alarm-title">${safe(alarm.title)}${noted}<small>${safe(alarm.id)} · ${safe(scenarios[alarm.type].label)}</small></button></td>
      <td>${pill(alarm.severity)}</td><td>${safe(alarm.ip)}</td><td>${safe(alarm.target)}</td><td><span class="state" style="--accent:${color}"><i></i>${label}</span></td><td class="arrow" aria-hidden="true">›</td></tr>`;
  }).join("") || '<tr><td colspan="7">Filtrelere uyan alarm bulunamadı.</td></tr>';
}

// Eksen için "yuvarlak" bir üst sınır: 4 eşit aralığın her biri 1, 2, 2.5 veya 5 × 10^n.
function niceMax(peak) {
  const rawStep = Math.max(peak, 1) / 4;
  const magnitude = 10 ** Math.floor(Math.log10(rawStep));
  const step = [1, 2, 2.5, 5, 10].map((factor) => factor * magnitude).find((candidate) => candidate >= rawStep);
  return step * 4;
}

function drawChart() {
  const {width, height} = canvas.getBoundingClientRect();
  if (!width || !height) return;
  const scale = window.devicePixelRatio || 1;
  canvas.width = Math.round(width * scale);
  canvas.height = Math.round(height * scale);
  const ctx = canvas.getContext("2d");
  ctx.scale(scale, scale);
  const scenario = scenarios[page];
  const traffic = scenario?.timeseries;
  const values = traffic ? [...traffic] : Array(12).fill(0);
  if (!traffic) {
    for (const alarm of pageAlerts()) {
      for (const [time] of alarm.events) {
        values[Math.min(11, Math.floor(Number(time.slice(3,5))/5))]++;
      }
    }
  }
  const color = scenario?.color || "#ae97ff";
  // Trafik serilerinde ölçek veriden hesaplanır (önceden senaryo adına göre sabit kodluydu);
  // log sayıları tamsayı kalsın diye 4'ün katına yuvarlanır.
  const max = traffic ? niceMax(Math.max(...values)) : Math.max(4, Math.ceil(Math.max(...values)/4)*4);
  const pad = {left:43,right:14,top:15,bottom:24};
  const bottom = height-pad.bottom;
  const usable = width-pad.left-pad.right;
  const x = (index) => pad.left + usable * index/11;
  const y = (value) => bottom - (bottom-pad.top)*value/max;
  ctx.font = "10px Consolas, monospace";
  for (let i=0; i<=4; i++) {
    const value = max*i/4;
    ctx.beginPath();
    ctx.moveTo(pad.left, y(value));
    ctx.lineTo(width-pad.right, y(value));
    ctx.strokeStyle = "#292d3d";
    ctx.stroke();
    ctx.fillStyle = "#a2a9bd";
    ctx.textAlign = "right";
    const label = value >= 1000 ? `${value/1000}k` : value;
    ctx.fillText(label, pad.left-7, y(value)+3);
  }
  ctx.textAlign = "center";
  for (const index of [0,2,4,6,8,10]) ctx.fillText("10:" + String(index*5).padStart(2,"0"),x(index),height-7);
  function line() {
    ctx.moveTo(x(0), y(values[0]));
    values.slice(1).forEach((value, index) => ctx.lineTo(x(index+1), y(value)));
  }
  const gradient = ctx.createLinearGradient(0,pad.top,0,bottom);
  gradient.addColorStop(0,color+"3b");
  gradient.addColorStop(1,color+"00");
  ctx.beginPath();
  line();
  ctx.lineTo(x(11),bottom);
  ctx.lineTo(x(0),bottom);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();
  ctx.beginPath();
  line();
  ctx.strokeStyle = color;
  ctx.lineJoin = "round";
  ctx.lineWidth = 2;
  ctx.stroke();
  const peak = values.indexOf(Math.max(...values));
  ctx.beginPath();
  ctx.arc(x(peak),y(values[peak]),3.5,0,2*Math.PI);
  ctx.fillStyle = color;
  ctx.fill();
}

function setPage(next, {updateHash = true} = {}) {
  // hasOwn: "#constructor" gibi prototip anahtarları senaryo sayılmasın.
  page = Object.hasOwn(scenarios, next) ? next : "all";
  if (updateHash) {
    const hash = page === "all" ? "" : `#${page}`;
    if (location.hash !== hash) history.replaceState(null, "", hash || location.pathname);
  }
  const scenario = scenarios[page];
  const label = scenario?.label || "Genel Bakış";
  document.title = `${label} · SOC / LAB`;
  $("#title").textContent = label;
  $("#crumb").textContent = label;
  $("#subtitle").textContent = scenario?.subtitle || defaultSubtitle;
  for (const button of document.querySelectorAll(".nav-item")) {
    const active = button.dataset.page === page;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current","page");
    else button.removeAttribute("aria-current");
  }
  $("#search").value = "";
  $("#severity").value = "";
  $("#status-filter").value = "";
  queuePage = 0;
  const metric = scenario?.timeseries ? "HTTP istekleri" : "Kanıt kayıtları";
  $("#legend").innerHTML = `<span><i style="--accent:${scenario?.color || "#ae97ff"}"></i>${metric}</span>`;
  $("#chart-caption").textContent = "UTC · 5 dakikalık aralıklar";
  const peak = scenario?.timeseries ? Math.max(...scenario.timeseries) : null;
  canvas.setAttribute("aria-label", peak
    ? `${label}, en yüksek örnek istek hacmi ${num.format(peak)}`
    : `${label}, 5 dakikalık aralıklarla ilişkili log sayısı`);
  renderSummary();
  renderRows();
  drawChart();
}

function savedLabel(review) {
  return review?.updatedAt ? `Son kayıt: ${dateTime.format(new Date(review.updatedAt))}` : "Henüz kaydedilmedi";
}

function openCase(alarm, button) {
  selected = alarm;
  opener = button;
  $("#case-id").textContent = `${alarm.id} · ${scenarios[alarm.type].label}`;
  $("#case-title").textContent = alarm.title;
  $("#case-body").innerHTML = `${pill(alarm.severity)}
    <p class="case-description">${safe(alarm.description)}</p>
    <div class="case-meta"><span>${safe(alarm.ip)}</span><span>${safe(alarm.target)}</span><span>${safe(alarm.time)} UTC</span></div>
    <section class="case-section"><h3>İlişkili Loglar</h3>${alarm.events.map(([time, source, payload], index) =>
      `<details class="event" ${index === 0 ? "open" : ""}><summary><span>${safe(time)} UTC</span> ${safe(source)}</summary>
      <pre>${safe(JSON.stringify({timestamp:`${LAB_DAY}T${time}Z`,source,...payload},null,2))}</pre></details>`).join("")}</section>
    <section class="case-section"><h3>İnceleme Soruları</h3><ol>${alarm.prompts.map((prompt) => `<li>${safe(prompt)}</li>`).join("")}</ol>
      <label for="case-notes"><h3>Analist Notu</h3></label><textarea id="case-notes" placeholder="Kararın, kanıtın ve sonraki adımın... (Ctrl+Enter ile kaydet)"></textarea></section>
    <details class="answer"><summary>Örnek Analizi Göster</summary><p>${safe(alarm.answer)}</p></details>`;
  $("#case-status").value = statusOf(alarm);
  $("#case-notes").value = reviews[alarm.id]?.notes || "";
  $("#case-saved").textContent = savedLabel(reviews[alarm.id]);
  dialog.showModal();
  $("#case-body").scrollTop = 0;
}

// Açık vakada kaydedilmemiş değişiklik var mı?
function isDirty() {
  if (!selected || !dialog.open) return false;
  const saved = reviews[selected.id];
  return $("#case-status").value !== statusOf(selected) || $("#case-notes").value !== (saved?.notes || "");
}

function requestClose() {
  if (isDirty() && !confirm("Kaydedilmemiş değişiklikler var. Kaydetmeden kapatılsın mı?")) return;
  dialog.close();
}

function saveCase() {
  const id = selected.id;
  reviews[id] = {status:$("#case-status").value, notes:$("#case-notes").value, updatedAt:new Date().toISOString()};
  if (!persist()) alert("Tarayıcı depolaması kullanılamıyor; inceleme yalnızca bu oturumda tutulacak.");
  renderSummary();
  renderRows();
  opener = document.querySelector(`tr[data-id="${CSS.escape(id)}"] button`);
  dialog.close();
}

function buildReport() {
  const reviewed = alerts.filter((alarm) => reviews[alarm.id]);
  const closed = alerts.filter((alarm) => statusOf(alarm) === "closed").length;
  const lines = [
    "# SOC / LAB İnceleme Raporu",
    "",
    `- Oluşturulma: ${new Date().toISOString()}`,
    `- Laboratuvar günü: ${LAB_DAY} (10:00–11:00 UTC, sentetik veri)`,
    `- Kapatılan alarm: ${closed} / ${alerts.length}`,
    `- Kaydedilen inceleme: ${reviewed.length}`,
    ""
  ];
  for (const [key, scenario] of Object.entries(scenarios)) {
    const items = reviewed.filter((alarm) => alarm.type === key);
    if (!items.length) continue;
    lines.push(`## ${scenario.label}`, "");
    for (const alarm of items) {
      const review = reviews[alarm.id];
      lines.push(
        `### ${alarm.id} · ${alarm.title}`,
        "",
        `- Önem: ${priorities[alarm.severity][0]} · Durum: ${states[statusOf(alarm)][0]}`,
        `- Kaynak: ${alarm.ip} → ${alarm.target} · ${alarm.time} UTC`,
        review.updatedAt ? `- Son kayıt: ${review.updatedAt}` : "",
        "",
        review.notes?.trim() ? review.notes.trim().split("\n").map((row) => `> ${row}`).join("\n") : "> _Not yok._",
        ""
      );
    }
  }
  return lines.filter((row, index, all) => !(row === "" && all[index-1] === "")).join("\n");
}

function exportReport() {
  if (!Object.keys(reviews).length) {
    alert("Henüz kaydedilmiş inceleme yok. Bir alarm açıp \"İncelemeyi Kaydet\" ile başla.");
    return;
  }
  const blob = new Blob([buildReport()], {type:"text/markdown;charset=utf-8"});
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `soc-lab-rapor-${new Date().toISOString().slice(0,10)}.md`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function resetProgress() {
  if (!Object.keys(reviews).length) return;
  if (!confirm("Tüm alarm durumları ve analist notları silinecek. Emin misin?")) return;
  reviews = {};
  try { localStorage.removeItem(storageKey); } catch {}
  renderSummary();
  renderRows();
}

function tickClock() {
  $("#clock").textContent = `◷  ${new Date().toISOString().slice(11,19)} UTC`;
}

$("#scenario-nav").innerHTML = Object.entries(scenarios).map(([key, scenario]) => {
  const count = alerts.filter((alarm) => alarm.type === key).length;
  return `<button class="nav-item" type="button" data-page="${safe(key)}">
    <span aria-hidden="true">${scenario.icon || icons[key]}</span><span class="nav-label">${safe(abbreviations[key] || scenario.label)}</span><small>${count}</small>
  </button>`;
}).join("");

for (const button of document.querySelectorAll(".nav-item")) {
  button.addEventListener("click", () => setPage(button.dataset.page));
}
function restartQueue() {
  queuePage = 0;
  renderRows();
}
$("#search").addEventListener("input",restartQueue);
$("#severity").addEventListener("change",restartQueue);
$("#status-filter").addEventListener("change",restartQueue);
$("#previous-page").addEventListener("click",() => {
  queuePage--;
  renderRows();
});
$("#next-page").addEventListener("click",() => {
  queuePage++;
  renderRows();
});
$("#rows").addEventListener("click",(event) => {
  const row = event.target.closest("tr[data-id]");
  if (row) openCase(alerts.find((alarm) => alarm.id === row.dataset.id),row.querySelector("button"));
});
$("#close-case").addEventListener("click",requestClose);
// Esc tuşu: değişiklik varsa önce onay iste.
dialog.addEventListener("cancel",(event) => {
  if (isDirty()) {
    event.preventDefault();
    requestClose();
  }
});
// Arka plana (backdrop) tıklayınca kapat.
dialog.addEventListener("click",(event) => {
  if (event.target === dialog) requestClose();
});
dialog.addEventListener("close",() => opener?.focus());
$("#save-case").addEventListener("click",saveCase);
$("#export-report").addEventListener("click",exportReport);
$("#reset-progress").addEventListener("click",resetProgress);
document.addEventListener("keydown",(event) => {
  if (dialog.open && event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    saveCase();
  } else if (!dialog.open && event.key === "/" && !event.target.closest("input, textarea, select")) {
    event.preventDefault();
    $("#search").focus();
  }
});
window.addEventListener("hashchange",() => setPage(location.hash.slice(1), {updateHash:false}));
// Başka sekmede kaydedilen incelemeler bu sekmeye de yansısın.
window.addEventListener("storage",(event) => {
  if (event.key !== storageKey) return;
  try { reviews = JSON.parse(event.newValue) || {}; } catch { reviews = {}; }
  renderSummary();
  renderRows();
});
new ResizeObserver(drawChart).observe(canvas);
tickClock();
setInterval(tickClock, 1000);
setPage(location.hash.slice(1), {updateHash:false});
