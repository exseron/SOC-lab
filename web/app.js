const $ = (selector) => document.querySelector(selector);
const safe = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
})[char]);
const num = new Intl.NumberFormat("tr-TR");
const priorities = {critical:["Kritik","#ff8396"],high:["Yüksek","#ffb480"],medium:["Orta","#f6d27a"]};
const states = {new:["Yeni","#a88fff"],review:["İnceleniyor","#67c9f4"],closed:["Kapatıldı","#5be2aa"]};
const storageKey = "soc-lab-investigations-v1";
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
  const sources = [...sourceCounts].sort((first, second) => second[1] - first[1] || first[0].localeCompare(second[0]));
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
}

function renderRows() {
  const list = pageAlerts();
  const query = $("#search").value.trim().normalize("NFC").toLowerCase().replace(/[ıİ]/g,"i").replace(/\u0307/g,"");
  const severity = $("#severity").value;
  const matches = list.filter((alarm) => {
    const haystack = [alarm.id, alarm.title, alarm.ip, alarm.target, scenarios[alarm.type].label, JSON.stringify(alarm.events)]
      .join(" ").normalize("NFC").toLowerCase().replace(/[ıİ]/g,"i").replace(/\u0307/g,"");
    return (!severity || alarm.severity === severity) && haystack.includes(query);
  });
  const pageCount = Math.max(1, Math.ceil(matches.length / pageSize));
  queuePage = Math.min(queuePage, pageCount - 1);
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
    return `<tr data-id="${alarm.id}"><td>${alarm.time}</td><td><button type="button" class="alarm-title">${safe(alarm.title)}<small>${alarm.id} · ${scenarios[alarm.type].label}</small></button></td>
      <td>${pill(alarm.severity)}</td><td>${alarm.ip}</td><td>${alarm.target}</td><td><span class="state" style="--accent:${color}"><i></i>${label}</span></td><td class="arrow" aria-hidden="true">›</td></tr>`;
  }).join("") || '<tr><td colspan="7">Filtrelere uyan alarm bulunamadı.</td></tr>';
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
  const values = traffic || Array(12).fill(0);
  if (!traffic) {
    for (const alarm of pageAlerts()) {
      for (const [time] of alarm.events) {
        values[Math.floor(Number(time.slice(3,5))/5)]++;
      }
    }
  }
  const color = scenario?.color || "#ae97ff";
  const max = traffic ? (page === "ddos" ? 100000 : page === "sqli" ? 1000 : 800)
    : Math.max(4, Math.ceil(Math.max(...values)/4)*4);
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

function setPage(next) {
  page = next;
  const scenario = scenarios[page];
  const label = scenario?.label || "Genel Bakış";
  $("#title").textContent = label;
  $("#crumb").textContent = label;
  $("#subtitle").textContent = scenario?.subtitle || "Sentetik güvenlik alarmlarını incele, logları ilişkilendir ve kararını kaydet.";
  for (const button of document.querySelectorAll(".nav-item")) {
    const active = button.dataset.page === page;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current","page");
    else button.removeAttribute("aria-current");
  }
  $("#search").value = "";
  $("#severity").value = "";
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

function openCase(alarm, button) {
  selected = alarm;
  opener = button;
  $("#case-id").textContent = `${alarm.id} · ${scenarios[alarm.type].label}`;
  $("#case-title").textContent = alarm.title;
  $("#case-body").innerHTML = `${pill(alarm.severity)}
    <p class="case-description">${safe(alarm.description)}</p>
    <div class="case-meta"><span>${safe(alarm.ip)}</span><span>${safe(alarm.target)}</span><span>${alarm.time} UTC</span></div>
    <section class="case-section"><h3>İlişkili Loglar</h3>${alarm.events.map(([time, source, payload], index) =>
      `<details class="event" ${index === 0 ? "open" : ""}><summary><span>${time} UTC</span> ${source}</summary>
      <pre>${safe(JSON.stringify({timestamp:`${LAB_DAY}T${time}Z`,source,...payload},null,2))}</pre></details>`).join("")}</section>
    <section class="case-section"><h3>İnceleme Soruları</h3><ol>${alarm.prompts.map((prompt) => `<li>${safe(prompt)}</li>`).join("")}</ol>
      <label for="case-notes"><h3>Analist Notu</h3></label><textarea id="case-notes" placeholder="Kararın, kanıtın ve sonraki adımın..."></textarea></section>
    <details class="answer"><summary>Örnek Analizi Göster</summary><p>${safe(alarm.answer)}</p></details>`;
  $("#case-status").value = statusOf(alarm);
  $("#case-notes").value = reviews[alarm.id]?.notes || "";
  dialog.showModal();
  $("#case-body").scrollTop = 0;
}

$("#scenario-nav").innerHTML = Object.entries(scenarios).map(([key, scenario]) => {
  const count = alerts.filter((alarm) => alarm.type === key).length;
  return `<button class="nav-item" type="button" data-page="${key}">
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
$("#close-case").addEventListener("click",() => dialog.close());
dialog.addEventListener("close",() => opener?.focus());
$("#save-case").addEventListener("click",() => {
  const id = selected.id;
  reviews[id] = {status:$("#case-status").value,notes:$("#case-notes").value};
  try { localStorage.setItem(storageKey,JSON.stringify(reviews)); } catch {}
  renderSummary();
  renderRows();
  opener = document.querySelector(`tr[data-id="${id}"] button`);
  dialog.close();
});
new ResizeObserver(drawChart).observe(canvas);
setPage("all");
