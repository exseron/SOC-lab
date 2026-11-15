// Sentetik alarm verisinin bütünlüğünü doğrular: node tests/validate_data.mjs
// tests/test_lab.py tarafından da (Node kuruluysa) çalıştırılır.
import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";
import vm from "node:vm";

const web = (name) => readFileSync(fileURLToPath(new URL(`../web/${name}`, import.meta.url)), "utf8");
const context = vm.createContext({});
// const/let bildirimleri bağlam nesnesine düşmediği için sonda dışa aktarıyoruz.
vm.runInContext(`${web("data.js")}\n${web("exercises.js")}\nglobalThis.__out = {LAB_DAY, scenarios, alerts};`, context);
const {LAB_DAY, scenarios, alerts} = context.__out;

const errors = [];
const fail = (id, message) => errors.push(`${id}: ${message}`);
const SEVERITIES = new Set(["critical", "high", "medium"]);
const STATUSES = new Set(["new", "review", "closed"]);
const TIME = /^10:[0-5]\d:[0-5]\d$/;
const seen = new Set();

if (!/^\d{4}-\d{2}-\d{2}$/.test(LAB_DAY)) fail("LAB_DAY", `geçersiz tarih: ${LAB_DAY}`);
for (const [key, scenario] of Object.entries(scenarios)) {
  if (!scenario.label || !scenario.subtitle) fail(key, "senaryoda label/subtitle eksik");
  if (!/^#[0-9a-f]{6}$/i.test(scenario.color)) fail(key, `renk 6 haneli hex olmalı: ${scenario.color}`);
  if (scenario.timeseries && scenario.timeseries.length !== 12) fail(key, "timeseries 12 adet 5 dakikalık değer içermeli");
}

for (const alarm of alerts) {
  const id = alarm.id || "(id yok)";
  if (!/^SOC-\d{3}$/.test(id)) fail(id, "id SOC-123 biçiminde olmalı");
  if (seen.has(id)) fail(id, "tekrarlanan id");
  seen.add(id);
  if (!Object.hasOwn(scenarios, alarm.type)) fail(id, `bilinmeyen senaryo: ${alarm.type}`);
  if (!SEVERITIES.has(alarm.severity)) fail(id, `bilinmeyen önem: ${alarm.severity}`);
  if (!STATUSES.has(alarm.status)) fail(id, `bilinmeyen durum: ${alarm.status}`);
  if (!TIME.test(alarm.time)) fail(id, `saat 10:00–10:59 aralığında olmalı: ${alarm.time}`);
  for (const field of ["title", "ip", "target", "description", "answer"]) {
    if (typeof alarm[field] !== "string" || !alarm[field].trim()) fail(id, `${field} boş`);
  }
  if (!Array.isArray(alarm.prompts) || alarm.prompts.length < 2) fail(id, "en az 2 inceleme sorusu olmalı");
  if (!Array.isArray(alarm.events) || alarm.events.length < 1) fail(id, "en az 1 log kaydı olmalı");
  for (const [time, source, payload] of alarm.events || []) {
    if (!TIME.test(time)) fail(id, `log saati geçersiz: ${time}`);
    if (typeof source !== "string" || !source) fail(id, "log kaynağı boş");
    if (!payload || typeof payload !== "object") fail(id, "log içeriği nesne olmalı");
  }
}

for (let i = 1; i < alerts.length; i++) {
  if (alerts[i - 1].time < alerts[i].time) fail(alerts[i].id, "alarmlar saate göre azalan sırada olmalı");
}

if (errors.length) {
  console.error(`${errors.length} veri hatası:\n- ${errors.join("\n- ")}`);
  process.exit(1);
}
console.log(`Veri doğrulandı: ${alerts.length} alarm, ${Object.keys(scenarios).length} senaryo.`);
