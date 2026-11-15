const LAB_DAY = "2026-11-15";
const scenarios = {
  ddos: {
    label:"DDoS", color:"#ae97ff",
    subtitle:"Edge trafiği, origin metrikleri ve rate-limit kayıtlarını ilişkilendir.",
    timeseries:[4400,4550,4800,5000,23100,49800,81000,41000,21900,10500,5700,5100]
  },
  sqli: {
    label:"SQL Injection", color:"#50d9de",
    subtitle:"WAF alarmını uygulama ve veritabanı kayıtlarıyla doğrula.",
    timeseries:[155,169,180,210,190,269,350,430,980,310,240,189]
  },
  xss: {
    label:"Cross-Site Scripting", color:"#ef86c3",
    subtitle:"Payload, response ve CSP kayıtlarıyla tarayıcıdaki etkiyi değerlendir.",
    timeseries:[130,120,165,180,220,340,185,195,320,710,460,225]
  }
};
const alerts = [
  {
    id:"SOC-106", type:"xss", time:"10:49:22", title:"Reflected XSS · Search", severity:"high", ip:"192.0.2.143", target:"shop.example.test", status:"new",
    description:"Arama parametresindeki HTML, uygulamanın döndürdüğü sayfada gözlendi. Etkinin kapsamını response ve tarayıcı loglarıyla değerlendir.",
    events:[
      ["10:49:22","WAF",{request_id:"req-x41",src_ip:"192.0.2.143",rule:"XSS_INPUT_MATCH",action:"log",path:"/search",query:{q:"<img src=x onerror=alert(1)>"}}],
      ["10:49:22","Application",{request_id:"req-x41",status:200,content_type:"text/html",response_excerpt:'<div>Results for <img src=x onerror=alert(1)></div>',output_encoding:"none"}],
      ["10:49:23","CSP Reporter",{request_id:"req-x41",effective_directive:"script-src-attr",blocked_uri:"inline",disposition:"enforce",policy:"script-src 'self'"}]
    ],
    prompts:["Payload hangi bağlamda response içinde yer alıyor?","CSP kaydı neyi doğruluyor? Yürütülmeye dair hangi kanıt eksik?","İlk containment adımın ve kalıcı düzeltmen ne olur?"],
    answer:"Reflected XSS açığı response ile doğrulanıyor. CSP, bu olayda inline event handler’ı engelliyor. Etkilenen parametreyi WAF ile sınırlandır, benzer endpoint’leri tara ve HTML bağlamına uygun çıktı kodlama uygula."
  },
  {
    id:"SOC-105", type:"xss", time:"10:45:09", title:"Stored XSS Şüphesi · Reviews", severity:"high", ip:"192.0.2.89", target:"reviews.example.test", status:"new",
    description:"Bir yorum isteği XSS kuralını tetikledi. Kaydedilen içeriğin başka kullanıcıya nasıl render edildiğini kontrol et.",
    events:[
      ["10:45:09","WAF",{request_id:"req-x27",src_ip:"192.0.2.89",rule:"XSS_INPUT_MATCH",action:"log",method:"POST",path:"/reviews",body:"<img src=x onerror=alert(1)>"}],
      ["10:45:09","Application",{request_id:"req-x27",status:201,review_id:"rv-21",stored_value:"<img src=x onerror=alert(1)>",reader_response:"<p>&lt;img src=x onerror=alert(1)&gt;</p>",renderer:"escaped_text"}],
      ["10:45:30","CSP Reporter",{review_id:"rv-21",observed_views:3,script_violations:0,policy:"script-src 'self'"}]
    ],
    prompts:["201 dönmesi hangi sonucu kanıtlar?","Okuyucuya gönderilen HTML saldırı etkisini destekliyor mu?","Aynı içeriğin göründüğü başka hangi yüzeyleri kontrol edersin?"],
    answer:"Payload saklandı ancak bu render yüzeyinde metne dönüştürülerek gösteriliyor. Yönetim paneli, e-posta ve diğer render yollarında bağlama uygun kodlamayı doğrula. CSP sinyali tek başına yeterli kanıt sağlamaz."
  },
  {
    id:"SOC-104", type:"sqli", time:"10:42:11", title:"SQLi · Olağandışı DB Okuması", severity:"critical", ip:"198.51.100.44", target:"catalog.example.test", status:"new",
    description:"WAF gözlem modunda bir SQLi kalıbı yakaladı. İsteğin sorgu davranışını ve veri erişimi üzerindeki etkisini araştır.",
    events:[
      ["10:42:11","WAF",{request_id:"req-s88",src_ip:"198.51.100.44",rule:"SQL_BOOLEAN_CONDITION",action:"log",path:"/api/products",query:{category:"' OR '1'='1' -- "}}],
      ["10:42:11","Application",{request_id:"req-s88",status:200,response_items:480,typical_response_items:12,db_session:"db-391"}],
      ["10:42:11","DB Audit",{session_id:"db-391",role:"catalog_reader",statement:"SELECT id,name FROM products WHERE category = '' OR '1'='1' -- '",rows_returned:480,executed:true}]
    ],
    prompts:["Üç veri kaynağını hangi alanlarla ilişkilendirirsin?","Sorgunun çalıştığını ve uygulama response kapsamını hangi alanlar gösteriyor?","Nasıl sınırlandırırsın ve erişilen veriyi nasıl belirlersin?"],
    answer:"request_id ile WAF ve uygulamayı, db_session üzerinden DB Audit kaydını eşleştir. SQLi sorgu mantığını değiştirmiş ve 480 ürün döndürmüş. Etkilenen endpoint’i sınırlandır, erişilen kayıtların sınıflandırmasını ve diğer istekleri incele, parametreli sorguya geç."
  },
  {
    id:"SOC-103", type:"sqli", time:"10:39:54", title:"SQLi Denemesi · Admin Login", severity:"medium", ip:"198.51.100.68", target:"admin.example.test", status:"review",
    description:"Admin girişine yönelik WAF alarmı oluştu. İsteğin origin’e ulaşıp ulaşmadığını ve alarmın kapsamını belirle.",
    events:[
      ["10:39:54","WAF",{request_id:"req-s77",src_ip:"198.51.100.68",path:"/admin/login",method:"POST",matched_value:"admin' -- ",action:"block",status:403,forwarded_to_origin:false}],
      ["10:39:54","Application",{lookup_request_id:"req-s77",matching_events:0,window_seconds:60}],
      ["10:40:54","DB Audit",{principal:"admin_app",window_start:"10:39:00",window_end:"10:40:54",abnormal_auth_queries:0}]
    ],
    prompts:["403 durum koduna ek olarak hangi alanı kontrol edersin?","Aynı kaynaktan başka başarılı istekleri nasıl ararsın?","Bu kanıta göre alarmı nasıl sınıflandırırsın?"],
    answer:"WAF isteği engellemiş ve origin’e iletmemiş. Uygulama ve DB aramalarında ilişkili etkinlik gözlenmiyor. Bu kaydı engellenen deneme olarak sınıflandırıp aynı kaynak veya kalıpla geçen diğer istekleri ara."
  },
  {
    id:"SOC-102", type:"ddos", time:"10:31:08", title:"HTTP Flood · Checkout", severity:"critical", ip:"203.0.113.84", target:"checkout.example.test", status:"new",
    description:"Checkout endpoint’inde çok sayıda kaynaktan istek artışıyla birlikte origin gecikmesi yükseldi. Trafik şeklini ve servis etkisini incele.",
    events:[
      ["10:30:00","Edge Gateway",{window_seconds:300,path:"/checkout",requests:81000,baseline_requests:5000,distinct_src_ips:1842,top_src_ip:"203.0.113.84",top_src_share_pct:2.7,cache_bypass_pct:96,method:"POST"}],
      ["10:31:08","Origin Monitor",{service:"checkout",p95_latency_ms:3800,baseline_p95_ms:220,http_5xx_pct:18,edge_ingress_mbps:94,edge_link_capacity_mbps:1000}],
      ["10:34:05","Rate Limiter",{scope:"/checkout",action:"challenge",suspicious_session_limit:"8 requests/10s",next_window_requests:41000,next_window_http_5xx_pct:6.2}]
    ],
    prompts:["L7 flood hipotezini destekleyen sinyaller neler?","Tek bir kaynak IP’yi engellemek trafik hacminin ne kadarını etkiler?","Mitigation sonrası servis sağlığını hangi metriklerle ölçersin?"],
    answer:"POST ve cache bypass ağırlıklı dağıtık istekler, doymamış bağlantı ve yükselen origin gecikmesi L7 flood hipotezini destekliyor. Endpoint ve oturum bazlı sınırlama uygula. 5xx, p95, meşru checkout başarı oranı ve origin’e ulaşan istekleri takip et."
  },
  {
    id:"SOC-101", type:"ddos", time:"10:20:13", title:"Trafik Anomalisi · Storefront", severity:"medium", ip:"203.0.113.12", target:"shop.example.test", status:"new",
    description:"Storefront, trafik eşiğini aştı. Promosyon etkisini saldırı belirtileriyle karşılaştır.",
    events:[
      ["10:20:00","Edge Gateway",{path:"/sale",window_seconds:300,requests:23100,baseline_requests:5000,cache_hit_pct:96,top_src_ip:"203.0.113.12",campaign_referral_share_pct:87}],
      ["10:20:10","Origin Monitor",{service:"storefront",p95_latency_ms:130,baseline_p95_ms:125,http_5xx_pct:0.15,baseline_http_5xx_pct:0.14}],
      ["10:20:13","Edge Gateway",{source:"simulated_campaign_calendar",campaign:"Sale announcement",starts_at:"10:20:00Z",expected_rise_in_get_requests:true}]
    ],
    prompts:["Bu yükselişi hangi iş sinyali açıklıyor?","Servis etkisi var mı?","Kapatma için hangi gözlemleri not edersin?"],
    answer:"Promosyon başlangıcı ve referral dağılımı trafik artışıyla örtüşüyor. Cache hit oranı yüksek ve origin metrikleri olağan. Bu alarmı meşru trafik artışı olarak belgeleyip izlemeye devam et."
  }
];
