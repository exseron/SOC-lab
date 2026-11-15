Object.assign(scenarios, {
  web: {label:"Web ve API", color:"#f0aa76", icon:"◇", subtitle:"HTTP, WAF ve uygulama kayıtlarından giriş noktasını ve etkiyi doğrula."},
  identity: {label:"Kimlik ve AD", color:"#61c8ff", icon:"♙", subtitle:"Oturum, MFA ve dizin değişiklikleri üzerinden hesap etkinliğini incele."},
  endpoint: {label:"Endpoint ve EDR", color:"#5adea4", icon:"▣", subtitle:"Process tree, dosya davranışı ve zaman çizelgesiyle host kapsamını belirle."},
  network: {label:"Ağ ve DNS", color:"#b1a3ff", icon:"⌁", subtitle:"DNS, NetFlow ve proxy kayıtlarıyla beaconing, hareket ve dış bağlantıları araştır."},
  cloud: {label:"Bulut ve Kubernetes", color:"#79d9ea", icon:"☁", subtitle:"Cloud audit, IAM ve Kubernetes kayıtlarında yetki ve veri erişimini takip et."},
  email: {label:"E-posta ve Phishing", color:"#ff96b4", icon:"✉", subtitle:"Mail gateway, URL tıklama ve kimlik loglarından maruziyet ve etkiyi ayır."},
  data: {label:"Veri Sızıntısı ve DLP", color:"#e7cd79", icon:"▤", subtitle:"Dosya erişimi, egress ve DLP verisinden aktarımın kapsamını çıkar."},
  devops: {label:"CI/CD ve Tedarik Zinciri", color:"#a7baf7", icon:"‹›", subtitle:"Pipeline, registry ve secret olaylarını build ve deploy kayıtlarıyla ilişkilendir."}
});

function exercise(id, type, minute, title, severity, ip, target, description, records, question, answer) {
  const time = `10:${String(minute).padStart(2, "0")}`;
  const seconds = ["04", "12", "26"];
  alerts.push({
    id:`SOC-${id}`, type, time:`${time}:12`, title, severity, ip, target, status:"new", description,
    events:records.map(([source, payload], index) => [`${time}:${seconds[index]}`, source, payload]),
    prompts:[question, "İlk aksiyonun ne olur ve bu aksiyonun etkisini nasıl doğrularsın?"],
    answer
  });
}

exercise(107,"ddos",27,"UDP Reflection · Edge Link", "critical","203.0.113.91","edge.example.test",
  "Edge bağlantısı doldu ve farklı servislerde paket kaybı görüldü.",
  [["NetFlow",{protocol:"UDP",src_port:53,distinct_src:6390,mbps:990,link_mbps:1000}],
   ["Edge Router",{dst:"192.0.2.10",packet_loss_pct:26,pps:811000}],
   ["Origin Monitor",{http_rps:44,baseline_rps:49,affected_services:4}]],
  "Trafiğin hacimsel olduğunu hangi kanıtlar gösteriyor?",
  "UDP/53 kaynak portları DNS reflection ile uyumlu. Bağlantı dolarken HTTP talebinin artmaması L3/L4 vakasını destekliyor. Upstream scrubbing ve sağlayıcı koordinasyonu gerekir. Link kullanımı, kayıp ve servis erişimini izle.");

exercise(108,"ddos",36,"SYN Flood · TLS Gateway", "high","203.0.113.53","tls-gw.example.test",
  "TLS gateway’de bağlantı kurulumu bozuldu. TCP el sıkışma telemetrisini kontrol et.",
  [["NetFlow",{dst_port:443,syn_per_sec:86000,ack_per_sec:480,distinct_src:12000}],
   ["Edge Gateway",{syn_backlog_used_pct:99,syn_cookie_sent:61400,tls_started_per_sec:410}],
   ["Origin Monitor",{ingress_utilization_pct:27,handshake_timeout_pct:39,http_p95_ms:210}]],
  "Bu vaka UDP reflection ve HTTP flood’dan hangi metriklerle ayrılıyor?",
  "Yüksek SYN:ACK oranı ve dolu backlog yarım kalan TCP oturumlarına işaret ediyor. SYN cookies veya SYN proxy etkisini tamamlanan handshake oranı, backlog ve meşru bağlantı başarısıyla değerlendir.");

exercise(109,"sqli",44,"Time-Based Blind SQLi · Search API","high","198.51.100.108","search.example.test",
  "Bir IP’den aynı endpoint’e gelen isteklerde süre farkı gözlendi.",
  [["WAF",{request_ids:["sql-t1","sql-t2"],action:"log",matched_patterns:["conditional-delay","control"]}],
   ["Application",{path:"/api/search",sql_t1_ms:5120,sql_t2_ms:118,repeat_pairs:6,http_status:200}],
   ["DB Audit",{trace:"sql-t1",statement_class:"SELECT",delay_function_executed:true,baseline_ms:38}]],
  "Gecikme kontrol isteği ve DB kaydıyla nasıl doğrulanıyor?",
  "Kontrollü tekrarlar ve DB’de çalışan gecikme fonksiyonu time-based SQLi’yi destekliyor. Veri çekildiğine dair kanıt için önceki istek dizilerini incele. Giriş noktasını sınırlandır ve parametreli sorguya geç.");

exercise(110,"sqli",17,"SQLi Kuralı · Katalog Araması","medium","198.51.100.18","catalog.example.test",
  "WAF kataloğa yapılan bir aramada SQL metni benzeri ifadeyi işaretledi.",
  [["WAF",{request_id:"sql-fp1",field:"search",matched:"SELECT FROM",action:"log"}],
   ["Application",{request_id:"sql-fp1",decoded_value:"SELECT FROM — SQL ders kitabı",http_status:200,rows:1}],
   ["DB Audit",{trace:"sql-fp1",prepared:true,placeholder:"$1",parameter_count:1,rows:1}]],
  "Hangi kanıtlar bu alarmın yanlış pozitif olabileceğini destekliyor?",
  "İstek ders kitabı aramasıyla uyumlu ve parametreli sorgu yapısını değiştirmemiş. Bu örneği yanlış pozitif olarak belgeleyip kural kapsamını daraltırken gerçek SQLi vakalarıyla regresyon testi yap.");

exercise(111,"xss",51,"DOM XSS · Redirect Widget","high","192.0.2.44","portal.example.test",
  "Tarayıcı telemetrisi, URL fragment’ından DOM’a yazılan içeriği işaretledi.",
  [["WAF",{path:"/dashboard",query_present:false,rule_matches:0}],
   ["Browser Telemetry",{page:"/dashboard",source:"location.hash",sink:"innerHTML",marker_rendered:true}],
   ["CSP Reporter",{directive:"script-src-attr",disposition:"report",inline_event_handler:true}]],
  "WAF kaydında URL fragment’ı neden görülmüyor ve report-only ne ifade ediyor?",
  "Fragment sunucuya gönderilmez, risk istemci tarafındaki source-to-sink akışında. Report-only politika engelleme yapmaz. Yürütülme kanıtını ve maruziyeti araştır, güvenli DOM API’leri kullan.");

exercise(112,"web",22,"Path Traversal · Download API","high","203.0.113.37","files.example.test",
  "Dosya indirme endpoint’inde beklenmeyen dosya okuması görüldü.",
  [["WAF",{request_id:"web-12",path:"/download",parameter:"..%2f..%2fconfig.yml",action:"log"}],
   ["Application",{request_id:"web-12",allowed_root:"/srv/public",resolved_path:"/srv/config.yml",status:200}],
   ["File Audit",{trace:"web-12",file:"/srv/config.yml",read_bytes:1326,uid:"webapp"}]],
  "URL decoding ve canonical path bu vakada ne gösteriyor?",
  "Okunan dosya izinli dizinin dışında ve istek 200 döndü. Erişim kapsamını belirle ve gerekirse içindeki kimlik bilgilerini döndür. Dosya kimliği veya canonical path doğrulamasıyla izinli kökü zorunlu kıl.");

exercise(113,"web",24,"SSRF · Metadata Erişimi","critical","198.51.100.27","preview.example.test",
  "Link önizleme servisi instance metadata adresine erişti.",
  [["Application",{request_id:"web-13",feature:"link_preview",resolved_ip:"169.254.169.254"}],
   ["Egress Proxy",{trace:"web-13",destination:"169.254.169.254",status:200,path_class:"role_credentials",response_bytes:934}],
   ["Cloud Audit",{identity:"preview-role",session:"i-004a",action:"ListBuckets",source_ip:"198.51.100.27"}]],
  "Hangi kayıt erişimle olası credential kullanımını birbirine bağlıyor?",
  "Önizlemenin metadata yanıtını alması ve aynı instance rolünün beklenmedik dış IP’den kullanılması araştırmayı yetki sızıntısına genişletir. Rol oturumlarını sınırlandır, dış erişimi kes ve DNS yeniden çözümleme ile yönlendirmelerde de hedef denetimi uygula.");

exercise(114,"web",28,"BOLA / IDOR · Sipariş API","high","192.0.2.86","orders.example.test",
  "Normal bir kullanıcı art arda başka hesaplara ait siparişleri okudu.",
  [["API Gateway",{request_id:"web-14",subject:"u-52",path:"/api/orders/881",status:200}],
   ["Application",{request_id:"web-14",resource_owner:"u-43",ownership_check:"not_called",records_returned:1}],
   ["API Analytics",{subject:"u-52",distinct_owners:14,requests:73,window_minutes:5}]],
  "Kimlik doğrulama kaydı neden yetkiyi ispatlamıyor?",
  "Token geçerli olsa da kaynak sahibi farklı ve nesne düzeyinde kontrol çağrılmamış. İstek geçmişinden etkilenen siparişleri çıkar ve her nesne için sahiplik veya yetki doğrulaması ekle.");

exercise(115,"web",33,"Command Injection · Export Worker","critical","192.0.2.55","export.example.test",
  "Bir export isteği sonrası web worker beklenmeyen bir shell işlemi başlattı.",
  [["API Gateway",{request_id:"web-15",path:"/api/export",argument_class:"shell_metacharacter",status:202}],
   ["Application",{request_id:"web-15",job:"job-77",worker:"export-worker-3"}],
   ["EDR",{host:"export-worker-3",job:"job-77",parent:"export-worker",child:"/bin/sh",observed_action:"unexpected system identity lookup"}]],
  "HTTP 202 ile process tree birlikte hangi hipotezi destekliyor?",
  "Job kimliği isteği beklenmeyen shell çalışmasına bağlıyor. Worker’ı izole et ve child process, ağ ve credential erişimini araştır. Shell çağrısını kaldır veya sabit argümanlarla doğrudan process başlat.");

exercise(116,"web",40,"Web Shell Şüphesi · Upload","critical","203.0.113.70","uploads.example.test",
  "Upload sonrası web sürecinin yeni dosyayı çalıştırdığına dair sinyal var.",
  [["Application",{request_id:"web-16",name:"receipt.php",declared_type:"image/jpeg",action:"saved",object_id:"f-44"}],
   ["Web Access",{path:"/uploads/receipt.php",status:200,object_id:"f-44"}],
   ["EDR",{parent:"php-fpm",child:"sh",script:"/srv/uploads/receipt.php",unexpected:true}]],
  "Dosya yükleme, HTTP erişimi ve çalıştırmayı hangi kayıtlar ayrı ayrı kanıtlıyor?",
  "Üç kayıt upload’dan process çalıştırmaya uzanan zinciri destekliyor. Host’u izole et ve dosyayı kanıt olarak koru. Upload yolunu web root dışına taşı ve bu alanda script execution’ı kapat.");

exercise(117,"identity",11,"Password Spraying · VPN","high","203.0.113.28","vpn.example.test",
  "Kısa sürede çok sayıda hesap benzer giriş hatası verdi.",
  [["VPN Auth",{src_ip:"203.0.113.28",users:72,failures:143,max_attempts_per_user:2}],
   ["Identity Provider",{outcome:"invalid_password",distinct_users:72,lockouts:0}],
   ["VPN Session",{src_ip:"203.0.113.28",user:"u-41",mfa:"passed",session:"vpn-19",tunnel_ip:"10.34.0.17"}]],
  "Davranış neden spray’e benziyor ve başarılı oturumu nasıl pivot edersin?",
  "Hesap başına az deneme ve geniş kullanıcı dağılımı spray’i destekliyor. vpn-19 ve tünel IP üzerinden iç ağ erişimini incele, kullanıcıyla doğrula ve şüpheli oturumu sonlandır.");

exercise(118,"identity",15,"MFA Fatigue · Oturum Açıldı","critical","198.51.100.29","idp.example.test",
  "Tek kullanıcıda peş peşe push reddi ve ardından kabul var.",
  [["Identity Provider",{user:"u-72",src_ip:"198.51.100.29",password:"success",auth_flow:"af-55"}],
   ["MFA",{auth_flow:"af-55",pushes:13,denied:12,last:"approved",interval_seconds:107}],
   ["SaaS Audit",{auth_flow:"af-55",session:"s-922",action:"AddMailboxRule",target:"external_forward"}]],
  "Onaydan sonra hangi kayıt hesabın fiilen kullanıldığını gösteriyor?",
  "Aynı akıştan açılan oturum forwarding kuralı eklemiş. Oturum ve token’ları iptal et, kuralı ve kalıcılık değişikliklerini araştır ve phishing-resistant MFA’yı değerlendir.");

exercise(119,"identity",19,"Impossible Travel · Kurumsal VPN","medium","198.51.100.36","idp.example.test",
  "Bir kullanıcı aynı cihazla iki farklı ülkeden görünmüş.",
  [["Identity Provider",{user:"u-81",minutes_between:6,countries:["TR","DE"],device:"managed-41"}],
   ["VPN Gateway",{device:"managed-41",new_egress:"198.51.100.36",region:"DE",gateway:"corp-vpn-de"}],
   ["Device Trust",{device:"managed-41",signing_key_match:true,session_changed:false,extra_risk_flags:0}]],
  "Konum farkını açıklayan bağımsız veri nedir?",
  "VPN egress değişikliği, aynı yönetilen cihaz ve aynı oturum konum farkını açıklıyor. Cihaz ve ağ kanıtını belgeleyerek benzer oturumlarda ek risk sinyallerini kontrol et.");

exercise(120,"identity",26,"DCSync · Beklenmeyen Replikasyon","critical","10.12.4.27","dc-01.lab.test",
  "DC dışındaki bir host’tan replikasyon yetkisi kullanımı işaretlendi.",
  [["AD Security",{event_id:4662,principal:"svc-report",access:"DS-Replication-Get-Changes-All",logon_id:"0x4108"}],
   ["Windows Security",{event_id:4624,logon_id:"0x4108",src_ip:"10.12.4.27",logon_type:3}],
   ["AD Inventory",{principal:"svc-report",approved_replication_role:false,src_is_domain_controller:false}]],
  "4662 kaydını kaynak makineye hangi alanla bağlarsın?",
  "DC üzerindeki Logon ID, yetki kullanımını servis hesabının ağ oturumuyla bağlıyor. Meşru senkronizasyon istisnalarını kontrol et. Hesabı ve host’u sınırlandırıp etki kapsamına göre koordineli credential recovery başlat.");

exercise(121,"identity",38,"AD Privilege Escalation · Grup Üyeliği","critical","10.12.3.51","dc-02.lab.test",
  "Domain Admins grubuna onay kaydı olmadan yeni üye eklendi.",
  [["AD Security",{event_id:4728,subject:"svc-deploy",member:"u-helpdesk",group:"Domain Admins",logon_id:"0x8c3"}],
   ["Windows Security",{event_id:4624,logon_id:"0x8c3",src_ip:"10.12.3.51",logon_type:3}],
   ["AD Audit",{principal:"u-helpdesk",new_privileged_logon:true,previous_privileged_membership:false}]],
  "Grup değişikliğini ve kazanılan yetkinin kullanımını hangi kayıtlar gösteriyor?",
  "4728 üyeliği, sonraki ayrıcalıklı logon ise kullanımını gösteriyor. Yetkiyi kaldırıp aktif oturumları ve değişikliği yapan hesabın diğer işlemlerini incele.");

exercise(122,"identity",41,"Kerberoasting · Servis Biletleri","high","10.12.5.32","dc-01.lab.test",
  "Bir workstation hesabı sıra dışı sayıda servis bileti istedi.",
  [["AD Security",{event_id:4769,requester:"u-32",client_ip:"10.12.5.32",distinct_spns:49,encryption:"0x17",window_seconds:55}],
   ["AD Baseline",{requester:"u-32",typical_distinct_spns:3,approved_scanner:false}],
   ["EDR",{host:"ws-32",user:"u-32",process_class:"directory enumeration",service_account_queries:47}]],
  "Bu telemetri bilet parolalarının kırıldığını söylemeye yeter mi?",
  "Toplu SPN ve RC4 bilet talepleri Kerberoasting ile uyumlu. Offline parola kırma bu loglarda görünmez. İlgili servis hesaplarının sonraki kullanımlarını incele, güçlü rastgele parola veya gMSA ve uygun şifreleme uygula.");

exercise(123,"endpoint",13,"Ransomware · Toplu Dosya Değişikliği","critical","10.24.4.18","finance-ws-18.lab.test",
  "Bir süreç toplu dosya yeniden adlandırma ve shadow copy silme sinyali üretti.",
  [["EDR",{process:"invoice-viewer.exe",pid:5116,signature:"unsigned",write_count:1674,rename_suffix:".locked"}],
   ["Windows Security",{parent_pid:5116,child:"vssadmin.exe",operation:"delete shadows",outcome:"success"}],
   ["File Server",{src_ip:"10.24.4.18",share:"finance",changed_files:318,principal:"u-fin-18"}]],
  "Yerel şifreleme şüphesini paylaşımlı dosya etkisine hangi log genişletiyor?",
  "EDR davranışı ve paylaşım değişiklikleri şifreleme hipotezini destekliyor. Endpoint’i izole et, ilgili paylaşım yazmalarını kes, etkiyi ve sağlam backup durumunu doğrula.");

exercise(124,"endpoint",16,"PowerShell · Office Child Process","high","10.24.2.14","ws-14.lab.test",
  "Word altında PowerShell ve dış bağlantı görüldü.",
  [["EDR",{process_guid:"p-124",parent:"WINWORD.EXE",child:"powershell.exe",encoded_argument:true}],
   ["PowerShell",{event_id:4104,process_guid:"p-124",script_behavior:"download and execute",amsi_result:"detected"}],
   ["Proxy",{device:"ws-14",host:"assets-check.example.test",status:200,bytes_in:18642}]],
  "Proxy’de 200 görülmesi disk üzerinde yürütmeyi kanıtlar mı?",
  "Process tree ve script davranışı zinciri destekliyor. Proxy indirme başarısını gösterir. Sonraki process, bellek ve dosya kanıtıyla yürütmeyi doğrula, cihazı izole et ve dokümanın dağıtım kapsamını araştır.");

exercise(125,"endpoint",23,"Credential Dumping · LSASS Access","critical","10.24.2.75","ws-75.lab.test",
  "İmzasız bir process LSASS erişimi açtı ve dump dosyası yazdı.",
  [["Sysmon",{event_id:10,source_process:"diag-helper.exe",target_process:"lsass.exe",source_guid:"p-125",granted_access:"0x1010"}],
   ["Sysmon",{event_id:11,process_guid:"p-125",path:"C:\\Temp\\diag.dmp",size_bytes:38666240}],
   ["EDR",{host:"ws-75",process_guid:"p-125",signature:"unsigned",approved_diagnostic:false}]],
  "LSASS handle erişimi ile dump yazılması arasındaki ilişkiyi nasıl kurarsın?",
  "Process GUID iki kaydı bağlıyor. Dosya içeriğini güvenli ortamda doğrula. Host’u izole et, maruz kalmış oturumları ve bu makinede bulunan ayrıcalıklı hesapları incele.");

exercise(126,"endpoint",30,"Scheduled Task · Persistence","high","10.24.2.47","ws-47.lab.test",
  "Kullanıcı yazılabilir bir dizinden periyodik çalışan görev oluşturuldu.",
  [["Windows Security",{event_id:4698,task:"Vendor Sync",subject:"u-47",run_as:"SYSTEM"}],
   ["Task Scheduler",{task:"Vendor Sync",trigger:"every 10 minutes",image:"C:\\ProgramData\\Temp\\sync.exe"}],
   ["EDR",{process:"sync.exe",parent:"taskeng.exe",signed:false,first_seen:true}]],
  "Görevin oluşturulması ile çalıştırılması hangi ayrı kanıtlarla doğrulanıyor?",
  "4698 oluşturmayı, EDR process zinciri yürütmeyi gösteriyor. XML ve executable’ı koruyup görevi devre dışı bırak, oluşturucu hesabı ve benzer görevleri araştır.");

exercise(127,"endpoint",35,"EDR Alarmı · Yetkili Yönetim Aracı","medium","10.24.8.35","ws-35.lab.test",
  "Uzaktan yönetim aracı hedefte servis oluşturdu.",
  [["Windows System",{event_id:7045,service:"RemoteAssist",attributed_account:"svc-support",src_ip:"10.24.8.35"}],
   ["EDR",{binary:"RemoteAssist.exe",signature_valid:true,hash_match:"approved_inventory"}],
   ["Change Audit",{ticket:"CHG-512",window:"10:30–10:45",approved_source:"10.24.8.35",approved_target:"ws-35"}]],
  "Binary imzasına ek olarak hangi yetkilendirme kanıtını ararsın?",
  "Hash, kaynak/hedef ve değişiklik penceresi onayla örtüşüyor. Onay kapsamı dışındaki sistemleri ve servis aksiyonlarını kontrol et. Eşleşen kaydı meşru değişiklik olarak belgeleyebilirsin.");

exercise(128,"network",14,"DNS Tunneling Şüphesi","high","10.44.2.17","dns-resolver.lab.test",
  "Bir endpoint uzun ve değişken DNS label’larıyla yüksek hacimli sorgu üretti.",
  [["DNS",{client:"10.44.2.17",zone:"sync-edge.example.test",query_count:1189,unique_labels:1124,median_label_length:58,type:"TXT"}],
   ["Proxy",{host:"10.44.2.17",web_requests_to_zone:0}],
   ["EDR",{host:"ws-dns17",network_process:"sync-agent.exe",first_seen:true,approved:false}]],
  "CDN veya telemetri trafiğinden ayırmak için hangi baseline ve host kanıtlarını kullanırsın?",
  "Yüksek benzersiz label oranı, uzunluk ve yeni process tünel şüphesini destekliyor. İçeriği ve yönü doğrula. Domain’i kontrollü engelle, süreci araştır ve aynı paterni diğer istemcilerde ara.");

exercise(129,"network",21,"Beaconing · Düzenli HTTPS","high","10.44.2.96","telemetry-edge.example.test",
  "Bir istemci sabit aralığa yakın küçük HTTPS bağlantıları kuruyor.",
  [["NetFlow",{source:"10.44.2.96",count:29,median_interval_seconds:60,interval_stddev_seconds:2.2,median_bytes_out:744}],
   ["Proxy",{host:"telemetry-edge.example.test",device:"ws-96",tls_interception:false,new_domain_in_env:true}],
   ["EDR",{host:"ws-96",process:"updater.exe",signature:"unsigned",install_source:"user_download"}]],
  "Periyodiklik neden tek başına C2 ispatı sayılmaz?",
  "Planlı updater’lar da periyodik olabilir. Yeni domain, imzasız binary ve kurulum kaynağı şüpheyi artırıyor. Dosya kökeni, parent process ve hedef bağlantılarını doğrula.");

exercise(130,"network",29,"Lateral Movement · SMB Service","critical","10.44.5.11","file-07.lab.test",
  "Bir workstation’dan dosya sunucusuna yönetim paylaşımı ve servis kurulumu görüldü.",
  [["Windows Security",{host:"file-07",event_id:4624,src_ip:"10.44.5.11",user:"svc-backup",logon_id:"0x511"}],
   ["Windows Security",{host:"file-07",event_id:5145,share:"ADMIN$",path:"Temp\\svc.exe",logon_id:"0x511",write:true}],
   ["Windows System",{host:"file-07",event_id:7045,service:"SvcTemp",image:"C:\\Windows\\Temp\\svc.exe"}]],
  "Hangi alan SMB yazmasını oturuma, hangi alan yazılan dosyayı servise bağlıyor?",
  "Logon ID ilk iki olayı, dosya yolu servis kurulumunu bağlıyor. Kaynak host’u ve servis hesabını sınırlandırıp aynı servis veya hash ile diğer hedefleri ara.");

exercise(131,"network",46,"Internal Scan · Vulnerability Scanner","medium","10.44.1.9","core-segment.lab.test",
  "Bir cihaz kısa sürede çok sayıda iç hedefe dokundu.",
  [["NetFlow",{src_ip:"10.44.1.9",distinct_hosts:191,distinct_ports:25,successful_tcp_pct:7}],
   ["Asset Inventory",{ip:"10.44.1.9",purpose:"managed vulnerability scanner",owner:"security engineering"}],
   ["Scanner Audit",{source_ip:"10.44.1.9",job:"SCAN-411",authorized_range:"10.44.0.0/16",started:"10:45:00Z"}]],
  "Varlık rolü tek başına alarmı kapatmak için yeterli mi?",
  "Rolü job kaydı, izinli ağ ve zaman penceresiyle doğrula. Yetkili taramayla örtüşen aktiviteyi belgeleyip kapsam dışı port veya hedef olup olmadığını kontrol et.");

exercise(132,"cloud",12,"AWS IAM · Access Key ile Yetki Artışı","critical","198.51.100.122","aws-account-7341",
  "Bir servis anahtarı beklenmeyen konumdan IAM değişiklikleri yaptı.",
  [["CloudTrail",{event:"AttachUserPolicy",actor:"ci-old-key",target_user:"ci-helper",policy:"AdministratorAccess",source_ip:"198.51.100.122"}],
   ["CloudTrail",{event:"CreateAccessKey",actor:"ci-old-key",target_user:"ci-helper",new_key_ref:"key-ref-132"}],
   ["CloudTrail",{event:"ListSecrets",key_ref:"key-ref-132",source_ip:"198.51.100.122",result:"success"}]],
  "İlk ve son olay arasında hangi aktör ve yeni credential ilişkisi var?",
  "İlk anahtar ayrıcalık ve yeni anahtar oluşturmuş, yeni anahtar başka hizmette kullanılmış. İki anahtarı sınırlandır, yaratılan yetkileri ve secret erişimini incele.");

exercise(133,"cloud",18,"S3 · Beklenmeyen Nesne İndirme","critical","203.0.113.52","exports-bucket",
  "Depo politikası değişikliğinden sonra dışarıdan nesne okuma görüldü.",
  [["CloudTrail",{event:"PutBucketPolicy",bucket:"exports-bucket",principal_added:"external-account",actor:"ci-role"}],
   ["S3 Access",{bucket:"exports-bucket",operation:"GET.OBJECT",principal:"external-account",status:200,objects:86,bytes_sent:36540812}],
   ["Data Catalog",{bucket:"exports-bucket",classification:"customer export",approved_cross_account:false}]],
  "Politika değişikliği ve başarılı veri erişimi için hangi kayıtlar kullanılır?",
  "Bucket policy izin değişikliğini, S3 access logları gerçekten aktarılan nesneleri kanıtlıyor. Politikayı düzelt, ayrıntılı obje listesini ve önceki alışılmadık erişimleri çıkar.");

exercise(134,"cloud",25,"Entra ID · OAuth Consent Grant","high","192.0.2.32","entra-tenant-01",
  "Kullanıcı, yeni bir üçüncü taraf uygulamasına posta ve kalıcı erişim izni verdi.",
  [["Entra Audit",{operation:"Consent to application",user:"u-134",app_id:"app-83",scopes:["Mail.Read","offline_access"],publisher_verified:false}],
   ["Sign-in Logs",{app_id:"app-83",user:"u-134",client_ip:"192.0.2.32",token_type:"refresh",status:"success"}],
   ["SaaS Audit",{app_id:"app-83",user:"u-134",operation:"MailItemsAccessed",count:194}]],
  "Consent kaydı ile posta erişimi arasında hangi alanla pivot yaparsın?",
  "App ID ve kullanıcı üç kaydı bağlıyor. Uygulama grant’ını kaldır ve oturumları iptal et. Başka kullanıcılara veya daha geniş tenant izinlerine bak.");

exercise(135,"cloud",34,"Kubernetes · Privileged Pod","critical","10.50.1.44","cluster-prod.lab.test",
  "Bir service account host erişimli ve privileged bir pod yarattı.",
  [["Kubernetes Audit",{verb:"create",kind:"Pod",namespace:"apps",user:"system:serviceaccount:apps:builder",pod_uid:"pod-85",privileged:true,host_path:"/"}],
   ["Runtime Security",{pod_uid:"pod-85",node:"worker-04",action:"host filesystem access",path:"/host/etc"}],
   ["Deployment Audit",{namespace:"apps",approved_build_id:null,expected_privileged:false}]],
  "Manifest riskiyle gerçek host erişimini hangi iki kayıt ayırıyor?",
  "API audit pod konfigürasyonunu, runtime kaydı host erişimini doğruluyor. Pod’u sınırlandır, node ve service account ayrıcalıklarını incele. Admission ve RBAC kontrolü ekle.");

exercise(136,"cloud",47,"Kubernetes · Service Account Secret Read","high","10.50.2.26","cluster-prod.lab.test",
  "Bir workload alışılmış namespace’i dışında secret listeliyor.",
  [["Kubernetes Audit",{verb:"list",resource:"secrets",namespace:"payments",username:"system:serviceaccount:metrics:collector",response_code:200}],
   ["RBAC Audit",{subject:"metrics:collector",binding:"temp-reader",scope:"cluster",granted_by:"deployer"}],
   ["Workload Inventory",{name:"collector",expected_resources:["pods","nodes"],expected_secret_reads:false}]],
  "200 sonucu hangi maruziyeti gösterir ve hangi son kullanım kanıtı eksik?",
  "Secret list erişimi yetkili görünse de beklenmiyor. Erişilen nesne kapsamını ve credential kullanımını araştır, binding’i kaldır ve maruz kalmış secret’ları koordineli döndür.");

exercise(137,"email",10,"Credential Phishing · Sahte Giriş","high","192.0.2.71","mail.example.test",
  "Birden fazla kullanıcı sahte SSO bağlantısı içeren e-posta aldı.",
  [["Mail Gateway",{message_id:"msg-137",from_domain:"login-support.example.test",spf:"pass",delivered:31}],
   ["URL Protection",{message_id:"msg-137",users_clicked:4,clicked_url:"https://sso-verify.example.test/login"}],
   ["Identity Provider",{user:"u-17",new_device:true,interactive_login:"success",src_ip:"192.0.2.71",time_since_click_seconds:46}]],
  "Teslim, tıklama ve olası hesap ele geçirmeyi hangi veriler ayrı ayrı destekliyor?",
  "Mail ve URL kayıtları maruziyeti, yeni cihaz oturumu olası credential kullanımını gösteriyor. Maili karantinaya al, tıklayanları incele ve şüpheli oturumu iptal et.");

exercise(138,"email",20,"BEC · Yeni Forwarding Kuralı","critical","198.51.100.84","mail.example.test",
  "Mali işler posta kutusunda dışa yönlendirme ve ödeme yazışması görüldü.",
  [["Identity Provider",{user:"finance-02",session:"mail-338",src_ip:"198.51.100.84",device_managed:false}],
   ["Mailbox Audit",{session:"mail-338",operation:"New-InboxRule",criteria:"invoice",forward_to:"inbox@external.example.test"}],
   ["Mail Trace",{actor:"finance-02",message_type:"invoice bank details change",external_delivery_count:2}]],
  "Kural oluşturma ve gerçekten dışarı giden mesaj arasında hangi ayrım var?",
  "Audit kuralı, mail trace dış teslimi gösteriyor. Oturumu iptal et, kuralı kaldır, erişilen konuşmaları belirle ve finans ekibiyle ödeme talimatlarını ayrı kanaldan doğrula.");

exercise(139,"email",37,"Malicious Attachment · Script Chain","high","10.24.8.92","ws-92.lab.test",
  "Bir arşiv ekinden çıkarılan kısayol sonrası script çalıştı.",
  [["Mail Gateway",{message_id:"msg-139",attachment:"shipping.zip",delivered_to:"u-92"}],
   ["EDR",{device:"ws-92",user:"u-92",file_origin:"shipping.zip",opened:"shipment.lnk",child:"wscript.exe"}],
   ["EDR",{device:"ws-92",parent:"wscript.exe",child:"powershell.exe",execution:"blocked",network_connects:0}]],
  "İlk çalıştırma olmuş mu ve EDR hangi aşamayı engellemiş?",
  "Kısayol ve wscript yürümüş, sonraki PowerShell adımı engellenmiş. İlk script’in olası yan etkilerini incele, mesajı karantinaya al ve diğer alıcıları tara.");

exercise(140,"data",32,"Bulk Download · SaaS Export","high","198.51.100.131","drive.example.test",
  "Bir hesap kısa sürede olağan dışı sayıda özel belge indirdi.",
  [["SaaS Audit",{user:"sales-14",operation:"download",objects:708,bytes:2395012021,window_minutes:9}],
   ["Identity Provider",{user:"sales-14",src_ip:"198.51.100.131",managed_device:false,session:"d-140"}],
   ["DLP",{session:"d-140",sensitivity:"Customer Confidential",matched_objects:62,approved_export_job:false}]],
  "Aktarım kapsamını dosya sayısı dışında hangi alanlarla belirlersin?",
  "Dosya sınıflandırması ve obje kimlikleriyle etkilenen veriyi çıkar. Oturumu ve hesabı değerlendir, indirme yetkisini sınırlandır ve veri sahibine doğrulanmış kapsamı ilet.");

exercise(141,"data",43,"Archive Upload · Proxy Egress","critical","10.33.4.44","upload-gateway.example.test",
  "Hassas dosyalar arşivlendikten sonra harici depoya yükleme görüldü.",
  [["EDR",{host:"ws-44",process:"7z.exe",artifact:"client-export.7z",bytes:24781926,hash_ref:"sha-art-141"}],
   ["DLP",{host:"ws-44",hash_ref:"sha-art-141",verdict:"match",action:"monitor",classification:"restricted"}],
   ["Proxy",{client:"10.33.4.44",host:"upload-gateway.example.test",method:"POST",status:201,bytes_out:24781926}]],
  "Hangi kanıtlar olası transfer yerine tamamlanmış bir upload’ı destekliyor?",
  "Arşiv boyutu, DLP hash’i, zaman ve 201 response birbirini destekliyor. Gerekirse hedef sağlayıcı kaydıyla nesne oluşturmayı doğrula. Egress’i sınırlandır ve arşivdeki belge kapsamını çıkar.");

exercise(142,"data",48,"DLP · Onaylı Yedekleme","medium","10.33.1.10","backup-vault.example.test",
  "Bir servis izinli görünen depoya çok miktarda hassas veri gönderdi.",
  [["DLP",{src_ip:"10.33.1.10",bytes_out:3301132288,classification:"restricted",channel:"https"}],
   ["Backup Audit",{job:"daily-142",src_ip:"10.33.1.10",destination:"backup-vault.example.test",encrypted:true,started:"10:47:00Z"}],
   ["Asset Inventory",{destination:"backup-vault.example.test",approved_destination:true,owner:"platform"}]],
  "Yanlış pozitif kararı için hangi üç bağlamı doğrularsın?",
  "Kaynak, zaman penceresi ve hedef belirtilen yedekleme işiyle örtüşüyor. İşin veri kapsamını ve şifreleme durumunu kayda geçir, kapsam dışı aktarımları ayrıca incele.");

exercise(143,"devops",15,"CI/CD · Pipeline Tanımı Değişti","critical","192.0.2.126","ci.example.test",
  "Pipeline’a bilinmeyen bir ağ hedefi eklenmiş ve runner o hedefe bağlanmış.",
  [["Git Audit",{repo:"shop-api",commit:"demo-143",actor:"bot-integrate",file:".ci/build.yml",reviewed:false}],
   ["CI Runner",{run_id:"run-143",commit:"demo-143",step:"publish metadata",private_secrets_in_context:4}],
   ["Proxy",{container:"runner-143",run_id:"run-143",host:"job-insights.example.test",method:"POST",status:200,body_logged:false}]],
  "Dış bağlantı var. Secret sızıntısı için hangi kanıt henüz eksik?",
  "Commit ve run ID değişikliği egress’e bağlıyor. POST başarılı olsa da gövde kaydı yok. Runner ve artifact’ları karantinaya al, kullanılan secret kapsamını belirleyip hassas credential’ları döndür.");

exercise(144,"devops",39,"Registry · İmaj Digest Değişimi","critical","198.51.100.192","registry.example.test",
  "Aynı imaj etiketi beklenmedik digest’e taşındı ve yeni pod onu çalıştırdı.",
  [["Registry Audit",{repo:"payments",tag:"stable",previous_digest:"sha256:demo-a",new_digest:"sha256:demo-b",actor:"registry-bot"}],
   ["Build Attestation",{digest:"sha256:demo-b",trusted_signature:false,approved_release_record:false}],
   ["Kubernetes Audit",{pod:"payments-7fb3",running_digest:"sha256:demo-b",status:"Running"}]],
  "Tag ile digest neden farklı güven seviyesi sağlar?",
  "Tag değiştirilebilir. Registry ve runtime kayıtları imajın değiştiğini ve çalıştığını gösteriyor. Deployment’ı doğrulanmış digest’e geri al, çalışan pod’ları ve pipeline credential’larını incele.");

exercise(145,"devops",52,"Secret Exposure · Artifact ve Kullanım","high","203.0.113.154","api.example.test",
  "Bir build artifact’ta anahtar parmak izi bulundu ve aynı anahtar API’de kullanıldı.",
  [["Secret Scanner",{artifact:"build-992.log",fingerprint:"key-fp-145",visibility:"org-wide",plaintext_retained:false}],
   ["CI Audit",{artifact:"build-992.log",downloads:7,created_by:"publish-job",run_id:"r-145"}],
   ["API Gateway",{fingerprint:"key-fp-145",src_ip:"203.0.113.154",key_use:"success",expected_runner_ip:false}]],
  "Secret’ı görüntülemeden sızıntıyla kullanımı nasıl ilişkilendirirsin?",
  "Parmak izi iki kaydı güvenli biçimde bağlıyor. Anahtarı iptal et, API çağrı kapsamını ve artifact erişimlerini incele. Masking ve artifact erişim kontrollerini düzelt.");

exercise(146,"web",12,"JWT · Hatalı İmza Doğrulaması","critical","198.51.100.77","auth-api.example.test",
  "API, identity provider tarafından imzalanmamış yönetici token’ını kabul etti.",
  [["API Gateway",{request_id:"web-146",route:"/api/admin/export",jwt_kid:"unknown-key",verification:"skipped",status:200}],
   ["Application",{request_id:"web-146",claimed_role:"admin",exported_records:41}],
   ["Identity Provider",{kid:"unknown-key",issued_by_tenant:false,expected_algorithm:"RS256"}]],
  "Token claim’i ile token’ın güvenilirliğini belirleyen kanıtlar hangi kaynaklarda?",
  "İmza doğrulaması atlanmış ve ayrıcalıklı çağrı başarılı. İmza, issuer, audience, süre ve izinli algoritmayı zorunlu kıl. Etkilenen API çağrılarını ve dönen veriyi belirle.");

exercise(147,"web",49,"CSRF · Hesap Ayarı Değişikliği","high","192.0.2.97","account.example.test",
  "Oturumu açık bir kullanıcının hesap ayarı yabancı bir sayfa üzerinden değiştirildi.",
  [["Web Access",{request_id:"csrf-147",route:"/settings/forwarding",method:"POST",origin:"https://cross-site.example.test",sec_fetch_site:"cross-site"}],
   ["Application",{request_id:"csrf-147",cookie_authenticated:true,csrf_token:"absent",status:200}],
   ["Account Audit",{request_id:"csrf-147",user:"u-147",operation:"forwarding_address_updated"}]],
  "Bu kayıtlarda isteğin cross-site geldiğini ve yan etki yarattığını ne gösteriyor?",
  "Origin ve Fetch Metadata site geçişini, hesap kaydı yan etkiyi gösteriyor. CSRF token’ı ve uygun cookie ayarlarını uygula, benzer state-changing endpoint’leri incele.");

exercise(148,"identity",47,"Credential Stuffing · Müşteri Girişleri","high","203.0.113.124","login.example.test",
  "Dağıtık istemcilerden çok sayıda hesapta giriş denemesi gözlendi.",
  [["Bot Management",{route:"/login",requests:2720,distinct_ips:164,max_attempts_per_account:2,repeated_client_pattern:true}],
   ["Identity Provider",{distinct_users:1290,successes:18,password_fields_redacted:true,mfa_required:false}],
   ["Account Audit",{user:"u-148",correlated_login:"lg-148",password_changed:true,device_first_seen:true}]],
  "Bu telemetriyle credential stuffing ve password spraying arasında kesin ayrım yapılabilir mi?",
  "Dağıtık düşük tekrar ve başarılı girişler stuffing hipotezini destekliyor. Parolalar kaydedilmediği için kullanılan parola desenini doğrulayamıyoruz. Riskli başarıları araştır ve hesap eylemlerini karşılaştır.");

exercise(149,"identity",53,"Session Hijacking · Token Replay","critical","192.0.2.150","idp.example.test",
  "Aynı oturum kimliği kısa aralıkla beklenmeyen bir cihazdan kullanıldı.",
  [["Identity Provider",{session_id:"sess-149",user:"u-149",issued_to:"device-17",mfa:"passed"}],
   ["API Gateway",{session_id:"sess-149",source_ip:"192.0.2.150",device_claim:"device-96",token_valid:true}],
   ["SaaS Audit",{session_id:"sess-149",device:"device-96",action:"ExportContacts",count:221}]],
  "İlk MFA başarısı sonraki isteğin meşruluğunu kanıtlıyor mu?",
  "MFA ilk oturumu doğruluyor. Sonraki cihaz ve etkinlik farkı token replay araştırmasını gerektiriyor. Oturumu iptal et ve aynı token’ın kullanım kapsamını çıkar.");

exercise(150,"endpoint",42,"Linux Persistence · Yetkisiz SSH Anahtarı","high","10.24.7.17","linux-17.lab.test",
  "Bir servis kullanıcısının authorized_keys dosyasına yeni anahtar eklendi.",
  [["Linux Audit",{uid:"websvc",process:"python3",path:"/home/websvc/.ssh/authorized_keys",operation:"write"}],
   ["SSH Auth",{user:"websvc",fingerprint:"sha256:demo-150",src_ip:"198.51.100.153",outcome:"Accepted publickey"}],
   ["Change Audit",{host:"linux-17",fingerprint:"sha256:demo-150",approved_change:false}]],
  "Dosya yazımı, anahtar kullanımı ve onay durumunu nasıl ilişkilendirirsin?",
  "Dosya yazımını ve aynı hesaba yeni anahtarla açılan oturumu ilişkilendir. Parmak izini dosyadan doğrula, şüpheli erişimi kes ve websvc süreciyle yapılan diğer değişikliklere bak.");

exercise(151,"network",50,"RDP · Başarısız Denemeler Sonrası Giriş","high","198.51.100.165","rdp-gateway.example.test",
  "RDP gateway’de tek kullanıcı için yoğun denemelerden sonra başarılı erişim var.",
  [["Firewall",{src_ip:"198.51.100.165",target_port:3389,connections:89,policy:"rdp-admin"}],
   ["Windows Security",{event_id:4625,logon_type:10,user:"u-rdp-1",attempts:87,src_ip:"198.51.100.165"}],
   ["Windows Security",{event_id:4624,logon_type:10,user:"u-rdp-1",logon_id:"0x151",src_ip:"198.51.100.165"}]],
  "Bu davranış spray’den nasıl ayrılıyor? Başarılı giriş sonrası neleri sorgularsın?",
  "Denemelerin tek hesaba yoğunlaşması brute-force hipotezini destekliyor. Başarılı remote interactive logon sonrası process, dosya ve ağ aktivitesini Logon ID ve zaman üzerinden araştır.");

exercise(152,"cloud",29,"AWS · Audit Loglama Durduruldu","critical","198.51.100.155","aws-account-7341",
  "Üretim CloudTrail kaydının beklenmedik oturumla durdurulduğu bildirildi.",
  [["Organization Trail",{event:"StopLogging",region:"eu-central-1",trail:"prod-trail",actor_session:"s-152"}],
   ["Identity Audit",{session:"s-152",role:"deploy-role",source_ip:"198.51.100.155",usual_source:"corporate-runner"}],
   ["Monitoring",{trail:"prod-trail",delivery_gap_seconds:720,remaining_source:"organization-trail"}]],
  "Log boşluğu sırasında araştırmayı hangi mevcut kayıtlarla sürdürürsün?",
  "Kayıt teslim boşluğu sinyaliyle StopLogging olayını eşleştir. Loglamayı geri aç, rol oturumunu sınırlandır ve merkezi organization trail, servis erişim logları ve ağ telemetrisiyle boşluğu araştır.");

exercise(153,"cloud",55,"Cloud Workload · Cryptomining Şüphesi","high","10.50.3.24","worker-07.lab.test",
  "Bir workload yeni çalıştırılabilir dosyayla yüksek CPU tüketiyor ve pool benzeri hedefe bağlanıyor.",
  [["Runtime Security",{node:"worker-07",pod:"export-153",process:"compute-helper",image_signature:"unknown",cpu_pct:98}],
   ["DNS",{client:"10.50.3.24",query:"pool-worker.example.test",first_seen:true}],
   ["Network Runtime",{pod:"export-153",dst_port:3333,protocol_guess:"stratum",egress_connections:12}]],
  "CPU artışını normal batch job’dan hangi sinyaller ayırıyor?",
  "Yeni süreç ve hedefle birlikte Stratum benzeri bağlantı mining hipotezini güçlendiriyor. Workload’u sınırlandır, image ve giriş vektörünü incele, CPU ve egress normale dönüyor mu kontrol et.");

exercise(154,"data",54,"Removable Media · USB Dosya Kopyası","high","10.33.7.19","eng-ws-19.lab.test",
  "Şirket dokümanları yeni takılan çıkarılabilir ortama kopyalandı.",
  [["Device Control",{host:"eng-ws-19",usb_serial:"usb-154",managed:false,action:"mount",volume:"E:"}],
   ["File Audit",{host:"eng-ws-19",user:"eng-19",destination:"E:",files_written:98,classification:"internal engineering"}],
   ["DLP",{device_serial:"usb-154",rule:"restricted source code",matches:19,policy_mode:"monitor"}]],
  "USB takılması, dosya yazımı ve hassas içerik tespiti hangi kayıtlarla ayrılıyor?",
  "Mount yalnızca medya erişimini gösteriyor. File Audit ve DLP aktarım ile hassas içeriği destekliyor. Dosya listesini, kullanıcı yetkisini ve cihaz sahipliğini doğrula.");

exercise(155,"devops",57,"Package Dependency · Install Script","high","198.51.100.199","build-runner-02.lab.test",
  "Build sırasında yeni bir bağımlılık kurulum script’i gizli değerlerin bulunduğu Runner’da çalıştı.",
  [["Git Audit",{repo:"checkout",commit:"demo-155",file:"package-lock.json",new_transitive_package:"format-helper-extra"}],
   ["CI Runner",{commit:"demo-155",step:"install",lifecycle_script:"postinstall",process_id:15510}],
   ["EDR",{process_id:15510,child:"node",network_target:"package-metrics.example.test",result:"connected"}]],
  "Etkiyi repo kapsamından runner ve üretilen artifact’lara nasıl genişletirsin?",
  "Lockfile, lifecycle script ve PID zinciri giriş noktasını bağlıyor. Paketi ve build’leri karantinaya al, runner erişim kapsamını ve artifact bütünlüğünü incele.");

alerts.sort((first, second) => second.time.localeCompare(first.time) || first.id.localeCompare(second.id));
