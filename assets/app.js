/*!
 * PC Check | CyberSecInfo
 * Four checks that run in the visitor's browser. MIT License.
 * Written in ES2017 on purpose, so that older browsers can still run it and be told they are old.
 */
(function () {
  'use strict';

  var CONFIG = {
    versionsUrl: 'api/versions.php',
    dnsResultUrl: 'api/dnsleak.php',
    traceUrls: ['https://one.one.one.one/cdn-cgi/trace', 'https://www.cloudflare.com/cdn-cgi/trace'],
    hibpRangeUrl: 'https://api.pwnedpasswords.com/range/',
    dnsProbeCount: 20,
    timeoutMs: 10000
  };

  var STATUS_ORDER = ['risk', 'warn', 'error', 'info', 'ok'];

  // ---------------------------------------------------------------------------
  // Text (PT-BR and EN). Functions receive values; nothing here touches the DOM.
  // ---------------------------------------------------------------------------
  var STR = {
    pt: {
      docTitle: 'Checagem de segurança do navegador | CyberSecInfo',
      skip: 'Pular para as verificações',
      langLabel: 'Idioma',
      title: 'Checagem de segurança do navegador',
      lead: 'Quatro verificações rápidas, feitas aqui no navegador, sem instalar nada. Nada sai do seu aparelho antes de você clicar, e tudo o que sair fica listado no registro de saída.',
      run: 'Verificar agora',
      running: 'Verificando…',
      runAgain: 'Verificar de novo',
      ledgerJump: 'Registro de saída',
      oldBrowser: 'Se o botão não responder, este navegador é antigo demais para rodar a página. Isso já é um sinal de que ele precisa de atualização.',
      checksTitle: 'Verificações',

      browserTitle: 'Navegador',
      browserQ: 'Seu navegador está atualizado?',
      connTitle: 'Conexão',
      connQ: 'A conexão usa criptografia moderna?',
      dnsTitle: 'DNS',
      dnsQ: 'Quem responde as suas consultas de DNS?',
      pwTitle: 'Senha',
      pwQ: 'Essa senha já apareceu em vazamentos?',

      st_idle: 'Não verificado',
      st_running: 'Verificando',
      st_ok: 'Tudo certo',
      st_warn: 'Atenção',
      st_risk: 'Risco',
      st_info: 'Informativo',
      st_error: 'Não deu para verificar',

      summary: function (c) {
        var parts = [];
        if (c.ok) parts.push('sem problemas: ' + c.ok);
        if (c.warn) parts.push('atenção: ' + c.warn);
        if (c.risk) parts.push('risco: ' + c.risk);
        if (c.info) parts.push('informativo: ' + c.info);
        if (c.error) parts.push('não verificado: ' + c.error);
        return 'Concluído. ' + capitalize(parts.join('; ')) + '.';
      },

      // Facts
      fBrowser: 'Navegador',
      fVersion: 'Sua versão',
      fEngine: 'Motor',
      fLatest: 'Mais recente',
      fLatestEsr: 'Mais recente (ESR)',
      fTls: 'Criptografia',
      fEch: 'Nome do site escondido (ECH)',
      fPq: 'Proteção pós-quântica',
      fHttp: 'Protocolo',
      fWarp: 'Cloudflare WARP',
      fPage: 'Esta página',
      fYourIp: 'Seu IP público',
      fDnsServers: 'Servidores de DNS',
      yes: 'Sim',
      no: 'Não',
      on: 'Ativo',
      unknown: 'Não informado',
      httpsOk: 'Aberta com HTTPS',
      httpsNo: 'Aberta sem HTTPS',

      // Browser
      browserOk: function (name, version) { return name + ' ' + version + ' está em dia.'; },
      browserPatch: function (name) { return 'Existe uma atualização de segurança do ' + name + ' que ainda não foi instalada.'; },
      browserBehind: function (name) { return 'Existe uma versão mais nova do ' + name + ' que ainda não foi instalada.'; },
      browserOld: function (name) { return 'Este ' + name + ' está desatualizado e pode ter falhas de segurança já conhecidas.'; },
      browserEsrMaybe: function (version) { return 'Firefox ' + version + ': se for a edição ESR, de suporte estendido, está em dia. Se for a edição comum, está desatualizado.'; },
      browserIos: 'No iPhone e no iPad, todo navegador usa o motor do sistema. Ele fica seguro quando o iOS está atualizado.',
      browserSafari: 'O Safari se atualiza junto com o macOS, então a versão mais recente não dá para confirmar daqui.',
      browserSamsung: 'O Samsung Internet usa uma base própria e recebe correções pela Galaxy Store.',
      browserUnknown: 'Não reconhecemos este navegador, então não dá para comparar a versão.',
      browserVersionsError: 'Não conseguimos buscar as versões mais recentes agora. Tente de novo em instantes.',
      fixUpdate: 'Abra o menu do navegador, entre em Ajuda e depois em Sobre. Ele procura a atualização sozinho; reinicie quando terminar.',
      fixFirefoxAbout: 'Abra o menu do Firefox, entre em Ajuda e depois em Sobre o Firefox para ver a edição e atualizar.',
      fixIos: 'Ajustes > Geral > Atualização de Software.',
      fixSafari: 'Menu Apple > Ajustes do Sistema > Geral > Atualização de Software.',
      fixSamsung: 'Galaxy Store > Menu > Atualizações.',

      // Connection
      connOk: 'A conexão usou TLS 1.3, a versão mais moderna da criptografia da web.',
      connTls12: 'A conexão usou TLS 1.2 com um servidor que aceita o 1.3. Antivírus ou proxies que inspecionam o tráfego HTTPS costumam causar isso.',
      connOld: function (v) { return 'A conexão usou ' + v + ', uma versão antiga e vulnerável.'; },
      connPageHttp: 'Esta página abriu sem HTTPS, então o que passa por ela pode ser lido no caminho.',
      connUnknown: 'A Cloudflare respondeu, mas não informou a versão da criptografia.',
      connError: 'Não conseguimos falar com a Cloudflare. Um bloqueador de anúncios ou a rede pode ter impedido o teste.',
      connEchNote: 'O ECH esconde de quem observa a rede qual site você visita. Ainda é pouco usado, então “Não” é o resultado mais comum.',
      connPqNote: 'A proteção pós-quântica impede que alguém grave o tráfego hoje para decifrar no futuro com computadores quânticos.',
      fixTlsInspect: 'Se você usa antivírus com “verificação de HTTPS” ou “proteção web”, veja se dá para desligar essa função. Em computador da empresa, fale com a TI.',
      fixConnError: 'Tente de novo ou use o teste da própria Cloudflare.',
      cfCheckLink: 'Abrir o teste da Cloudflare',

      // DNS
      dnsOk: function (n) { return n === 1 ? '1 servidor de DNS respondeu as consultas e não há sinal de vazamento.' : n + ' servidores de DNS responderam as consultas e não há sinal de vazamento.'; },
      dnsLeak: 'Possível vazamento: as consultas de DNS saíram por uma rede diferente da sua conexão.',
      dnsDone: function (n) { return n === 1 ? '1 servidor de DNS respondeu as consultas.' : n + ' servidores de DNS responderam as consultas.'; },
      dnsNone: 'Nenhuma consulta chegou ao servidor de teste. Um bloqueador ou o DNS seguro do navegador pode ter filtrado os endereços de teste.',
      dnsError: 'O teste de DNS não respondeu agora. Tente de novo em instantes.',
      dnsRate: 'Muitos testes seguidos. Espere alguns minutos e tente de novo.',
      dnsNote: 'Sem VPN, ver aqui o DNS da sua operadora é normal. Com VPN ligada, ele não deveria aparecer.',
      fixDns: 'Se você usa VPN, ative a proteção contra vazamento de DNS no app dela. Também dá para ligar o DNS seguro nas configurações de privacidade do navegador.',

      // Password
      pwLabel: 'Senha para verificar',
      pwShow: 'Mostrar',
      pwHide: 'Ocultar',
      pwHint: 'A senha não sai do aparelho. Só os 5 primeiros caracteres do código dela (o hash) são enviados.',
      pwCheck: 'Verificar senha',
      pwChecking: 'Verificando…',
      pwEmpty: 'Digite uma senha para verificar.',
      pwNoCrypto: 'Este navegador não permite calcular o código da senha aqui. A página precisa estar em HTTPS.',
      pwFound: function (n) { return 'Essa senha apareceu ' + n + (n === '1' ? ' vez' : ' vezes') + ' em vazamentos. Não use mais em lugar nenhum.'; },
      pwNotFound: 'Essa senha não aparece nos vazamentos conhecidos. Isso não quer dizer que ela seja forte.',
      pwError: 'Não conseguimos consultar a base de vazamentos agora. Tente de novo.',
      fixPw: 'Troque essa senha em todos os sites onde ela é usada e ative a verificação em duas etapas. Um gerenciador de senhas ajuda a ter uma diferente para cada site.',
      notePwOk: 'Use uma senha longa e diferente em cada site. Uma frase com quatro ou mais palavras funciona bem.',
      hashOut: 'Saiu do aparelho',
      hashKept: 'Ficou no aparelho',
      hashCaption: function (n) { return 'Código SHA-1 da senha. Só os 5 primeiros caracteres foram enviados. O serviço devolveu ' + n + ' códigos parecidos, e a comparação foi feita aqui.'; },

      // Ledger
      ledgerTitle: 'O que saiu do seu aparelho',
      ledgerEmpty: 'Nada ainda. Cada pedido aparece aqui no momento em que acontece.',
      ledgerNote: 'Qualquer pedido revela ao destino o seu endereço IP e o tipo de navegador. Isso faz parte de toda conexão na internet.',
      ledgerCount: function (n) { return n === 0 ? 'Nenhum pedido até agora.' : (n === 1 ? '1 pedido até agora.' : n + ' pedidos até agora.'); },
      ledgerSent: 'Enviado:',
      ledgerNothing: 'nada além do pedido',
      lpVersions: 'Versões mais recentes dos navegadores (este site)',
      lpTrace: 'Diagnóstico da conexão (Cloudflare)',
      lpDnsProbes: function (n) { return n + ' consultas de DNS a endereços de teste (bash.ws)'; },
      lpDnsResult: 'Resultado do teste de DNS. Este site repassa o código do teste e o seu IP à bash.ws.',
      lpHibp: 'Consulta da senha (Pwned Passwords)',

      // About
      aboutTitle: 'Como funciona',
      aboutPw: 'Senha: o navegador transforma a senha num código (hash SHA-1) e envia só os 5 primeiros caracteres. O serviço Pwned Passwords devolve centenas de códigos que começam igual, e a comparação acontece aqui. Nem o serviço sabe qual senha você testou.',
      aboutDns: 'DNS: o navegador consulta 20 endereços de teste que só existem para você. O serviço bash.ws registra quais servidores de DNS fizeram essas consultas e compara com a rede da sua conexão.',
      aboutConn: 'Conexão: a Cloudflare informa como o seu navegador se conectou a ela, com a versão do TLS e se o nome do site foi escondido (ECH).',
      aboutBrowser: 'Navegador: a versão é lida aqui mesmo e comparada com a versão mais recente publicada pelo Google e pela Mozilla.',
      aboutPrivacy: 'Esta página não usa cookies, analytics nem scripts de terceiros.',
      creditsLead: 'Serviços usados:',
      creditsAnd: 'e',
      footMade: 'Feito por Adriano Huttener para o CyberSecInfo.',
      footCode: 'Código aberto no GitHub'
    },

    en: {
      docTitle: 'PC Check | CyberSecInfo',
      skip: 'Skip to the checks',
      langLabel: 'Language',
      title: 'PC Check',
      lead: 'Four quick checks that run right here in your browser, with nothing to install. Nothing leaves your device until you click, and everything that does is listed in the outbound log.',
      run: 'Check now',
      running: 'Checking…',
      runAgain: 'Check again',
      ledgerJump: 'Outbound log',
      oldBrowser: 'If the button does nothing, this browser is too old to run the page. That alone is a sign it needs updating.',
      checksTitle: 'Checks',

      browserTitle: 'Browser',
      browserQ: 'Is your browser up to date?',
      connTitle: 'Connection',
      connQ: 'Does the connection use modern encryption?',
      dnsTitle: 'DNS',
      dnsQ: 'Who answers your DNS lookups?',
      pwTitle: 'Password',
      pwQ: 'Has this password shown up in data breaches?',

      st_idle: 'Not checked',
      st_running: 'Checking',
      st_ok: 'All good',
      st_warn: 'Attention',
      st_risk: 'Risk',
      st_info: 'For your info',
      st_error: "Couldn't check",

      summary: function (c) {
        var parts = [];
        if (c.ok) parts.push('all good: ' + c.ok);
        if (c.warn) parts.push('attention: ' + c.warn);
        if (c.risk) parts.push('risk: ' + c.risk);
        if (c.info) parts.push('for your info: ' + c.info);
        if (c.error) parts.push("couldn't check: " + c.error);
        return 'Done. ' + capitalize(parts.join('; ')) + '.';
      },

      fBrowser: 'Browser',
      fVersion: 'Your version',
      fEngine: 'Engine',
      fLatest: 'Latest',
      fLatestEsr: 'Latest (ESR)',
      fTls: 'Encryption',
      fEch: 'Site name hidden (ECH)',
      fPq: 'Post-quantum protection',
      fHttp: 'Protocol',
      fWarp: 'Cloudflare WARP',
      fPage: 'This page',
      fYourIp: 'Your public IP',
      fDnsServers: 'DNS servers',
      yes: 'Yes',
      no: 'No',
      on: 'On',
      unknown: 'Not reported',
      httpsOk: 'Loaded over HTTPS',
      httpsNo: 'Loaded without HTTPS',

      browserOk: function (name, version) { return name + ' ' + version + ' is up to date.'; },
      browserPatch: function (name) { return 'A security update for ' + name + ' is available but not installed yet.'; },
      browserBehind: function (name) { return 'A newer version of ' + name + ' is available but not installed yet.'; },
      browserRolling: function (name) { return 'A new version of ' + name + ' is rolling out and should reach you in the next days.'; },
      browserOld: function (name) { return 'This ' + name + ' is out of date and may have publicly known security flaws.'; },
      browserEsrMaybe: function (version) { return 'Firefox ' + version + ': if this is the ESR (extended support) edition, it is up to date. If it is the regular edition, it is out of date.'; },
      browserIos: 'On iPhone and iPad, every browser uses the system engine. It stays safe when iOS is up to date.',
      browserSafari: 'Safari updates together with macOS, so the latest version cannot be confirmed from here.',
      browserSamsung: 'Samsung Internet uses its own base and gets fixes through the Galaxy Store.',
      browserUnknown: "We don't recognise this browser, so its version can't be compared.",
      browserVersionsError: "We couldn't fetch the latest versions right now. Try again in a moment.",
      fixUpdate: 'Open the browser menu, then Help and About. It looks for the update on its own; restart when it finishes.',
      fixFirefoxAbout: 'Open the Firefox menu, then Help and About Firefox, to see the edition and update.',
      fixIos: 'Settings > General > Software Update.',
      fixSafari: 'Apple menu > System Settings > General > Software Update.',
      fixSamsung: 'Galaxy Store > Menu > Updates.',

      connOk: 'The connection used TLS 1.3, the most modern version of web encryption.',
      connTls12: 'The connection used TLS 1.2 with a server that supports 1.3. Antivirus tools or proxies that inspect HTTPS traffic often cause this.',
      connOld: function (v) { return 'The connection used ' + v + ', an old and vulnerable version.'; },
      connPageHttp: 'This page loaded without HTTPS, so what passes through it can be read along the way.',
      connUnknown: 'Cloudflare answered but did not report the encryption version.',
      connError: "We couldn't reach Cloudflare. An ad blocker or the network may have stopped the test.",
      connEchNote: 'ECH hides which site you visit from anyone watching the network. It is still rare, so “No” is the most common result.',
      connPqNote: 'Post-quantum protection stops someone from recording traffic today to decrypt it later with quantum computers.',
      fixTlsInspect: 'If your antivirus has “HTTPS scanning” or “web protection”, see if you can turn that feature off. On a work computer, ask IT.',
      fixConnError: "Try again or use Cloudflare's own test.",
      cfCheckLink: "Open Cloudflare's test",

      dnsOk: function (n) { return n === 1 ? '1 DNS server answered the lookups, with no sign of a leak.' : n + ' DNS servers answered the lookups, with no sign of a leak.'; },
      dnsLeak: 'Possible leak: your DNS lookups went out through a different network than your connection.',
      dnsDone: function (n) { return n === 1 ? '1 DNS server answered the lookups.' : n + ' DNS servers answered the lookups.'; },
      dnsNone: "No lookups reached the test server. A blocker or the browser's secure DNS may have filtered the test addresses.",
      dnsError: "The DNS test didn't respond right now. Try again in a moment.",
      dnsRate: 'Too many tests in a row. Wait a few minutes and try again.',
      dnsNote: "Without a VPN, seeing your internet provider's DNS here is normal. With a VPN on, it shouldn't appear.",
      fixDns: "If you use a VPN, turn on DNS leak protection in its app. You can also turn on secure DNS in the browser's privacy settings.",

      pwLabel: 'Password to check',
      pwShow: 'Show',
      pwHide: 'Hide',
      pwHint: 'The password never leaves your device. Only the first 5 characters of its code (the hash) are sent.',
      pwCheck: 'Check password',
      pwChecking: 'Checking…',
      pwEmpty: 'Type a password to check.',
      pwNoCrypto: "This browser can't compute the password code here. The page needs HTTPS.",
      pwFound: function (n) { return 'This password has appeared ' + n + (n === '1' ? ' time' : ' times') + ' in data breaches. Stop using it everywhere.'; },
      pwNotFound: "This password isn't in known breaches. That doesn't mean it is strong.",
      pwError: "We couldn't reach the breach database right now. Try again.",
      fixPw: 'Change this password on every site that uses it and turn on two-step verification. A password manager makes it easy to have a different one per site.',
      notePwOk: 'Use a long, different password for each site. A phrase of four or more words works well.',
      hashOut: 'Left your device',
      hashKept: 'Stayed on your device',
      hashCaption: function (n) { return 'SHA-1 code of the password. Only the first 5 characters were sent. The service returned ' + n + ' similar codes, and the comparison happened here.'; },

      ledgerTitle: 'What left your device',
      ledgerEmpty: 'Nothing yet. Each request appears here the moment it happens.',
      ledgerNote: 'Every request reveals your IP address and browser type to the destination. That is part of every connection on the internet.',
      ledgerCount: function (n) { return n === 0 ? 'No requests so far.' : (n === 1 ? '1 request so far.' : n + ' requests so far.'); },
      ledgerSent: 'Sent:',
      ledgerNothing: 'nothing beyond the request',
      lpVersions: 'Latest browser versions (this site)',
      lpTrace: 'Connection diagnostics (Cloudflare)',
      lpDnsProbes: function (n) { return n + ' DNS lookups of test addresses (bash.ws)'; },
      lpDnsResult: 'DNS test result. This site passes the test code and your IP to bash.ws.',
      lpHibp: 'Password lookup (Pwned Passwords)',
      lpStun: 'WebRTC address check (STUN, UDP 3478). A STUN request (no personal data).',
      webrtcTitle: 'WebRTC leak',
      webrtcQ: 'Can sites see your real IP through WebRTC?',
      webrtcOk: 'WebRTC shows the same public address as your connection. No leak.',
      webrtcBlocked: 'WebRTC is turned off or blocked in this browser, so it cannot expose your IP.',
      webrtcNone: 'WebRTC did not reveal any address.',
      webrtcLeak: 'WebRTC revealed a different public address than your connection. Your real IP may be leaking past your VPN or proxy.',
      webrtcLocal: 'No public leak, but WebRTC shows your address on the local network.',
      webrtcOtherFamily: 'No leak found. WebRTC only showed an address of the other IP version (IPv4/IPv6), so it could not be compared directly.',
      webrtcNoCompare: "Couldn't compare: the connection check didn't return your public IP.",
      webrtcNote: 'With a VPN on, the public address here should be the VPN’s, not your home one.',
      fixWebrtc: 'Turn on your VPN’s WebRTC leak protection, or block WebRTC: Firefox about:config media.peerconnection.enabled = false; Chrome/Edge an extension such as WebRTC Leak Shield; Brave Settings > Privacy > WebRTC IP handling policy.',
      fixWebrtcLocal: 'Most browsers hide local addresses by default. If you changed WebRTC settings or flags, restore the defaults.',
      fWebrtcPublic: 'Public address via WebRTC',
      fWebrtcLocal: 'Local address via WebRTC',
      trackTitle: 'Trackability',
      trackQ: 'How easy is this browser to track without cookies?',
      trackLow: function (n) { return 'Estimated trackability: low. ' + n + ' privacy protections found.'; },
      trackMedium: 'Estimated trackability: medium. 1 privacy protection found.',
      trackHigh: 'Estimated trackability: high. No privacy protection found.',
      trackNote: 'This is an estimate. Any site can read the details below without cookies; together they can recognise a browser. Nothing here left your device.',
      fixTrack: 'Turn on Global Privacy Control, add a tracker blocker such as uBlock Origin, or use a browser with fingerprinting protection (Brave, Firefox, Safari).',
      fOs: 'System',
      fLanguage: 'Language',
      fTimeZone: 'Time zone',
      fScreen: 'Screen',
      fCores: 'CPU cores',
      fMemory: 'Memory (approx.)',
      fGpu: 'Graphics',
      fTouch: 'Touch screen',
      fCanvas: 'Canvas fingerprint',
      fGpc: 'Global Privacy Control',
      fDnt: 'Do Not Track (ignored by most sites)',
      fBlocker: 'Tracker blocker',
      fItp: 'Built-in tracking prevention',
      vOn: 'On',
      vOff: 'Off',
      vYes: 'Yes',
      vNo: 'No',
      vDetected: 'Detected',
      vNotDetected: 'Not detected',
      vRandomised: 'Randomised (protected)',
      speedTitle: 'Internet speed',
      speedQ: 'How fast is your connection right now?',
      speedGo: 'GO',
      speedAgain: 'Test again',
      speedCancel: 'Cancel',
      speedWarn: 'Runs only when you press GO. Uses up to about 55 MB of data.',
      speedFast: function (d) { return 'Fast connection: ' + d + ' Mbps download.'; },
      speedOk: function (d) { return 'Good for browsing and video: ' + d + ' Mbps download.'; },
      speedSlow: function (d) { return 'Slow connection: ' + d + ' Mbps download. HD video and large downloads will struggle.'; },
      speedFail: "We couldn't measure the speed. The connection dropped or the test was blocked.",
      speedCancelled: 'Speed test cancelled.',
      speedOld: 'This browser is too old to run the speed test. That alone is a sign it needs updating.',
      speedNote: 'Measured to the nearest Cloudflare data centre. Wi-Fi signal and other devices on your network affect the result.',
      speedPingHigh: 'Ping is above 100 ms: calls and games may feel laggy.',
      speedPartial: 'The connection slowed down during the test, so this result uses the parts that finished.',
      fixSpeed: 'Test again close to the router or with a cable. If it stays slow, restart the router and check your plan with your provider.',
      fDown: 'Download',
      fUp: 'Upload',
      fPing: 'Ping',
      fJitter: 'Jitter',
      fColo: 'Cloudflare data centre',
      lpSpeed: function (phase) { return 'Speed test, ' + phase + ' (Cloudflare)'; },
      pdfBtn: 'Download PDF report',
      pdfHint: 'Choose “Save as PDF” in the print window.',
      reportTitle: 'PC Check report',
      reportGenerated: function (when) { return 'Generated ' + when; },
      reportPrefix: function (p) { return 'Sent to Pwned Passwords: only the first 5 characters of the hash (' + p + '). The password itself is not in this report.'; },
      reportFoot: 'Generated locally in your browser — nothing was sent to CyberSecInfo. cybersecinfo.com/pccheck',

      // System report (Windows reports read on this device)
      sysBanner: function (family, label) {
        switch (family) {
          case 'windows': return 'You’re on ' + label + '. Follow the three steps below to check this PC.';
          case 'mac': return 'You’re on macOS. Mac reports are coming soon; for now PC Check reads Windows reports.';
          case 'linux': return 'You’re on Linux. Linux reports are coming soon; for now PC Check reads Windows reports.';
          case 'android': return 'You’re on Android. These steps are done on a computer: open this page there, or follow them on the computer and come back with the files.';
          case 'ios': return 'You’re on an iPhone or iPad. These steps are done on a computer: open this page there, or follow them on the computer and come back with the files.';
          default: return 'Pick the system of the computer you want to check.';
        }
      },
      sysSoon: function (name) { return name + ' reports are coming soon. For now PC Check reads Windows reports; the browser checks above work on any system.'; },
      sysReading: 'Reading the file on this device…',
      sysReadReliability: function (date, n) { return 'Read: reliability history' + (date ? ' saved ' + date : '') + ', ' + n + (n === 1 ? ' event.' : ' events.'); },
      sysReadBattery: 'Read: battery report.',
      sysReadMsinfo: 'Read: system information.',
      sysNotReliability: 'This doesn’t look like a Reliability history file. In Reliability Monitor, use “Save reliability history…” and pick the .xml file.',
      sysNotBattery: 'This doesn’t look like a battery report. Pick the battery-report.html file the command saved on your Desktop.',
      sysNotMsinfo: 'This doesn’t look like a System Information export. In msinfo32, use File > Export and pick the .txt file.',
      sysLooksLike: function (step) { return ' It looks like the file for step ' + step + '.'; },
      sysLanguage: 'This report is in a language PC Check can’t read yet — the crash history still works.',
      sysTooBig: 'This file is larger than 40 MB, so it is not one of the reports PC Check reads.',
      sysReadError: 'This file could not be read. Try saving it again.',
      sysNeedFile: 'Add at least one report first. The crash history (step 1) tells the most.',
      sysDone: 'Analyzed on this device. Nothing was sent.',
      sysNoCrash: 'Analyzed on this device. Nothing was sent. Add the crash history (step 1) for the full picture.',
      sysCopied: 'Copied',
      sysCopy: 'Copy',
      sysScoreTitle: 'Health score',
      sysVerdictOk: 'No serious problems in these reports.',
      sysVerdictWarn: 'A few things need attention.',
      sysVerdictRisk: 'This PC has problems worth fixing soon.',
      sysReportFrom: function (date) { return 'Reliability history from ' + date + ' · read on this device, nothing uploaded'; },
      sysLocalOnly: 'Read on this device, nothing uploaded',
      sysFindingsTitle: 'What we found',
      sysNoFindings: 'Nothing to fix in these reports.',
      sysFactsTitle: 'This PC',
      sysFix: 'Fix: ',
      sev_risk: 'Risk',
      sev_warn: 'Attention',
      sev_info: 'For your info',

      aboutTitle: 'How it works',
      aboutPw: 'Password: your browser turns the password into a code (SHA-1 hash) and sends only the first 5 characters. Pwned Passwords returns hundreds of codes that start the same way, and the comparison happens here. Not even the service knows which password you checked.',
      aboutDns: 'DNS: your browser looks up 20 test addresses that exist only for you. The bash.ws service records which DNS servers made those lookups and compares them with your connection’s network.',
      aboutConn: 'Connection: Cloudflare reports how your browser connected to it, including the TLS version and whether the site name was hidden (ECH).',
      aboutBrowser: 'Browser: the version is read right here and compared with the latest version published by Google and Mozilla.',
      aboutPrivacy: 'This page uses no cookies, no analytics and no third-party scripts.',
      creditsLead: 'Services used:',
      creditsAnd: 'and',
      footMade: 'Made by Adriano Huttener for CyberSecInfo.',
      footCode: 'Open source on GitHub'
    }
  };

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------
  var state = {
    lang: 'en',
    running: false,
    ranOnce: false,
    summaryCounts: null,
    checks: {
      browser: blankCheck(),
      connection: blankCheck(),
      dns: blankCheck(),
      webrtc: blankCheck(),
      tracking: blankCheck(),
      speed: blankCheck(),
      password: blankCheck()
    },
    ledger: [],
    hash: null,
    pwVisible: false,
    pwBusy: false,
    pwError: null,
    speed: { running: false, result: null, controller: null },
    // System report: os = detected system, selected = button chosen, steps = per-file message for the UI
    sys: {
      os: null,
      selected: 'windows',
      files: { reliability: null, battery: null, msinfo: null },
      steps: { reliability: null, battery: null, msinfo: null },
      status: null,
      evaluation: null
    }
  };

  function blankCheck() {
    return { status: 'idle', verdict: null, facts: [], note: null, fix: null, link: null };
  }

  // ---------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function capitalize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

  function t(key) {
    var args = Array.prototype.slice.call(arguments, 1);
    var table = STR[state.lang] || STR.en;
    var value = Object.prototype.hasOwnProperty.call(table, key) ? table[key] : STR.en[key];
    if (typeof value === 'function') return value.apply(null, args);
    return value == null ? key : value;
  }

  // A "spec" is either plain text or [key, ...args] resolved in the current language.
  function resolve(spec) {
    if (spec == null) return '';
    if (Array.isArray(spec)) return t.apply(null, spec);
    return String(spec);
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function withTimeout(promise, ms) {
    return new Promise(function (resolveFn, rejectFn) {
      var timer = setTimeout(function () { rejectFn(new Error('timeout')); }, ms);
      promise.then(function (v) { clearTimeout(timer); resolveFn(v); }, function (e) { clearTimeout(timer); rejectFn(e); });
    });
  }

  function request(url, options) {
    var opts = Object.assign({ cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error' }, options || {});
    var controller = typeof AbortController === 'function' ? new AbortController() : null;
    if (controller) opts.signal = controller.signal;
    var timer = setTimeout(function () { if (controller) controller.abort(); }, CONFIG.timeoutMs);
    return fetch(url, opts).then(function (res) {
      clearTimeout(timer);
      return res;
    }, function (err) {
      clearTimeout(timer);
      throw err;
    });
  }

  function getJSON(url) {
    return request(url, { headers: { Accept: 'application/json' } }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) {
        if (!res.ok) {
          var err = new Error('http_' + res.status);
          err.status = res.status;
          err.body = body;
          throw err;
        }
        return body;
      });
    });
  }

  function getText(url, headers) {
    return request(url, headers ? { headers: headers } : null).then(function (res) {
      if (!res.ok) throw new Error('http_' + res.status);
      return res.text();
    });
  }

  function formatNumber(n) {
    try { return Number(n).toLocaleString(state.lang === 'pt' ? 'pt-BR' : 'en-IE'); } catch (e) { return String(n); }
  }

  function formatTime(date) {
    try {
      return date.toLocaleTimeString(state.lang === 'pt' ? 'pt-BR' : 'en-IE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (e) {
      return date.toTimeString().slice(0, 8);
    }
  }

  function isLocalHost() {
    return /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname);
  }

  function compareVersions(a, b) {
    var pa = String(a).split('.').map(function (x) { return parseInt(x, 10) || 0; });
    var pb = String(b).split('.').map(function (x) { return parseInt(x, 10) || 0; });
    var len = Math.max(pa.length, pb.length);
    for (var i = 0; i < len; i++) {
      var x = pa[i] || 0;
      var y = pb[i] || 0;
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  }

  function majorOf(v) { var n = parseInt(String(v), 10); return isNaN(n) ? null : n; }

  // ---------------------------------------------------------------------------
  // Outbound ledger
  // ---------------------------------------------------------------------------
  function logOutbound(host, purpose, data) {
    state.ledger.push({ ts: new Date(), host: host, purpose: purpose, data: data || [], isNew: true });
    renderLedger();
  }

  function renderLedger() {
    var list = $('#ledger-list');
    list.textContent = '';
    state.ledger.forEach(function (entry) {
      var li = el('li', 'ledger-item' + (entry.isNew ? ' is-new' : ''));
      li.appendChild(el('span', 'ledger-time', formatTime(entry.ts)));
      li.appendChild(el('div', 'ledger-host', entry.host));
      li.appendChild(el('p', 'ledger-purpose', resolve(entry.purpose)));
      var sent = el('p', 'ledger-sent', t('ledgerSent'));
      if (entry.data.length) {
        entry.data.forEach(function (value) { sent.appendChild(el('span', 'data', value)); });
      } else {
        sent.appendChild(document.createTextNode(' ' + t('ledgerNothing')));
      }
      li.appendChild(sent);
      list.appendChild(li);
      entry.isNew = false;
    });
    var n = state.ledger.length;
    $('#ledger-empty').hidden = n > 0;
    $('#ledger-count').textContent = t('ledgerCount', n);
    $('#ledger-count-inline').textContent = String(n);
  }

  // ---------------------------------------------------------------------------
  // Check rendering
  // ---------------------------------------------------------------------------
  function setCheck(id, patch) {
    state.checks[id] = Object.assign(blankCheck(), patch);
    renderCheck(id);
    renderPdfButton();
  }

  function renderCheck(id) {
    var data = state.checks[id];
    var root = document.getElementById('check-' + id);
    root.setAttribute('data-status', data.status);
    $('.mark use', root).setAttribute('href', '#i-' + data.status);
    $('[data-role="pill"]', root).textContent = t('st_' + data.status);
    $('[data-role="verdict"]', root).textContent = resolve(data.verdict);

    var facts = $('[data-role="facts"]', root);
    // The password card has no facts list (it shows the hash instead).
    if (facts) facts.textContent = '';
    if (facts) data.facts.forEach(function (f) {
      facts.appendChild(el('dt', null, resolve(f.label)));
      var dd = el('dd');
      if (f.list) {
        var ul = el('ul');
        f.list.forEach(function (item) {
          var li = el('li');
          if (item.data) li.appendChild(el('span', 'data', item.data));
          if (item.text) li.appendChild(document.createTextNode((item.data ? ' ' : '') + item.text));
          ul.appendChild(li);
        });
        dd.appendChild(ul);
      } else if (f.data) {
        dd.appendChild(el('span', 'data', resolve(f.value)));
      } else {
        dd.textContent = resolve(f.value);
      }
      facts.appendChild(dd);
    });

    $('[data-role="note"]', root).textContent = resolve(data.note);

    var fix = $('[data-role="fix"]', root);
    fix.textContent = resolve(data.fix);
    if (data.link && data.fix) {
      fix.appendChild(document.createTextNode(' '));
      var a = el('a', null, t(data.link.text));
      a.href = data.link.href;
      a.rel = 'noopener noreferrer';
      fix.appendChild(a);
    }

    if (id === 'password') renderHash();
  }

  function renderHash() {
    var root = document.getElementById('check-password');
    var box = $('[data-role="hash"]', root);
    if (!state.hash) { box.hidden = true; return; }
    box.hidden = false;
    $('[data-role="hash-out"]', root).textContent = state.hash.prefix;
    $('[data-role="hash-kept"]', root).textContent = new Array(36).join('•');
    $('[data-role="hash-caption"]', root).textContent = t('hashCaption', formatNumber(state.hash.returned));
  }

  function renderStatic() {
    var html = document.documentElement;
    html.lang = state.lang === 'pt' ? 'pt-BR' : 'en';
    document.title = t('docTitle');
    $all('[data-i18n]').forEach(function (node) {
      node.textContent = t(node.getAttribute('data-i18n'));
    });
    $all('[data-i18n-aria]').forEach(function (node) {
      node.setAttribute('aria-label', t(node.getAttribute('data-i18n-aria')));
    });
    $all('.lang button').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-lang') === state.lang));
    });
    renderRunButton();
    renderPasswordForm();
  }

  function renderRunButton() {
    var btn = $('#run');
    btn.disabled = state.running;
    btn.textContent = state.running ? t('running') : (state.ranOnce ? t('runAgain') : t('run'));
    $('#run-status').textContent = (!state.running && state.summaryCounts) ? t('summary', state.summaryCounts) : '';
  }

  function renderPasswordForm() {
    var input = $('#pw');
    var toggle = $('#pw-toggle');
    input.type = state.pwVisible ? 'text' : 'password';
    toggle.setAttribute('aria-pressed', String(state.pwVisible));
    toggle.textContent = state.pwVisible ? t('pwHide') : t('pwShow');
    var submit = $('#pw-submit');
    submit.disabled = state.pwBusy;
    submit.textContent = state.pwBusy ? t('pwChecking') : t('pwCheck');
    $('#pw-error').textContent = state.pwError ? t(state.pwError) : '';
  }

  function renderAll() {
    renderStatic();
    renderSpeedButtons();
    Object.keys(state.checks).forEach(renderCheck);
    renderLedger();
    renderSys();
  }

  // ---------------------------------------------------------------------------
  // Check 1: browser version
  // ---------------------------------------------------------------------------
  var PREFERRED_BRANDS = ['Microsoft Edge', 'Brave', 'Opera', 'Opera GX', 'Vivaldi', 'Samsung Internet', 'YaBrowser', 'DuckDuckGo', 'Google Chrome'];

  function detectBrowser() {
    var ua = navigator.userAgent || '';
    var info = { name: null, version: null, family: 'unknown', engineMajor: null, platform: null };
    var isIOS = /iPhone|iPad|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    var m;

    if (isIOS) {
      info.family = 'ios';
      if ((m = ua.match(/CriOS\/([\d.]+)/))) { info.name = 'Chrome'; info.version = m[1]; }
      else if ((m = ua.match(/FxiOS\/([\d.]+)/))) { info.name = 'Firefox'; info.version = m[1]; }
      else if ((m = ua.match(/EdgiOS\/([\d.]+)/))) { info.name = 'Edge'; info.version = m[1]; }
      else if ((m = ua.match(/Version\/([\d.]+).*Safari/))) { info.name = 'Safari'; info.version = m[1]; }
      else { info.name = 'WebKit'; }
      return Promise.resolve(info);
    }

    var uad = navigator.userAgentData;
    if (uad && Array.isArray(uad.brands) && uad.brands.length) {
      var high = typeof uad.getHighEntropyValues === 'function'
        ? uad.getHighEntropyValues(['fullVersionList', 'platform']).catch(function () { return {}; })
        : Promise.resolve({});
      return high.then(function (hev) {
        var list = (hev && hev.fullVersionList && hev.fullVersionList.length) ? hev.fullVersionList : uad.brands;
        var real = list.filter(function (b) {
          return b && b.brand && !/^not.a.brand$/i.test(String(b.brand).replace(/\s+/g, ' ').trim());
        });
        var chromium = find(real, function (b) { return b.brand === 'Chromium'; });
        var named = null;
        for (var i = 0; i < PREFERRED_BRANDS.length && !named; i++) {
          named = find(real, sameBrand(PREFERRED_BRANDS[i]));
        }
        if (!named) named = find(real, function (b) { return b.brand !== 'Chromium'; }) || chromium;
        if (!named) return fromUserAgent(ua, info);

        info.family = /Samsung/i.test(named.brand) ? 'samsung' : 'chromium';
        info.name = named.brand.replace(/^Google /, '');
        info.version = named.version;
        info.engineMajor = majorOf((chromium || named).version);
        info.platform = mapPlatform((hev && hev.platform) || uad.platform);
        return info;
      });
    }

    return Promise.resolve(fromUserAgent(ua, info));
  }

  function find(arr, fn) {
    for (var i = 0; i < arr.length; i++) if (fn(arr[i])) return arr[i];
    return null;
  }

  function sameBrand(name) { return function (b) { return b.brand === name; }; }

  function mapPlatform(p) {
    switch (String(p || '')) {
      case 'Windows': return 'win';
      case 'macOS': return 'mac';
      case 'Linux': return 'linux';
      case 'Android': return 'android';
      default: return null;
    }
  }

  function fromUserAgent(ua, info) {
    var m;
    var chrome = ua.match(/Chrom(?:e|ium)\/([\d.]+)/);
    if ((m = ua.match(/SamsungBrowser\/([\d.]+)/))) {
      info.family = 'samsung'; info.name = 'Samsung Internet'; info.version = m[1];
    } else if ((m = ua.match(/Firefox\/([\d.]+)/)) && !/Seamonkey/i.test(ua)) {
      info.family = 'firefox'; info.name = 'Firefox'; info.version = m[1]; info.engineMajor = majorOf(m[1]);
    } else if ((m = ua.match(/Edg(?:e|A)?\/([\d.]+)/))) {
      info.family = 'chromium'; info.name = 'Edge'; info.version = m[1]; info.engineMajor = majorOf((chrome || m)[1]);
    } else if ((m = ua.match(/OPR\/([\d.]+)/))) {
      info.family = 'chromium'; info.name = 'Opera'; info.version = m[1]; info.engineMajor = chrome ? majorOf(chrome[1]) : null;
    } else if (chrome) {
      info.family = 'chromium'; info.name = /Chromium\//.test(ua) ? 'Chromium' : 'Chrome'; info.version = chrome[1]; info.engineMajor = majorOf(chrome[1]);
    } else if ((m = ua.match(/Version\/([\d.]+).*Safari/))) {
      info.family = 'safari'; info.name = 'Safari'; info.version = m[1];
    }
    if (/Windows/.test(ua)) info.platform = 'win';
    else if (/Android/.test(ua)) info.platform = 'android';
    else if (/Mac OS X/.test(ua)) info.platform = 'mac';
    else if (/Linux/.test(ua)) info.platform = 'linux';
    return info;
  }

  function shortVersion(v) {
    if (!v) return '';
    var parts = String(v).split('.');
    // Reduced user-agent strings end in .0.0.0; show only the meaningful part.
    while (parts.length > 1 && parts[parts.length - 1] === '0') parts.pop();
    return parts.join('.');
  }

  // A patch reaches everyone gradually; under 14 days old it is still "rolling out".
  // Only used for a pending patch: rollout dates change often and say nothing reliable about a whole major version.
  var ROLLOUT_DAYS = 14;
  function isRollingOut(released, now) {
    var when = released ? Date.parse(released) : NaN;
    if (isNaN(when)) return false;
    return (now || new Date()).getTime() - when < ROLLOUT_DAYS * 86400000;
  }

  function evaluateBrowser(b, v, now) {
    var facts = [{ label: ['fBrowser'], value: b.name || t('unknown') }];
    if (b.version) facts.push({ label: ['fVersion'], value: shortVersion(b.version), data: true });

    if (b.family === 'ios') return { status: 'info', verdict: ['browserIos'], facts: facts, fix: ['fixIos'] };
    if (b.family === 'samsung') return { status: 'info', verdict: ['browserSamsung'], facts: facts, fix: ['fixSamsung'] };
    if (b.family === 'safari') return { status: 'info', verdict: ['browserSafari'], facts: facts, fix: ['fixSafari'] };

    if (b.family === 'chromium' && b.engineMajor && v && v.chrome) {
      var isChrome = b.name === 'Chrome';
      var platformLatest = (b.platform && v.chrome[b.platform]) || v.chrome.win || null;
      if (!platformLatest) return { status: 'error', verdict: ['browserVersionsError'], facts: facts };
      if (!isChrome) facts.push({ label: ['fEngine'], value: 'Chromium ' + b.engineMajor, data: true });
      facts.push({ label: ['fLatest'], value: isChrome ? platformLatest.version : 'Chromium ' + platformLatest.major, data: true });

      var diff = platformLatest.major - b.engineMajor;
      if (diff >= 2) return { status: 'risk', verdict: ['browserOld', b.name], facts: facts, fix: ['fixUpdate'] };
      var rolling = isRollingOut(platformLatest.released, now);
      if (diff === 1) return { status: 'warn', verdict: ['browserBehind', b.name], facts: facts, fix: ['fixUpdate'] };
      // Same major. Chrome reports its full version, so pending security patches are visible too.
      if (isChrome && diff === 0 && compareVersions(b.version, platformLatest.version) < 0 && !/\.0\.0\.0$/.test(b.version)) {
        return { status: rolling ? 'info' : 'warn', verdict: [rolling ? 'browserRolling' : 'browserPatch', b.name], facts: facts, fix: ['fixUpdate'] };
      }
      return { status: 'ok', verdict: ['browserOk', b.name, shortVersion(b.version)], facts: facts };
    }

    if (b.family === 'firefox' && b.engineMajor && v && v.firefox) {
      var f = v.firefox;
      if (f.esr_major && b.engineMajor === f.esr_major && b.engineMajor < f.latest_major) {
        facts.push({ label: ['fLatest'], value: f.latest, data: true });
        facts.push({ label: ['fLatestEsr'], value: f.esr, data: true });
        return { status: 'info', verdict: ['browserEsrMaybe', String(b.engineMajor)], facts: facts, fix: ['fixFirefoxAbout'] };
      }
      facts.push({ label: ['fLatest'], value: f.latest, data: true });
      var fdiff = f.latest_major - b.engineMajor;
      if (fdiff >= 2) return { status: 'risk', verdict: ['browserOld', 'Firefox'], facts: facts, fix: ['fixUpdate'] };
      if (fdiff === 1) return { status: 'warn', verdict: ['browserBehind', 'Firefox'], facts: facts, fix: ['fixUpdate'] };
      return { status: 'ok', verdict: ['browserOk', 'Firefox', shortVersion(b.version)], facts: facts };
    }

    if (b.family === 'chromium' || b.family === 'firefox') {
      return { status: 'error', verdict: ['browserVersionsError'], facts: facts };
    }
    return { status: 'info', verdict: ['browserUnknown'], facts: facts };
  }

  function runBrowser() {
    return detectBrowser().then(function (b) {
      var needsVersions = b.family === 'chromium' || b.family === 'firefox';
      if (!needsVersions) return evaluateBrowser(b, null);
      logOutbound(location.host || 'localhost', ['lpVersions'], []);
      return getJSON(CONFIG.versionsUrl).then(function (v) {
        return evaluateBrowser(b, v);
      }, function () {
        return evaluateBrowser(b, null);
      });
    }).then(function (result) {
      setCheck('browser', result);
    }, function () {
      setCheck('browser', { status: 'error', verdict: ['browserVersionsError'] });
    });
  }

  // ---------------------------------------------------------------------------
  // Check 2: connection (Cloudflare trace)
  // ---------------------------------------------------------------------------
  function parseTrace(text) {
    var out = {};
    String(text).split('\n').forEach(function (line) {
      var i = line.indexOf('=');
      if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
    return out;
  }

  function fetchTrace() {
    var urls = CONFIG.traceUrls.slice();
    function attempt() {
      var url = urls.shift();
      if (!url) return Promise.reject(new Error('trace_unavailable'));
      logOutbound(new URL(url).host, ['lpTrace'], []);
      return getText(url).then(function (text) {
        var data = parseTrace(text);
        if (!data.ip && !data.tls) throw new Error('trace_invalid');
        return data;
      }).catch(function () { return attempt(); });
    }
    return attempt();
  }

  function prettyTls(v) {
    var m = /^TLSv?(\d(?:\.\d)?)$/i.exec(v || '');
    return m ? 'TLS ' + m[1] : (v || '');
  }

  function evaluateConnection(trace) {
    var pageHttps = location.protocol === 'https:';
    var facts = [];
    var tls = trace.tls || '';
    facts.push({ label: ['fTls'], value: tls ? prettyTls(tls) : t('unknown'), data: !!tls });
    if (trace.sni) facts.push({ label: ['fEch'], value: trace.sni === 'encrypted' ? ['yes'] : ['no'] });
    if (trace.kex) {
      var pq = /mlkem|kyber/i.test(trace.kex);
      facts.push({ label: ['fPq'], value: (pq ? t('yes') : t('no')) + ' (' + trace.kex + ')' });
    }
    if (trace.http) facts.push({ label: ['fHttp'], value: trace.http.toUpperCase().replace('HTTP/', 'HTTP/'), data: true });
    if (trace.warp && trace.warp !== 'off') facts.push({ label: ['fWarp'], value: ['on'] });
    facts.push({ label: ['fPage'], value: pageHttps ? ['httpsOk'] : ['httpsNo'] });

    var note = trace.kex && /mlkem|kyber/i.test(trace.kex) ? ['connPqNote'] : (trace.sni ? ['connEchNote'] : null);

    if (!pageHttps && !isLocalHost()) return { status: 'risk', verdict: ['connPageHttp'], facts: facts, note: note };
    if (/^TLSv?1\.3$/i.test(tls)) return { status: 'ok', verdict: ['connOk'], facts: facts, note: note };
    if (/^TLSv?1\.2$/i.test(tls)) return { status: 'warn', verdict: ['connTls12'], facts: facts, note: note, fix: ['fixTlsInspect'] };
    if (tls) return { status: 'risk', verdict: ['connOld', prettyTls(tls)], facts: facts, note: note, fix: ['fixTlsInspect'] };
    return { status: 'info', verdict: ['connUnknown'], facts: facts, note: note };
  }

  function runConnection(tracePromise) {
    return tracePromise.then(function (trace) {
      setCheck('connection', evaluateConnection(trace));
    }, function () {
      setCheck('connection', {
        status: 'error',
        verdict: ['connError'],
        fix: ['fixConnError'],
        link: { href: 'https://www.cloudflare.com/ssl/encrypted-sni/', text: 'cfCheckLink' }
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Check 3: DNS leak (bash.ws, via this site's PHP endpoint)
  // ---------------------------------------------------------------------------
  function randomTestId() {
    // 9-digit numeric id, the format bash.ws expects.
    var buf = new Uint32Array(1);
    window.crypto.getRandomValues(buf);
    return String(100000000 + (buf[0] % 900000000));
  }

  function probe(url) {
    return new Promise(function (resolveFn) {
      var img = new Image();
      var done = false;
      function finish() { if (!done) { done = true; resolveFn(); } }
      img.onload = finish;
      img.onerror = finish;
      img.referrerPolicy = 'no-referrer';
      setTimeout(finish, 5000);
      img.src = url;
    });
  }

  function evaluateDns(result, ip) {
    var servers = Array.isArray(result.servers) ? result.servers : [];
    var facts = [{ label: ['fYourIp'], value: ip || t('unknown'), data: !!ip }];
    if (servers.length) {
      facts.push({
        label: ['fDnsServers'],
        list: servers.map(function (s) {
          return { data: s.ip, text: [s.asn, s.country_name].filter(Boolean).join(', ') };
        })
      });
    }
    if (!servers.length) return { status: 'info', verdict: ['dnsNone'], facts: facts };
    if (result.conclusion_code === 'no_leak') return { status: 'ok', verdict: ['dnsOk', servers.length], facts: facts, note: ['dnsNote'] };
    if (result.conclusion_code === 'leak') return { status: 'warn', verdict: ['dnsLeak'], facts: facts, note: ['dnsNote'], fix: ['fixDns'] };
    return { status: 'info', verdict: ['dnsDone', servers.length], facts: facts, note: ['dnsNote'] };
  }

  function runDns(tracePromise) {
    var id = randomTestId();
    var count = CONFIG.dnsProbeCount;
    var probes = [];
    var nonce = Date.now().toString(36);
    logOutbound('*.' + id + '.bash.ws', ['lpDnsProbes', count], ['1.' + id + '.bash.ws']);
    for (var i = 1; i <= count; i++) {
      probes.push(probe('https://' + i + '.' + id + '.bash.ws/img.png?n=' + nonce));
    }

    var ip = null;
    return Promise.all(probes)
      .then(function () { return withTimeout(tracePromise, 4000).then(function (tr) { ip = tr.ip || null; }, function () {}); })
      .then(function () { return sleep(1200); })
      .then(function () {
        var url = CONFIG.dnsResultUrl + '?id=' + id + (ip ? '&ip=' + encodeURIComponent(ip) : '');
        function ask() {
          logOutbound(location.host || 'localhost', ['lpDnsResult'], ip ? [id, ip] : [id]);
          return getJSON(url);
        }
        return ask().then(function (result) {
          if (result && Array.isArray(result.servers) && result.servers.length) return result;
          return sleep(2500).then(ask);
        });
      })
      .then(function (result) {
        setCheck('dns', evaluateDns(result || {}, ip));
      }, function (err) {
        setCheck('dns', { status: 'error', verdict: [err && err.status === 429 ? 'dnsRate' : 'dnsError'] });
      });
  }

  // ---------------------------------------------------------------------------
  // Check: WebRTC leak (STUN through Cloudflare, compared with the trace IP)
  // ---------------------------------------------------------------------------
  function isIPv6(ip) { return String(ip).indexOf(':') !== -1; }

  function isPrivateIp(ip) {
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|f[cd][0-9a-f]{2}:)/i.test(String(ip));
  }

  function parseCandidate(line) {
    var p = String(line).split(' ');
    var i = p.indexOf('typ');
    if (p.length < 8 || i < 0) return null;
    return { ip: p[4], type: p[i + 1] };
  }

  function rtcConstructor() {
    var PC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    return typeof PC === 'function' ? PC : null;
  }

  function gatherWebRtc(timeoutMs) {
    return new Promise(function (resolve) {
      var PC = rtcConstructor();
      var srflx = [];
      var host = [];
      var pc;
      var done = false;
      function finish() {
        if (done) return;
        done = true;
        try { pc.close(); } catch (e) { /* already closed */ }
        resolve({ supported: true, srflx: srflx, host: host });
      }
      if (!PC) { resolve({ supported: false, srflx: [], host: [] }); return; }
      try {
        pc = new PC({ iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }] });
      } catch (e) {
        resolve({ supported: false, srflx: [], host: [] });
        return;
      }
      pc.onicecandidate = function (event) {
        if (!event || !event.candidate) { finish(); return; }
        var c = parseCandidate(event.candidate.candidate);
        if (!c || !c.ip) return;
        if (c.type === 'srflx' && srflx.indexOf(c.ip) === -1) srflx.push(c.ip);
        if (c.type === 'host' && !/\.local$/i.test(c.ip) && host.indexOf(c.ip) === -1) host.push(c.ip);
      };
      try {
        pc.createDataChannel('pc-check');
        pc.createOffer().then(function (offer) { return pc.setLocalDescription(offer); }).catch(finish);
      } catch (e) {
        finish();
      }
      setTimeout(finish, timeoutMs);
    });
  }

  function evaluateWebRtc(result, traceIp) {
    var facts = [{ label: ['fYourIp'], value: traceIp || t('unknown'), data: !!traceIp }];
    if (result.srflx.length) facts.push({ label: ['fWebrtcPublic'], list: result.srflx.map(function (ip) { return { data: ip }; }) });
    if (result.host.length) facts.push({ label: ['fWebrtcLocal'], list: result.host.map(function (ip) { return { data: ip }; }) });

    if (!result.supported) return { status: 'ok', verdict: ['webrtcBlocked'], facts: facts };
    if (!result.srflx.length && !result.host.length) return { status: 'ok', verdict: ['webrtcNone'], facts: facts };
    if (result.srflx.length && !traceIp) return { status: 'info', verdict: ['webrtcNoCompare'], facts: facts, note: ['webrtcNote'] };

    // Compare per address family: an IPv4 and an IPv6 address of the same visitor are not a leak.
    var leaks = result.srflx.filter(function (ip) {
      return traceIp && isIPv6(ip) === isIPv6(traceIp) && ip.toLowerCase() !== traceIp.toLowerCase();
    });
    if (leaks.length) return { status: 'risk', verdict: ['webrtcLeak'], facts: facts, note: ['webrtcNote'], fix: ['fixWebrtc'] };
    if (result.host.some(isPrivateIp)) return { status: 'warn', verdict: ['webrtcLocal'], facts: facts, fix: ['fixWebrtcLocal'] };
    var comparable = result.srflx.some(function (ip) { return isIPv6(ip) === isIPv6(traceIp); });
    if (result.srflx.length && !comparable) return { status: 'ok', verdict: ['webrtcOtherFamily'], facts: facts, note: ['webrtcNote'] };
    return { status: 'ok', verdict: ['webrtcOk'], facts: facts, note: ['webrtcNote'] };
  }

  function runWebRtc(tracePromise) {
    if (rtcConstructor()) logOutbound('stun.cloudflare.com', ['lpStun'], []);
    return gatherWebRtc(3000).then(function (result) {
      return withTimeout(tracePromise, 4000).then(function (tr) { return tr.ip || null; }, function () { return null; })
        .then(function (ip) { setCheck('webrtc', evaluateWebRtc(result, ip)); });
    }, function () {
      setCheck('webrtc', { status: 'error', verdict: ['webrtcNone'] });
    });
  }

  // ---------------------------------------------------------------------------
  // Check: trackability (everything stays on the device)
  // ---------------------------------------------------------------------------
  function shortHash(text) {
    var h = 0x811c9dc5;
    for (var i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return ('0000000' + h.toString(16)).slice(-8);
  }

  function canvasData() {
    try {
      var c = document.createElement('canvas');
      c.width = 220; c.height = 40;
      var g = c.getContext('2d');
      g.textBaseline = 'top';
      g.font = '16px Arial';
      g.fillStyle = '#f60'; g.fillRect(0, 0, 60, 20);
      g.fillStyle = '#069'; g.fillText('PC Check \u2713 1.0', 4, 8);
      return c.toDataURL();
    } catch (e) { return null; }
  }

  function gpuName() {
    try {
      var gl = document.createElement('canvas').getContext('webgl');
      var ext = gl && gl.getExtension('WEBGL_debug_renderer_info');
      return ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : null;
    } catch (e) { return null; }
  }

  function readSurface(b) {
    var tz = null;
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch (e) { /* old browser */ }
    var canvas = canvasData();
    return {
      browser: b && b.name ? b.name + (b.version ? ' ' + shortVersion(b.version) : '') : null,
      os: (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || null,
      language: navigator.language || null,
      timeZone: tz,
      screen: window.screen ? screen.width + ' × ' + screen.height : null,
      pixelRatio: window.devicePixelRatio || null,
      cores: navigator.hardwareConcurrency || null,
      memoryGb: navigator.deviceMemory || null,
      gpu: gpuName(),
      touch: (navigator.maxTouchPoints || 0) > 0,
      canvasHash: canvas ? shortHash(canvas) : null
    };
  }

  function detectProtections(b) {
    var bait = document.getElementById('bait');
    var first = canvasData();
    var second = canvasData();
    return sleep(100).then(function () {
      var blocked = !bait || !document.body.contains(bait) || bait.offsetHeight === 0 ||
        window.getComputedStyle(bait).display === 'none' || window.getComputedStyle(bait).visibility === 'hidden';
      return {
        gpc: navigator.globalPrivacyControl === true,
        dnt: navigator.doNotTrack === '1' || window.doNotTrack === '1',
        blocker: blocked,
        canvasRandomised: !!(first && second && first !== second),
        webkitItp: !!b && (b.family === 'ios' || b.family === 'safari')
      };
    });
  }

  function evaluateTracking(surface, prot) {
    var s = surface || {};
    var facts = [];
    function add(label, value, data) { if (value !== null && value !== undefined && value !== '') facts.push({ label: [label], value: String(value), data: !!data }); }
    add('fBrowser', s.browser);
    add('fOs', s.os);
    add('fLanguage', s.language);
    add('fTimeZone', s.timeZone);
    add('fScreen', s.screen ? s.screen + (s.pixelRatio ? ' @' + s.pixelRatio + 'x' : '') : null);
    add('fCores', s.cores, true);
    add('fMemory', s.memoryGb ? s.memoryGb + ' GB' : null, true);
    add('fGpu', s.gpu);
    if (s.touch !== undefined) add('fTouch', t(s.touch ? 'vYes' : 'vNo'));
    add('fCanvas', prot.canvasRandomised ? t('vRandomised') : s.canvasHash, !prot.canvasRandomised);
    add('fGpc', t(prot.gpc ? 'vOn' : 'vOff'));
    add('fDnt', t(prot.dnt ? 'vOn' : 'vOff'));
    add('fBlocker', t(prot.blocker ? 'vDetected' : 'vNotDetected'));
    if (prot.webkitItp) add('fItp', t('vOn'));

    // Do Not Track is shown but not counted: most sites ignore it.
    var count = [prot.gpc, prot.blocker, prot.canvasRandomised, prot.webkitItp].filter(Boolean).length;
    if (count >= 2) return { status: 'ok', verdict: ['trackLow', count], facts: facts, note: ['trackNote'] };
    if (count === 1) return { status: 'info', verdict: ['trackMedium'], facts: facts, note: ['trackNote'], fix: ['fixTrack'] };
    return { status: 'warn', verdict: ['trackHigh'], facts: facts, note: ['trackNote'], fix: ['fixTrack'] };
  }

  function runTracking() {
    return detectBrowser().catch(function () { return null; }).then(function (b) {
      return detectProtections(b).then(function (prot) { setCheck('tracking', evaluateTracking(readSurface(b), prot)); });
    }).catch(function () {
      setCheck('tracking', { status: 'error', verdict: ['trackHigh'] });
    });
  }

  // ---------------------------------------------------------------------------
  // Speed test (Cloudflare speed endpoints; only from its own GO button)
  // ---------------------------------------------------------------------------
  var SPEED = {
    base: 'https://speed.cloudflare.com/',
    downSizes: [100000, 1000000, 10000000, 25000000],
    upSizes: [1000000, 5000000, 10000000],
    downBudgetMs: 8000,
    upBudgetMs: 6000,
    pingBudgetMs: 4000,
    requestTimeoutMs: 10000,
    pings: 10
  };

  function now() { return (window.performance && performance.now) ? performance.now() : Date.now(); }

  // One request with its own 10 s timeout, also aborted by the outer Cancel signal.
  function speedFetch(url, opts, outer) {
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, SPEED.requestTimeoutMs);
    function onOuter() { controller.abort(); }
    if (outer) outer.addEventListener('abort', onOuter);
    var t0 = now();
    return fetch(url, Object.assign({ cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', signal: controller.signal }, opts))
      .then(function (res) {
        if (!res.ok) throw new Error('http_' + res.status);
        return res.arrayBuffer().then(function (buf) { return { ms: Math.max(now() - t0, 1), bytes: buf.byteLength, res: res }; });
      })
      .then(function (out) { clearTimeout(timer); if (outer) outer.removeEventListener('abort', onOuter); return out; },
        function (err) { clearTimeout(timer); if (outer) outer.removeEventListener('abort', onOuter); throw err; });
  }

  function median(xs) {
    var s = xs.slice().sort(function (a, b) { return a - b; });
    return s.length ? s[Math.floor((s.length - 1) / 2)] : null;
  }
  function p90(xs) {
    var s = xs.slice().sort(function (a, b) { return a - b; });
    return s.length ? s[Math.max(Math.ceil(0.9 * s.length) - 1, 0)] : null;
  }
  function round1(n) { return n === null ? null : Math.round(n * 10) / 10; }

  function measureSpeed(onProgress, signal) {
    var out = { pingMs: null, jitterMs: null, downMbps: null, upMbps: null, colo: null, partial: false };
    function aborted() { return signal && signal.aborted; }
    function stop(err) { if (aborted()) throw err; out.partial = true; }

    var pings = [];
    var pingStart = now();
    onProgress('ping', null);
    function ping(i) {
      if (i >= SPEED.pings || aborted() || (i > 0 && now() - pingStart > SPEED.pingBudgetMs)) return Promise.resolve();
      return speedFetch(SPEED.base + '__down?bytes=0', {}, signal).then(function (r) {
        if (!out.colo) out.colo = r.res.headers.get('cf-meta-colo');
        pings.push(r.ms);
        onProgress('ping', r.ms);
        return ping(i + 1);
      });
    }

    function phase(sizes, budget, send) {
      var samples = [];
      var start = now();
      onProgress(send.phaseName, null);
      function step(i) {
        if (i >= sizes.length || now() - start > budget || aborted()) return Promise.resolve(samples);
        return send(sizes[i]).then(function (r) {
          var mbps = (sizes[i] * 8) / (r.ms / 1000) / 1e6;
          samples.push(mbps);
          onProgress(send.phaseName, mbps);
          return step(i + 1);
        }, function (err) { stop(err); return samples; });
      }
      return step(0);
    }
    function down(size) { return speedFetch(SPEED.base + '__down?bytes=' + size, {}, signal); }
    down.phaseName = 'download';
    function up(size) { return speedFetch(SPEED.base + '__up', { method: 'POST', body: new Uint8Array(size) }, signal); }
    up.phaseName = 'upload';

    return ping(0).catch(function (err) { stop(err); })
      .then(function () {
        out.pingMs = round1(median(pings));
        if (pings.length > 1) {
          var diffs = 0;
          for (var i = 1; i < pings.length; i++) diffs += Math.abs(pings[i] - pings[i - 1]);
          out.jitterMs = round1(diffs / (pings.length - 1));
        }
        return phase(SPEED.downSizes, SPEED.downBudgetMs, down);
      })
      .then(function (s) { out.downMbps = round1(p90(s)); return phase(SPEED.upSizes, SPEED.upBudgetMs, up); })
      .then(function (s) { out.upMbps = round1(p90(s)); return out; });
  }

  function evaluateSpeed(r) {
    if (!r || r.downMbps === null || r.downMbps === undefined) return { status: 'error', verdict: ['speedFail'], fix: ['fixSpeed'] };
    var facts = [{ label: ['fDown'], value: r.downMbps + ' Mbps', data: true }];
    if (r.upMbps !== null) facts.push({ label: ['fUp'], value: r.upMbps + ' Mbps', data: true });
    if (r.pingMs !== null) facts.push({ label: ['fPing'], value: r.pingMs + ' ms', data: true });
    if (r.jitterMs !== null) facts.push({ label: ['fJitter'], value: r.jitterMs + ' ms', data: true });
    if (r.colo) facts.push({ label: ['fColo'], value: r.colo, data: true });
    var note = r.partial ? ['speedPartial'] : (r.pingMs > 100 ? ['speedPingHigh'] : ['speedNote']);
    if (r.downMbps >= 25) return { status: 'ok', verdict: ['speedFast', r.downMbps], facts: facts, note: note };
    if (r.downMbps >= 10) return { status: 'info', verdict: ['speedOk', r.downMbps], facts: facts, note: note, fix: ['fixSpeed'] };
    return { status: 'warn', verdict: ['speedSlow', r.downMbps], facts: facts, note: note, fix: ['fixSpeed'] };
  }

  var gauge = null;

  function renderSpeedButtons() {
    var go = $('#speed-go');
    var cancel = $('#speed-cancel');
    if (!go) return;
    var again = !!state.speed.result || state.checks.speed.status !== 'idle';
    go.disabled = state.speed.running;
    go.textContent = t(again ? 'speedAgain' : 'speedGo');
    go.classList.toggle('again', again && !state.speed.running);
    // The 'again' button sits under the gauge, so it must leave the gauge box.
    var home = again ? $('.speed-actions') : $('#gauge');
    if (home && go.parentNode !== home) home.insertBefore(go, home.firstChild);
    cancel.hidden = !state.speed.running;
  }

  function runSpeed() {
    if (state.speed.running) return;
    if (typeof AbortController !== 'function' || typeof fetch !== 'function') {
      setCheck('speed', { status: 'error', verdict: ['speedOld'], fix: ['fixUpdate'] });
      renderSpeedButtons();
      return;
    }
    var controller = new AbortController();
    state.speed = { running: true, result: null, controller: controller };
    setCheck('speed', { status: 'running' });
    renderSpeedButtons();
    if (gauge) gauge.reset();
    var logged = {};
    measureSpeed(function (phase, value) {
      if (!logged[phase]) { logged[phase] = true; logOutbound('speed.cloudflare.com', ['lpSpeed', phase], ['test bytes only']); }
      if (gauge) { gauge.phase(phase); if (phase !== 'ping' && value !== null) gauge.set(value); }
    }, controller.signal).then(function (result) {
      state.speed.result = result;
      if (gauge && result.downMbps !== null) gauge.set(result.downMbps);
      setCheck('speed', evaluateSpeed(result));
    }, function () {
      setCheck('speed', controller.signal.aborted ? { status: 'info', verdict: ['speedCancelled'] } : { status: 'error', verdict: ['speedFail'], fix: ['fixSpeed'] });
    }).then(function () {
      state.speed.running = false;
      if (gauge) gauge.phase('done');
      renderSpeedButtons();
    });
  }

  function cancelSpeed() {
    if (state.speed.running && state.speed.controller) state.speed.controller.abort();
  }

  // ---------------------------------------------------------------------------
  // System report: Windows reports read and judged on this device only.
  // Nothing here touches the network, so nothing is added to the outbound log.
  // ---------------------------------------------------------------------------
  var SYS_KINDS = ['reliability', 'battery', 'msinfo'];
  var SYS_MAX_BYTES = 40 * 1024 * 1024;
  var SYS_MSINFO_HEAD_BYTES = 4 * 1024 * 1024; // about 2 million UTF-16 characters: System Summary and Problem Devices come first
  var SYS_PARSER = { reliability: 'parseReliability', battery: 'parseBattery', msinfo: 'parseMsinfo' };
  var SYS_WRONG = { reliability: 'sysNotReliability', battery: 'sysNotBattery', msinfo: 'sysNotMsinfo' };
  var SYS_STEP_NO = { reliability: 1, battery: 2, msinfo: 3 };
  var SYS_OS_NAMES = { windows: 'Windows', mac: 'Mac', linux: 'Linux' };
  var SYS_GLYPH = { windows: 'os-windows', mac: 'os-mac', linux: 'os-linux', android: 'os-phone', ios: 'os-phone', other: 'os-windows' };
  var SEVERITY_ORDER = ['risk', 'warn', 'info'];
  var sysReads = {};

  function detectOs() {
    var ua = navigator.userAgent || '';
    var uad = navigator.userAgentData;
    var family;
    if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) family = 'ios';
    else if (/Android/.test(ua)) family = 'android';
    else if (/Windows/.test(ua)) family = 'windows';
    else if (/Mac OS X|Macintosh/.test(ua)) family = 'mac';
    else if (/CrOS/.test(ua)) family = 'other';
    else if (/Linux|X11/.test(ua)) family = 'linux';
    else family = 'other';
    var labels = { windows: 'Windows', mac: 'macOS', linux: 'Linux', android: 'Android', ios: 'iPhone or iPad', other: 'this device' };
    var info = { family: family, label: labels[family] };
    if (family !== 'windows' || !uad || uad.platform !== 'Windows' || typeof uad.getHighEntropyValues !== 'function') return Promise.resolve(info);
    // Windows 11 reports platformVersion 13 or higher; Windows 10 reports 1 to 10.
    return uad.getHighEntropyValues(['platformVersion']).then(function (h) {
      var major = parseInt(String((h && h.platformVersion) || ''), 10);
      if (major >= 13) info.label = 'Windows 11';
      else if (major >= 1) info.label = 'Windows 10';
      return info;
    }).catch(function () { return info; });
  }

  function svgUse(id, cls) {
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    if (cls) svg.setAttribute('class', cls);
    var use = document.createElementNS(ns, 'use');
    use.setAttribute('href', '#' + id);
    svg.appendChild(use);
    return svg;
  }

  function readBuffer(blob) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(reader.result); };
      reader.onerror = function () { reject(reader.error); };
      reader.readAsArrayBuffer(blob);
    });
  }

  // Which report a text looks like, to point a file dropped in the wrong box to the right step.
  function sniffKind(text) {
    var head = String(text).slice(0, 5000);
    if (/<RelMonReport[\s>]/.test(head)) return 'reliability';
    if (/schemas\.microsoft\.com\/battery|<title>\s*Battery report/i.test(head)) return 'battery';
    if (/^\s*\[(System Summary|Resumo do Sistema)\]\s*$/m.test(head)) return 'msinfo';
    return null;
  }

  function isoDate(d) { return d && !isNaN(d.getTime()) ? d.toISOString().slice(0, 10) : null; }

  function setSysStep(kind, status, msg) {
    state.sys.steps[kind] = status ? { status: status, msg: msg } : null;
    renderSysStep(kind);
  }

  function loadSysFile(kind, file) {
    if (!file) return Promise.resolve();
    state.sys.files[kind] = null;
    state.sys.evaluation = null;
    state.sys.status = null;
    renderSysResults();
    if (!window.PCSys) { setSysStep(kind, 'error', ['sysReadError']); return Promise.resolve(); }
    if (file.size > SYS_MAX_BYTES) { setSysStep(kind, 'error', ['sysTooBig']); return Promise.resolve(); }
    setSysStep(kind, 'reading', ['sysReading']);
    var blob = kind === 'msinfo' ? file.slice(0, SYS_MSINFO_HEAD_BYTES) : file;
    var job = readBuffer(blob).then(function (buffer) {
      var text = window.PCSys.decode(buffer);
      var parsed = window.PCSys[SYS_PARSER[kind]](text);
      if (parsed && parsed.error) {
        var other = sniffKind(text);
        var msg = t(SYS_WRONG[kind]) + (other && other !== kind ? t('sysLooksLike', SYS_STEP_NO[other]) : '');
        setSysStep(kind, 'error', msg);
      } else if (parsed && parsed.unsupportedLanguage) {
        setSysStep(kind, 'error', ['sysLanguage']);
      } else {
        state.sys.files[kind] = parsed;
        if (kind === 'reliability') setSysStep(kind, 'ok', ['sysReadReliability', isoDate(parsed.generated), parsed.events.length]);
        else setSysStep(kind, 'ok', [kind === 'battery' ? 'sysReadBattery' : 'sysReadMsinfo']);
      }
    }).catch(function () {
      setSysStep(kind, 'error', ['sysReadError']);
    });
    sysReads[kind] = job;
    return job;
  }

  function analyzeSys() {
    var pending = SYS_KINDS.map(function (k) { return sysReads[k] || Promise.resolve(); });
    return Promise.all(pending).then(function () {
      var f = state.sys.files;
      if (!f.reliability && !f.battery && !f.msinfo) {
        state.sys.evaluation = null;
        state.sys.status = ['sysNeedFile'];
      } else {
        state.sys.evaluation = window.PCSys.evaluateWindows({ reliability: f.reliability, battery: f.battery, msinfo: f.msinfo }, new Date());
        state.sys.status = f.reliability ? ['sysDone'] : ['sysNoCrash'];
      }
      renderSysResults();
      var heading = $('#sys-results h3');
      if (state.sys.evaluation && heading) heading.focus();
    });
  }

  function selectSysOs(os) {
    state.sys.selected = os;
    renderSysOs();
  }

  function renderSysBanner() {
    var banner = $('#sys-banner');
    if (!banner || !state.sys.os) return;
    banner.textContent = '';
    banner.appendChild(svgUse(SYS_GLYPH[state.sys.os.family] || 'os-windows', 'sys-glyph'));
    banner.appendChild(el('span', null, t('sysBanner', state.sys.os.family, state.sys.os.label)));
  }

  function renderSysOs() {
    if (!$('#system')) return;
    $all('.sys-os-btn').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-os') === state.sys.selected));
    });
    var windows = state.sys.selected === 'windows';
    $('#sys-steps').hidden = !windows;
    var soon = $('#sys-soon');
    soon.hidden = windows;
    soon.textContent = windows ? '' : t('sysSoon', SYS_OS_NAMES[state.sys.selected]);
  }

  function renderSysStep(kind) {
    var root = document.getElementById('sys-step-' + kind);
    if (!root) return;
    var step = state.sys.steps[kind];
    root.setAttribute('data-state', step ? step.status : 'empty');
    $('[data-role="msg"]', root).textContent = step ? resolve(step.msg) : '';
  }

  function bandOf(score) { return score >= 80 ? 'ok' : (score >= 50 ? 'warn' : 'risk'); }

  function renderSysResults() {
    var root = $('#sys-results');
    if (!root) return;
    $('#sys-status').textContent = state.sys.status ? resolve(state.sys.status) : '';
    root.textContent = '';
    var e = state.sys.evaluation;
    root.hidden = !e;
    if (!e) return;

    var band = bandOf(e.score);
    var top = el('div', 'sys-summary');
    var ring = el('div', 'sys-ring');
    ring.setAttribute('data-band', band);
    // A CSS custom property set through CSSOM: allowed by the strict CSP (no style attribute in markup).
    ring.style.setProperty('--score', String(e.score));
    var num = el('span', 'sys-score', String(e.score));
    num.id = 'sys-score';
    ring.appendChild(num);
    ring.appendChild(el('span', 'sys-score-of', '/ 100'));
    top.appendChild(ring);
    var words = el('div', 'sys-summary-text');
    var h = el('h3', null, t('sysScoreTitle'));
    h.tabIndex = -1;
    words.appendChild(h);
    words.appendChild(el('p', 'sys-verdict', t(band === 'ok' ? 'sysVerdictOk' : (band === 'warn' ? 'sysVerdictWarn' : 'sysVerdictRisk'))));
    var date = isoDate(e.reportDate);
    words.appendChild(el('p', 'sys-date', date ? t('sysReportFrom', date) : t('sysLocalOnly')));
    top.appendChild(words);
    root.appendChild(top);

    root.appendChild(el('h4', 'sys-subtitle', t('sysFindingsTitle')));
    var findings = e.findings.slice().sort(function (a, b) {
      return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    });
    if (!findings.length) {
      root.appendChild(el('p', 'sys-none', t('sysNoFindings')));
    } else {
      var list = el('ul', 'sys-findings');
      findings.forEach(function (f) {
        var li = el('li', 'sys-finding');
        li.setAttribute('data-severity', f.severity);
        li.appendChild(svgUse('i-' + f.severity, 'sys-mark'));
        var body = el('div', 'sys-finding-body');
        var title = el('p', 'sys-finding-title');
        title.appendChild(el('span', 'sys-sev', t('sev_' + f.severity)));
        title.appendChild(el('span', null, f.title));
        body.appendChild(title);
        if (f.detail) body.appendChild(el('p', 'sys-detail', f.detail));
        if (f.fix) {
          var fix = el('p', 'sys-fix');
          fix.appendChild(el('strong', null, t('sysFix')));
          fix.appendChild(document.createTextNode(f.fix));
          body.appendChild(fix);
        }
        li.appendChild(body);
        list.appendChild(li);
      });
      root.appendChild(list);
    }

    if (e.facts.length) {
      root.appendChild(el('h4', 'sys-subtitle', t('sysFactsTitle')));
      var tiles = el('dl', 'sys-tiles');
      e.facts.forEach(function (f) {
        var tile = el('div', 'sys-tile');
        tile.appendChild(el('dt', null, f.label));
        tile.appendChild(el('dd', null, f.value));
        tiles.appendChild(tile);
      });
      root.appendChild(tiles);
    }
  }

  function renderSys() {
    if (!$('#system')) return;
    renderSysBanner();
    renderSysOs();
    SYS_KINDS.forEach(renderSysStep);
    renderSysResults();
  }

  function copyText(button) {
    var code = document.getElementById(button.getAttribute('aria-controls'));
    if (!code) return;
    var done = function () {
      button.textContent = t('sysCopied');
      setTimeout(function () { button.textContent = t('sysCopy'); }, 2000);
    };
    var selectIt = function () {
      var range = document.createRange();
      range.selectNodeContents(code);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(code.textContent).then(done, selectIt);
    } else {
      selectIt();
    }
  }

  function initSys() {
    if (!$('#system')) return;
    $all('.sys-os-btn').forEach(function (b) {
      b.addEventListener('click', function () { selectSysOs(b.getAttribute('data-os')); });
    });
    SYS_KINDS.forEach(function (kind) {
      var input = document.getElementById('sys-file-' + kind);
      var zone = $('#sys-step-' + kind + ' .sys-drop');
      input.addEventListener('change', function () {
        var file = input.files && input.files[0];
        loadSysFile(kind, file).then(function () { input.value = ''; });
      });
      zone.addEventListener('dragover', function (ev) { ev.preventDefault(); zone.classList.add('is-over'); });
      zone.addEventListener('dragleave', function () { zone.classList.remove('is-over'); });
      zone.addEventListener('drop', function (ev) {
        ev.preventDefault();
        zone.classList.remove('is-over');
        var files = ev.dataTransfer && ev.dataTransfer.files;
        if (files && files[0]) loadSysFile(kind, files[0]);
      });
    });
    // A file dropped outside the boxes would make the browser open it and leave the page.
    ['dragover', 'drop'].forEach(function (type) {
      window.addEventListener(type, function (ev) {
        var types = ev.dataTransfer && ev.dataTransfer.types;
        if (types && Array.prototype.indexOf.call(types, 'Files') !== -1) ev.preventDefault();
      });
    });
    $all('.sys-copy').forEach(function (b) { b.addEventListener('click', function () { copyText(b); }); });
    $('#sys-analyze').addEventListener('click', analyzeSys);

    detectOs().then(function (os) {
      state.sys.os = os;
      if (os.family === 'mac' || os.family === 'linux') state.sys.selected = os.family;
      renderSys();
    });
  }

  // ---------------------------------------------------------------------------
  // PDF report: built from the current results only when asked, then printed
  // ---------------------------------------------------------------------------
  var REPORT_ORDER = ['browser', 'connection', 'dns', 'webrtc', 'tracking', 'password', 'speed'];

  function hasResult(id) {
    var s = state.checks[id] && state.checks[id].status;
    return !!s && s !== 'idle' && s !== 'running';
  }

  function renderPdfButton() {
    var show = REPORT_ORDER.some(hasResult);
    if ($('#pdf')) $('#pdf').hidden = !show;
    if ($('#pdf-hint')) $('#pdf-hint').hidden = !show;
  }

  function buildReport() {
    var root = $('#report');
    root.textContent = '';
    var head = el('div', 'report-head');
    var logo = el('img');
    logo.src = 'assets/emblem.png';
    logo.alt = 'CyberSecInfo';
    head.appendChild(logo);
    var titles = el('div');
    titles.appendChild(el('h1', null, t('reportTitle')));
    titles.appendChild(el('p', 'report-meta', t('reportGenerated', new Date().toLocaleString('en-IE')) + ' · ' + location.href.split('#')[0].split('?')[0]));
    head.appendChild(titles);
    root.appendChild(head);

    REPORT_ORDER.filter(hasResult).forEach(function (id) {
      var data = state.checks[id];
      var box = el('section', 'report-check');
      box.setAttribute('data-status', data.status);
      var h = el('h2');
      h.appendChild(el('span', null, ($('#check-' + id + ' h3') || {}).textContent || id));
      h.appendChild(el('span', 'report-pill', t('st_' + data.status)));
      box.appendChild(h);
      if (data.verdict) box.appendChild(el('p', null, resolve(data.verdict)));
      if (id === 'password') {
        if (state.hash) box.appendChild(el('p', 'report-fix', t('reportPrefix', state.hash.prefix)));
      } else if (data.facts.length) {
        var dl = el('dl');
        data.facts.forEach(function (f) {
          dl.appendChild(el('dt', null, resolve(f.label)));
          dl.appendChild(el('dd', null, f.list ? f.list.map(function (i) { return [i.data, i.text].filter(Boolean).join(' '); }).join(', ') : resolve(f.value)));
        });
        box.appendChild(dl);
      }
      if (data.fix) box.appendChild(el('p', 'report-fix', resolve(data.fix)));
      root.appendChild(box);
    });

    if (state.ledger.length) {
      var lg = el('section', 'report-check');
      var lh = el('h2');
      lh.appendChild(el('span', null, t('ledgerTitle')));
      lg.appendChild(lh);
      var ol = el('ol', 'report-ledger');
      state.ledger.forEach(function (item) {
        ol.appendChild(el('li', null, formatTime(item.ts) + ' · ' + item.host + ' · ' + resolve(item.purpose) +
          (item.data.length ? ' · ' + t('ledgerSent') + ' ' + item.data.join(', ') : '')));
      });
      lg.appendChild(ol);
      root.appendChild(lg);
    }
    root.appendChild(el('p', 'report-foot', t('reportFoot')));
  }

  function printReport() {
    buildReport();
    window.print();
  }

  // ---------------------------------------------------------------------------
  // Check 4: password (Pwned Passwords range API, k-anonymity)
  // ---------------------------------------------------------------------------
  function sha1Hex(text) {
    var bytes = new TextEncoder().encode(text);
    return window.crypto.subtle.digest('SHA-1', bytes).then(function (buf) {
      var view = new Uint8Array(buf);
      var hex = '';
      for (var i = 0; i < view.length; i++) hex += ('0' + view[i].toString(16)).slice(-2);
      return hex.toUpperCase();
    });
  }

  function countInRange(body, suffix) {
    var lines = String(body).split('\n');
    var returned = 0;
    var found = 0;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      var sep = line.indexOf(':');
      if (sep !== 35) continue;
      var count = parseInt(line.slice(sep + 1), 10) || 0;
      if (count > 0) returned++;
      if (line.slice(0, sep).toUpperCase() === suffix) found = count;
    }
    return { found: found, returned: returned };
  }

  function fetchRange(prefix) {
    var url = CONFIG.hibpRangeUrl + prefix;
    // Padding hides the real size of the answer. If the extra header is refused, fall back to a plain request.
    return getText(url, { 'Add-Padding': 'true' }).catch(function () { return getText(url); });
  }

  function runPassword(password) {
    state.pwError = null;
    if (!password) { state.pwError = 'pwEmpty'; renderPasswordForm(); $('#pw').focus(); return Promise.resolve(); }
    if (!window.crypto || !window.crypto.subtle || typeof TextEncoder !== 'function') {
      setCheck('password', { status: 'error', verdict: ['pwNoCrypto'] });
      return Promise.resolve();
    }
    state.pwBusy = true;
    state.hash = null;
    renderPasswordForm();
    setCheck('password', { status: 'running' });

    return sha1Hex(password).then(function (hash) {
      var prefix = hash.slice(0, 5);
      var suffix = hash.slice(5);
      logOutbound('api.pwnedpasswords.com', ['lpHibp'], [prefix]);
      return fetchRange(prefix).then(function (body) {
        var r = countInRange(body, suffix);
        state.hash = { prefix: prefix, returned: r.returned };
        if (r.found > 0) {
          setCheck('password', { status: 'risk', verdict: ['pwFound', formatNumber(r.found)], fix: ['fixPw'] });
        } else {
          setCheck('password', { status: 'ok', verdict: ['pwNotFound'], note: ['notePwOk'] });
        }
      });
    }).catch(function () {
      state.hash = null;
      setCheck('password', { status: 'error', verdict: ['pwError'] });
    }).then(function () {
      state.pwBusy = false;
      renderPasswordForm();
    });
  }

  // ---------------------------------------------------------------------------
  // Orchestration
  // ---------------------------------------------------------------------------
  function runAll() {
    if (state.running) return;
    state.running = true;
    state.summaryCounts = null;
    ['browser', 'connection', 'dns', 'webrtc', 'tracking'].forEach(function (id) { setCheck(id, { status: 'running' }); });
    renderRunButton();

    var tracePromise = fetchTrace();
    tracePromise.catch(function () {});

    var tasks = [runBrowser(), runConnection(tracePromise), runDns(tracePromise), runWebRtc(tracePromise), runTracking()];
    Promise.all(tasks.map(function (p) { return p.catch(function () {}); })).then(function () {
      state.running = false;
      state.ranOnce = true;
      var counts = { ok: 0, warn: 0, risk: 0, info: 0, error: 0 };
      ['browser', 'connection', 'dns', 'webrtc', 'tracking'].forEach(function (id) {
        var s = state.checks[id].status;
        if (Object.prototype.hasOwnProperty.call(counts, s)) counts[s]++;
      });
      state.summaryCounts = counts;
      renderRunButton();
    });
  }

  function detectLang() {
    // cybersecinfo.com is English-only. The PT texts stay in STR so the page can be bilingual again later.
    return 'en';
  }

  function setLang(lang) {
    state.lang = lang;
    try { window.localStorage.setItem('bsc-lang', lang); } catch (e) { /* ignore */ }
    renderAll();
  }

  function init() {
    document.documentElement.classList.add('js');
    state.lang = detectLang();

    $('#run').addEventListener('click', runAll);
    $('#speed-go').addEventListener('click', runSpeed);
    try {
      if (window.PCGauge && $('#gauge')) gauge = window.PCGauge.create($('#gauge'));
    } catch (e) {
      gauge = null; // the speed test still works, just without the dial
    }
    $('#speed-cancel').addEventListener('click', cancelSpeed);
    $('#pdf').addEventListener('click', printReport);
    window.addEventListener('beforeprint', buildReport);

    $all('.lang button').forEach(function (b) {
      b.addEventListener('click', function () { setLang(b.getAttribute('data-lang')); });
    });

    $('#pw-toggle').addEventListener('click', function () {
      state.pwVisible = !state.pwVisible;
      renderPasswordForm();
    });

    $('#pw').addEventListener('input', function () {
      if (state.pwError) { state.pwError = null; renderPasswordForm(); }
    });

    $('#pw-form').addEventListener('submit', function (event) {
      event.preventDefault();
      var input = $('#pw');
      var value = input.value;
      input.value = '';
      state.pwVisible = false;
      runPassword(value);
      value = null;
    });

    initSys();
    renderAll();
  }

  // Exposed only for automated tests; harmless in production.
  window.__bsc = {
    compareVersions: compareVersions,
    parseTrace: parseTrace,
    countInRange: countInRange,
    evaluateBrowser: evaluateBrowser,
    evaluateConnection: evaluateConnection,
    evaluateDns: evaluateDns,
    evaluateWebRtc: evaluateWebRtc,
    evaluateTracking: evaluateTracking,
    evaluateSpeed: evaluateSpeed,
    sha1Hex: sha1Hex,
    shortVersion: shortVersion,
    detectOs: detectOs
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
