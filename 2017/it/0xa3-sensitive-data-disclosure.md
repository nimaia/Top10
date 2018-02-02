# A3:2017 Esposizione di Dati Sensibili

| Agenti di minaccia/Vettori di attacco | Problematiche di sicurezza           | Impatto               |
| -- | -- | -- |
| Livello di accesso : Sfruttabilità 2 | Diffusione 2 : Individuazione 3 | Tecnico 3 : Business ? |
| Piuttosto che tentare una decodifica degli algoritmi crittografici, gli attaccanti tendono a rubare le chiavi crittografiche, eseguire attacchi man-in-the-middle, o intercettare dati non criptati sul server, durante il transito o direttamente dal client dell'utente (i.e. browser). Di solito questo richiede un attacco manuale. Anche un database criptato, una volta trafugato, può essere decodificato con successo mediante un attacco di forza bruta utilizzando l'enorme potenza di calcolo delle attuali GPU. | Negli ultimi anni questo è stato il tipo di attacco più diffuso ed efficace. L'errore più comune rimane quello di non criptare affatto i dati sensibili. Oppure,  quando questo viene fatto, è diffuso l'utilizzo di sistemi inappropriati per la generazione e la gestione delle chiavi, l'utilizzo di protocolli o algoritmi di hashing deboli, in particolare quelli utilizzati per il salvataggio delle password. Le vulnerabilità lato server sono facili da individuare nei sistemi di trasmissione dei dati, mentre è difficile per quelle legate al salvataggio dei dati. | Un fallimento nelle misure di protezione di solito compromette tutti i dati che altrimenti sarebbero dovuti essere protetti. Tipicamente: cartelle cliniche, credenziali, dati personali e carte di credito che spesso richiedono una protezione specifica anche in applicazione delle leggi vigenti, come il GDPR Europeo o altre leggi locali. |

## L'applicazione è vulnerabile ?

La prima cosa è determinare le esigenze di protezione dei dati in transito e salvati. Per esempio richiedono una protezione extra: password, numeri di carta di credito, cartelle cliniche, informazioni personali e secreti industriali, particolarmente se tali dati ricadono sotto la giurisdizione delle leggi sulla privacy come il General Data Protection Regulation (GDPR) Europeo o dei regolamenti sui dati finanziari come il PCI Data Security Standard (PCI DSS). Per tutti questi dati verificare se:

* Vengono trasmessi in chiaro ? Questo riguarda procolli quali: HTTP, SMTP e FTP. Tutto il traffico esterno (internet) è particolarmente pericoloso, ma va verificato anche il traffico interno (tra bilancitori, web server e sistemi di back-end).
* Sono utilizzati di default o in vecchi software algoritmi crittografici obsoleti ?
* Sono utilizzate chiavi crittografiche di default oppure deboli ? Le chiavi sono soggette ad una gestione appropriata oppure vengono riutilizzate ? Manca completamente un criterio di rotazione delle chiavi (i.e. rigenerazione) ?
* Il cripting dei dati non è obbligato ? Ovvero, mancano le opportune direttive di sicurezza o gli header per specifici browser ?
* I client (i.e. App, gestori di mail) non verificano se il certificato offerto dal server sia effettivamente valido ?

Vedi: ASVS [Requisiti Crittografici (V7)](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [Data Protection (V9)](https://www.owasp.org/index.php/ASVS_V9_Data_Protection) e [SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS_V10_Communications).

## Come prevenire ?

Fai come minimo le seguenti cose e consulta i riferimenti:

* Classifica i dati processati, salvato o trasmessi da ogni applicazione. Identifica quali dati sono sensibili in relazione alle normative sulla privacy, i regolamenti in vigore o le necessità del business.
* Applica controlli per tutti i dati classificati.
* Non salvare alcun dato sensibile se non è strettamente necessario. Cancellali non appena possibile, oppure troncali o utilizza sistemi di tokenizzazione conformi ai criteri PCI DSS. Dati non salvati non possono essere rubati.
* Cripta tutti i dati sensibili che richiedono di essere salvati.
* Assicurati di utilizzare algoritmi crittografici standard, robusti e aggiornati, così come protocolli e chiavi crittografiche appropriate e gestite con processi corretti.
* Cripta tutti i dati in transito con protocolli come TLS, dotati di algoritmi di cifratura di tipo perfect forward secrecy (PFS), applica criteri di priorità degli algoritmi di cifra decisi dal server e configurati in modo sicuro. Assicurati l'obbligo di una connessione criptata attraverso l'utilizzo di direttive quali HTTP Strict Transport Security (HSTS).
* Disabilita il caching nelle risposte che contengono dati sensibili.
* Salva le password utilizzando funzioni di hashing robusti adattivi, dotati di seme e di un fattore di carico come [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) o [PBKDF2](https://wikipedia.org/wiki/PBKDF2).
* Verifica in modo indipendente l'efficacia delle configurazioni utilizzate.

## Scenari di Attacco

**Scenario #1**: Un'applicazione cripta numeri di carta di credito in un database utilizzando una procedura automatica a livello di database. Dato che i dati vengono automaticamente decriptati in fase di estrazione, una vulnerabilità di SQL injection permette di estrarre i numero di carta di credito in chiaro.

**Scenario #2**: Un sito non utilizza o non obbliga ad utilizzare il protocollo TLS per tutte le pagine, o comunque permette l'utilizzo di algoritmi deboli. Un attaccante in grado di monitorare il traffico di rete (ad esempio attraverso una rete wireless non adeguatamente protetta), forza il passaggio della connessione da HTTPS ad HTTP, intercetta una richiesta ed entra in possesso del cookie di sessione dell'utente. L'attaccante inviando il cookie rubato può accedere alla sessione (autenticata) dell'utente, accedendo e modificando tutti i dati privati a cui ha accesso l'utente. In alternativa potrebbe alterare i dati inviati, ad esempio modificando il destinatario di un bonifico.

**Scenario #3**: Un database contiene password salvate senza "sale" o con un algoritmo di hashing debole per il salvataggio delle password. Una vulnerabilità in una form di upload, permette all'attaccante di recuperare una copia del database. Tutte le password possono quindi essere decriptate attraverso l'utilizzo di tabelle di associazione inversa con hash precalcolate ("rainbow table"). Ma anche nel caso di utilizzo di un "sale", se ci si è basati su algoritmi semplici o comunque veloci ed efficienti, le password possono essere decriptate attraverso l'utilizzo di GPU.

## Riferimenti

### OWASP

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard]((https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)): [V7](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [9](https://www.owasp.org/index.php/ASVS_V9_Data_Protection), [10](https://www.owasp.org/index.php/ASVS_V10_Communications)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) and [Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### Esterni

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html); [CWE-327: Broken/Risky Crypto](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
