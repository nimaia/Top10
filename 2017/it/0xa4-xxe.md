# A4:2017 Entità XML Esterne (XXE)

| Agenti di minaccia/Vettori di attacco | Problematiche di sicurezza           | Impatto               |
| -- | -- | -- |
| Livello di accesso : Sfruttabilità 2 | Diffusione 2 : Individuazione 3 | Tecnico 3 : Business ? |
| Gli attaccanti possono sfruttare interpreti XML vulnerabili se possono caricare un XML o includere del contenuto ostile in un documento XML, approfittando di una vulnerabilità nel codice, nelle dipendenze o nel metodo di integrazione utilizzato. | Normalmente molti vecchi interpreti XML permettono di specificare entità esterne, in pratica una URI che viene dereferenziata durante il processo di decodifica dell'XML. Tramite [strumenti di analisi statica del codice (SAST)](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) è possibile scopire questa questa problematica, ispezionando dipendenze e configurazioni. Gli [strumenti di analisi dinamica (DAST)](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) normalmente richiedono un tuning manuale della configurazione per poter scoprire e sfruttare questa vulnerabilità. Il personale che effettua i test deve quindi essere appositamente formato su come effettuare test che sfruttino un XXE, pratica non particolarmente diffusa dai dati raccolti nel 2017. | Questi difetti possono essere utilizzati per estrarre dati, eseguire richieste remote da parte del server, effettuare scansioni del sistema, eseguire un attacco DoS, così come altre tipologie di attacco. |

## L'applicazione è vulnerabile ?

L'applicazione, in particolare i web service basati su XML, e il relativo software a valle sono vulnerabili all'attacco se:

* L'applicazione accetta direttamente XML o upload di file XML, specialmente da sorgenti non attendibili, o inserisce dati non attendibili all'interno di documenti XML che verranno successivamente processati da un interprete XML.
* Un interprete XML dell'applicazione o dei web service basati su SOAP hanno abilitato il cosiddetto [document type definitions (DTDs)](https://it.wikipedia.org/wiki/Document_type_definition). Dato che il modo per disabilitare le direttive DTD varia da interprete ad interprete, è buona pratica consultare riferimenti come ad esempio l'[OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet). 
* Se l'applicazione utilizza SAML per l'identificazione degli utenti all'interno di un sistema di autenticazione distribuito o per realizzare servizi di Single Sign On (SSO). SAML utilizza XML per lo scambio dei dati e può essere vulnerabile.
* Se l'applicazione utilizza una versione di SOAP precedente la 1.2 è estremamente probabile che sia suscettibile ad un attacco XXE se è possibile inviare entità XML al framework SOAP.
* Essere vulnerabile ad un'attacco XXE significa essere vulnerabile ad un'attacco DoS, come ad esempio il Billion Laughs attack.

## Come prevenire ?

Un percorso di formazione degli sviluppatori è essenziale per poter identificare e ridurre l'impatto di un XXE. In ogni caso prevenire un XXE significa, tra le altre cose:

* Quando possibile utilizzare formati più semplici, come JSON, ed evitare di serializzare dati sensibili.
* Aggiornare tutti gli interpreti XML e tutte le librerie utilizzate dall'applicazione o dal sistema operativo sottostante. Per fare questo utilizzare opportuni [dependency checkers](https://www.owasp.org/index.php/OWASP_Dependency_Check) per identificare i moduli con problemi. Aggiornare SOAP a SOAP 1.2 o superiore.
* Disabilitare la risoluzione di entità XML esterne e DTD in tutti gli interpreti XML dell'applicazione, così come indicato in [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet). 
* Implementare lato server una validazione dei contenuti esterni mediante whitelist, filtraggio o sanitizzazione del contenuto XML (documenti, headers e singoli nodi).
* Verificare che i file XML o XLS caricati da parte degli utenti siano validati tramite XSD o altri meccanismi similari.
* Gli strumenti di analisi statica del codice possono aiutare a scoprire XXE nel codice sorgente, ma la revisione manuale del codice rimane la migliore alternativa per applicazioni di grandi dimensioni e complesse, con molte integrazioni.

Se questi controlli non dovessero essere possibili, prendere in considerazione l'ipotesi di effettuare un [virtual patching](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices) o di introdurre degli API security gateways o dei Web Application Firewalls (WAFs) per individuare, monitorare e bloccare attacchi di tipo XXE.

## Scenari di Attacco

Sono state scoperte numerose problematiche di tipo XXE, compresi attacchi verso dispositivi embedded. Gli attacchi XXE sono possibili in molti posti insospettabili, come all'interno di dipendenze innestate molto in profondità. Il modo più semplice è di effettuare l'upload di un XML maligno che, se accettato, permette all'attaccante di:

**Scenario #1**: estrarre dei dati dal server:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Scenario #2**: effettuare una scansione della rete privata del server, sostituendo la precedente linea contenente la ENTITY con:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Scenario #3**: effettuare un attacco DoS, includendo un file potenzialmente senza fine:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Riferimenti

### OWASP

* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for XML Injection](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XML Security](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### Esterni

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
