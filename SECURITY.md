# Sicurezza

## Segnalare un problema

Per vulnerabilità o problemi di sicurezza del repository o delle liste (per esempio una fonte compromessa, una voce che blocca un servizio critico, dati sensibili pubblicati per errore) **non aprire una issue pubblica**: usa la segnalazione privata di GitHub, *Security → Report a vulnerability*, su questo repository.

Per i falsi positivi ordinari usa il modulo *Segnala un falso positivo*.

## Misure in atto

- Le GitHub Actions sono fissate per SHA e aggiornate da Dependabot con PR da approvare.
- Fonti solo in HTTPS, con licenza verificata; ogni fonte ha una cache e una soglia di calo: se una fonte non risponde, si svuota o cala oltre il 50%, resta l'ultima versione valida.
- Variazioni anomale dei feed (oltre il 25%) vengono pubblicate solo dopo approvazione tramite PR.
- Gli IP di infrastrutture condivise e dei servizi critici (`domains/allowlist/protetti.txt`) non entrano mai nei feed.
- La CI rifiuta dati personali nelle voci e regole per singolo cliente.
- Ogni build registra aggiunte e rimozioni in `dist/CHANGELOG.md`; ogni settimana una release conserva una copia datata delle liste con le impronte SHA-256.
- Un controllo giornaliero segnala se i feed non vengono aggiornati da più di 24 ore.
